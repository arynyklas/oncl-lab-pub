#!/usr/bin/env python3
# Independent TUF test vectors for OpenNCALayer, built and checked with python-tuf.
#
# Pinned: tuf==7.0.1 (python-tuf; pulls securesystemslib==1.6.0), cryptography==50.0.2.
#   python3 -m venv /mnt/d/oncl-tuf-venv
#   /mnt/d/oncl-tuf-venv/bin/pip install tuf==7.0.1 cryptography==50.0.2
#   /mnt/d/oncl-tuf-venv/bin/python xtask/assets/tuf-oracle/gen.py
#
# Writes crates/oncl-update/tests/fixtures/tuf/{valid,<attack>}/ (+ keys.json) and the delegated
# repositories delegated-*/, then runs python-tuf's ngclient.Updater over a local
# http.server against every repository and prints a
# verdict table. Everything is deterministic: the keys are SYNTHETIC test keys derived from fixed
# seeds, Ed25519 signatures are deterministic, and the clock of the check is fixed (NOW below).
# Re-running must leave `git status` clean.
#
# The binding contract this follows is documented in fixtures/tuf/README.md.

from __future__ import annotations

import argparse
import copy
import datetime as dt
import hashlib
import http.server
import json
import shutil
import sys
import tempfile
import threading
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from securesystemslib.formats import encode_canonical
from securesystemslib.signer import CryptoSigner
from tuf.api.metadata import (
    Key,
    Metadata,
    MetaFile,
    Root,
    Snapshot,
    TargetFile,
    Targets,
    Timestamp,
)
from tuf.api.serialization.json import JSONSerializer
from tuf.ngclient import Updater, UpdaterConfig

UTC = dt.timezone.utc
# Signing time of every file of the valid repository.
T0 = dt.datetime(2026, 11, 15, 0, 0, 0, tzinfo=UTC)
# The clock every check runs at (python-tuf here, the Rust verifier in its tests).
NOW = T0 + dt.timedelta(days=1)
ROOT_EXPIRES = T0 + dt.timedelta(days=365)
TARGETS_EXPIRES = T0 + dt.timedelta(days=30)
SNAPSHOT_EXPIRES = T0 + dt.timedelta(days=30)
TIMESTAMP_EXPIRES = T0 + dt.timedelta(days=7)
# The timestamp `version` is the Unix time in seconds at signing.
TS_VERSION = int(T0.timestamp())
EXPIRED = T0 + dt.timedelta(hours=12)  # before NOW

SEED_PREFIX = "oncl-tuf-oracle-v1/"
KEY_NAMES = ["root-a", "root-b", "targets", "snapshot", "timestamp-1", "timestamp-2"]

OUT_DEFAULT = Path(__file__).resolve().parents[3] / "crates/oncl-update/tests/fixtures/tuf"


# --------------------------------------------------------------------------- keys


def make_signer(name: str) -> tuple[CryptoSigner, bytes]:
    seed = hashlib.sha256((SEED_PREFIX + name).encode()).digest()
    signer = CryptoSigner(Ed25519PrivateKey.from_private_bytes(seed))
    return signer, seed


def olpc(obj) -> bytes:
    """OLPC canonical JSON, enough for the ASCII key objects hashed here."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


SIGNERS: dict[str, CryptoSigner] = {}
SEEDS: dict[str, bytes] = {}
for _n in KEY_NAMES:
    SIGNERS[_n], SEEDS[_n] = make_signer(_n)


def key_of(name: str) -> Key:
    return SIGNERS[name].public_key


def keyid_of(name: str) -> str:
    return key_of(name).keyid


# The contract: keyid = lowercase hex sha256 of the OLPC canonical JSON of the key object.
for _n in KEY_NAMES:
    _k = key_of(_n)
    _obj = {"keytype": _k.keytype, "scheme": _k.scheme, "keyval": {"public": _k.keyval["public"]}}
    assert _k.keytype == "ed25519" and _k.scheme == "ed25519", _n
    assert hashlib.sha256(olpc(_obj)).hexdigest() == _k.keyid, f"keyid of {_n} differs from contract"


# ----------------------------------------------------------------------- metadata


def ser(md: Metadata) -> bytes:
    return md.to_bytes(JSONSerializer(compact=False))


def sign_with(md: Metadata, *names: str) -> bytes:
    md.signatures.clear()
    for n in names:
        md.sign(SIGNERS[n], append=True)
    return ser(md)


def index_body(channel: str, seq: int) -> bytes:
    """A small synthetic update index (the shape of crates/oncl-update/src/index.rs tests)."""
    sums = lambda n: bytes([n] * 32).hex()  # noqa: E731
    doc = {
        "schema": 1,
        "channel": channel,
        "seq": seq,
        "generated": "2026-11-14T00:00:00Z",
        "expires": "2026-12-14T00:00:00Z",
        "core": [
            {
                "version": "0.1.0",
                "flavors": {
                    "win-x64": {
                        "url": "https://example.invalid/releases/v0.1.0/full.nupkg",
                        "sha256": sums(1),
                        "size": 123,
                        "contents_sha256": sums(2),
                    }
                },
                "rollout": 100,
                "revoked": False,
                "notes_url": "https://example.invalid/releases/v0.1.0",
            }
        ],
        "extension": {
            "version": "0.1.0",
            "chromium_zip": {"url": "https://example.invalid/e.zip", "sha256": sums(3)},
            "firefox_xpi": {"url": "https://example.invalid/e.xpi", "sha256": sums(4)},
        },
        "plugins": [],
    }
    return (json.dumps(doc, indent=2, sort_keys=True) + "\n").encode()


TARGET_PATHS = ["indexes/stable.json", "indexes/beta.json"]
BODIES = {"indexes/stable.json": index_body("stable", 7), "indexes/beta.json": index_body("beta", 9)}


def target_file_name(path: str, body: bytes) -> str:
    d, _, base = path.rpartition("/")
    return f"targets/{d}/{hashlib.sha256(body).hexdigest()}.{base}"


def build_root(version: int, roles: dict[str, list[str]], threshold: dict[str, int] | None = None) -> Metadata:
    root = Root(version=version, expires=ROOT_EXPIRES, consistent_snapshot=True)
    for role, names in roles.items():
        for n in names:
            root.add_key(key_of(n), role)
        root.roles[role].threshold = (threshold or {}).get(role, 1)
    return Metadata(root)


def build_targets(version: int) -> Metadata:
    t = Targets(version=version, expires=TARGETS_EXPIRES)
    for p in TARGET_PATHS:
        t.targets[p] = TargetFile.from_data(p, BODIES[p], ["sha256"])
    return Metadata(t)


def build_snapshot(version: int, targets_version: int) -> Metadata:
    return Metadata(
        Snapshot(version=version, expires=SNAPSHOT_EXPIRES, meta={"targets.json": MetaFile(targets_version)})
    )


def build_timestamp(version: int, snapshot_version: int) -> Metadata:
    return Metadata(Timestamp(version=version, expires=TIMESTAMP_EXPIRES, snapshot_meta=MetaFile(snapshot_version)))


def build_valid() -> dict[str, bytes]:
    """The valid repository: root v1 -> v2 (timestamp key rotated) -> v3 (root key rotated)."""
    files: dict[str, bytes] = {}
    role_keys_1 = {"root": ["root-a"], "targets": ["targets"], "snapshot": ["snapshot"], "timestamp": ["timestamp-1"]}
    files["metadata/1.root.json"] = sign_with(build_root(1, role_keys_1), "root-a")
    role_keys_2 = {**role_keys_1, "timestamp": ["timestamp-2"]}
    files["metadata/2.root.json"] = sign_with(build_root(2, role_keys_2), "root-a")
    role_keys_3 = {**role_keys_2, "root": ["root-b"]}
    # The root key rotates in v3: signed by the old threshold (root-a) and the new one (root-b).
    files["metadata/3.root.json"] = sign_with(build_root(3, role_keys_3), "root-a", "root-b")
    files["metadata/2.targets.json"] = sign_with(build_targets(2), "targets")
    files["metadata/2.snapshot.json"] = sign_with(build_snapshot(2, 2), "snapshot")
    files["metadata/timestamp.json"] = sign_with(build_timestamp(TS_VERSION, 2), "timestamp-2")
    for p in TARGET_PATHS:
        files[target_file_name(p, BODIES[p])] = BODIES[p]
    return files


def load(files: dict[str, bytes], path: str) -> Metadata:
    return Metadata.from_bytes(files[path])


# ------------------------------------------------------------------------ attacks


class Attack:
    def __init__(self, name, attack, fails_at, error, build, prior_state=None):
        self.name, self.attack, self.fails_at, self.error = name, attack, fails_at, error
        self.build, self.prior_state = build, prior_state


def flip_hex_char(h: str) -> str:
    return h[:-1] + ("0" if h[-1] != "0" else "1")


def a_expired(path, signer, expires=EXPIRED):
    def build(f):
        md = load(f, path)
        md.signed.expires = expires
        f[path] = sign_with(md, signer)

    return build


def a_rollback_timestamp(f):
    f["metadata/timestamp.json"] = sign_with(build_timestamp(TS_VERSION - 3600, 2), "timestamp-2")


def a_rollback_snapshot(f):
    # A newer timestamp pointing at snapshot v1, after snapshot v2 was already accepted.
    f["metadata/timestamp.json"] = sign_with(build_timestamp(TS_VERSION + 3600, 1), "timestamp-2")
    f["metadata/1.snapshot.json"] = sign_with(build_snapshot(1, 1), "snapshot")
    f["metadata/1.targets.json"] = sign_with(build_targets(1), "targets")


def a_rollback_targets(f):
    # A newer timestamp and snapshot v3, whose `targets.json` entry is v1 after v2 was accepted.
    f["metadata/timestamp.json"] = sign_with(build_timestamp(TS_VERSION + 7200, 3), "timestamp-2")
    f["metadata/3.snapshot.json"] = sign_with(build_snapshot(3, 1), "snapshot")
    f["metadata/1.targets.json"] = sign_with(build_targets(1), "targets")


def a_bad_signature_targets(f):
    md = load(f, "metadata/2.targets.json")
    sig = md.signatures[next(iter(md.signatures))]
    sig.signature = flip_hex_char(sig.signature)
    f["metadata/2.targets.json"] = ser(md)


def a_threshold(f):
    # Root v2 demands 2 of {root-a, root-b} for the root role but carries one signature.
    md = build_root(
        2,
        {"root": ["root-a", "root-b"], "targets": ["targets"], "snapshot": ["snapshot"], "timestamp": ["timestamp-2"]},
        {"root": 2},
    )
    f["metadata/2.root.json"] = sign_with(md, "root-a")


def a_wrong_keyid(f):
    # Root v2 names the new timestamp key by an id that is not sha256 of its canonical form.
    d = json.loads(f["metadata/2.root.json"])
    real = keyid_of("timestamp-2")
    bogus = "00" * 32
    d["signed"]["keys"][bogus] = d["signed"]["keys"].pop(real)
    d["signed"]["roles"]["timestamp"]["keyids"] = [bogus]
    md = Metadata.from_dict(d)
    f["metadata/2.root.json"] = sign_with(md, "root-a")


def a_unknown_field(f):
    # A field the signer never saw, added after signing: it is part of the signed object.
    d = json.loads(f["metadata/2.targets.json"])
    d["signed"]["x-tampered"] = {"note": "unknown field"}
    f["metadata/2.targets.json"] = (json.dumps(d, indent=1, sort_keys=True)).encode()


def a_hash_mismatch(f):
    p = "indexes/stable.json"
    name = target_file_name(p, BODIES[p])
    body = f[name]
    assert b"0.1.0" in body
    f[name] = body.replace(b'"seq": 7', b'"seq": 8')  # same length, other content
    assert len(f[name]) == len(body) and f[name] != body


def a_length_mismatch(f):
    p = "indexes/stable.json"
    name = target_file_name(p, BODIES[p])
    f[name] = f[name] + b"\n"


def a_root_gap(f):
    # File 2.root.json holds root version 3 (signed by both root keys): the chain skips v2.
    d = json.loads(f["metadata/3.root.json"])
    md = Metadata.from_dict(d)
    f["metadata/2.root.json"] = sign_with(md, "root-a", "root-b")
    del f["metadata/3.root.json"]


def a_new_root_new_keys_only(f):
    md = load(f, "metadata/3.root.json")
    f["metadata/3.root.json"] = sign_with(md, "root-b")


ATTACKS = [
    Attack("expired-timestamp", "timestamp.json is past its expires", "timestamp",
           "ExpiredMetadataError: timestamp expires 2026-11-15T12:00:00Z is before the clock",
           a_expired("metadata/timestamp.json", "timestamp-2")),
    Attack("expired-snapshot", "2.snapshot.json is past its expires", "snapshot",
           "ExpiredMetadataError: snapshot expires 2026-11-15T12:00:00Z is before the clock",
           a_expired("metadata/2.snapshot.json", "snapshot")),
    Attack("expired-targets", "2.targets.json is past its expires", "targets",
           "ExpiredMetadataError: targets expires 2026-11-15T12:00:00Z is before the clock",
           a_expired("metadata/2.targets.json", "targets")),
    Attack("rollback-timestamp",
           "an older timestamp (version = TS_VERSION-3600) is served after TS_VERSION was accepted",
           "timestamp", "Rollback: timestamp version lower than the trusted one (BadVersionNumberError)",
           a_rollback_timestamp, "valid"),
    Attack("rollback-snapshot",
           "a newer timestamp (TS_VERSION+3600) names snapshot v1 after snapshot v2 was accepted; "
           "the pair metadata/timestamp.json + metadata/1.snapshot.json replaces timestamp.json/2.snapshot.json",
           "snapshot", "Rollback: snapshot version lower than the trusted one (BadVersionNumberError)",
           a_rollback_snapshot, "valid"),
    Attack("rollback-targets",
           "a newer timestamp (TS_VERSION+7200) and snapshot v3 whose `targets.json` entry is v1 after targets v2 "
           "was accepted; the pair metadata/3.snapshot.json + metadata/1.targets.json",
           "snapshot or targets", "Rollback: the targets version in the new snapshot (v1) is lower than the trusted one "
           "(python-tuf refuses at the targets step with BadVersionNumberError; a client MAY equally refuse at the "
           "snapshot step, but must never accept)",
           a_rollback_targets, "valid"),
    Attack("bad-signature-targets", "the only signature of 2.targets.json has its last hex digit flipped",
           "targets", "UnsignedMetadataError: signature threshold not met for targets", a_bad_signature_targets),
    Attack("threshold-not-met", "2.root.json sets the root role to threshold 2 over {root-a, root-b} and has one signature",
           "root", "UnsignedMetadataError: the new root does not meet its own root threshold (1 of 2)", a_threshold),
    Attack("wrong-keyid-in-root", "2.root.json lists the timestamp key under a keyid that is not sha256 of its OLPC form",
           "root", "Malformed root: keyid does not match the key (contract rule; python-tuf does not check it)",
           a_wrong_keyid),
    Attack("tampered-unknown-field", "an unknown field was added to the signed part of 2.targets.json without re-signing",
           "targets", "UnsignedMetadataError: signature invalid (unknown fields are part of the signed bytes)",
           a_unknown_field),
    Attack("target-hash-mismatch", "the stable index target has the same length, other content (sha256 differs)",
           "target", "Target hash mismatch (LengthOrHashMismatchError)", a_hash_mismatch),
    Attack("target-length-mismatch", "the stable index target is one byte longer than targets metadata says",
           "target", "Target length mismatch (LengthOrHashMismatchError / DownloadLengthMismatchError)",
           a_length_mismatch),
    Attack("root-version-gap", "2.root.json contains root version 3 (signed by root-a and root-b): v2 is skipped",
           "root", "BadVersionNumberError: root file N+1 must have version N+1", a_root_gap),
    Attack("new-root-signed-only-by-new-keys", "3.root.json (root key rotated) is signed only by the new root key root-b",
           "root", "UnsignedMetadataError: the new root is not signed by the threshold of the OLD root keys",
           a_new_root_new_keys_only),
]


# ------------------------------------------------------------- delegated vectors
#
# A second repository, as `tuf/v1` is laid out once it delegates (docs/design/publishers.md):
# its own root (new root, snapshot and timestamp keys, named v2-* after a dropped design; the
# `targets` key shared with the valid repository), a
# top-level targets that always has `delegations`, and the delegated roles `pub-alpha` and
# `pub-beta` of two third-party publishers, each delegated `plugins/<name>/*/*`, terminating,
# threshold 1. The snapshot lists every metadata file with version, length and sha256.
#
# These files are written as raw JSON and signed over their canonical form here, not through
# python-tuf's model: the negative vectors need what that model refuses to build (a role name
# twice, a top-level role name). python-tuf only reads them, through its ngclient.

V2_KEY_NAMES = ["v2-root", "v2-snapshot", "v2-timestamp", "pub-alpha", "pub-beta", "pub-beta-2"]
for _n in V2_KEY_NAMES:
    SIGNERS[_n], SEEDS[_n] = make_signer(_n)

SPEC = ".".join(["1", "0", "31"])
DELEGATED_ANCHOR = "delegated-valid/metadata/1.root.json"


def iso(t: dt.datetime) -> str:
    return t.strftime("%Y-%m-%dT%H:%M:%SZ")


def sign_raw(signed: dict, *names: str) -> bytes:
    """The file of `signed`, signed by `names` over its OLPC canonical form."""
    payload = encode_canonical(signed).encode()
    sigs = [SIGNERS[n].sign(payload) for n in names]
    doc = {"signatures": [{"keyid": s.keyid, "sig": s.signature} for s in sigs], "signed": signed}
    return json.dumps(doc, indent=1, separators=(",", ": "), sort_keys=True).encode()


def meta_entry(version: int, data: bytes) -> dict:
    return {"version": version, "length": len(data), "hashes": {"sha256": hashlib.sha256(data).hexdigest()}}


def file_entry(data: bytes, custom: dict | None = None) -> dict:
    entry = {"length": len(data), "hashes": {"sha256": hashlib.sha256(data).hexdigest()}}
    if custom is not None:
        entry["custom"] = custom
    return entry


def publishers_body() -> bytes:
    doc = {
        "schema": 1,
        "publishers": [
            {"name": name, "state": "active", "display": {"ru": name, "kk": name, "en": name},
             "id_prefix": f"kz.{name}.", "modules": [f"kz.{name}.Module"], "bundles": []}
            for name in ("alpha", "beta")
        ],
    }
    return (json.dumps(doc, indent=2, sort_keys=True) + "\n").encode()


DELEGATED_TOP_BODIES = {**BODIES, "publishers.json": publishers_body()}


def plugin(publisher: str, plugin_id: str, version: str) -> tuple[str, bytes, dict]:
    """A publisher's target: its path, the (synthetic, unpublished) package and custom.oncl."""
    path = f"plugins/{publisher}/{plugin_id}/{version}.onclp"
    package = f"synthetic package {plugin_id} {version}\n".encode()
    custom = {"oncl": {
        "schema": 1, "id": plugin_id, "version": version,
        "url": f"https://downloads.example.invalid/{plugin_id}-{version}.onclp",
        "channel": "stable", "min_core": "0.1.2", "modules": [f"kz.{publisher}.Module"],
        "name": {"ru": plugin_id, "kk": plugin_id, "en": plugin_id},
        "capabilities": {}, "rollout": 100, "revoked": False,
    }}
    return path, package, custom


ALPHA = plugin("alpha", "kz.alpha.signer", "1.0.0")
BETA = plugin("beta", "kz.beta.tool", "2.1.0")


def key_dict(name: str) -> dict:
    return key_of(name).to_dict()


def delegation(publisher: str, keys: list[str], threshold: int = 1) -> dict:
    return {
        "name": f"pub-{publisher}",
        "keyids": [keyid_of(k) for k in keys],
        "threshold": threshold,
        "paths": [f"plugins/{publisher}/*/*"],
        "terminating": True,
    }


def role_signed(version: int, targets: list[tuple[str, bytes, dict]], expires: dt.datetime = TARGETS_EXPIRES) -> dict:
    return {
        "_type": "targets", "spec_version": SPEC, "version": version, "expires": iso(expires),
        "targets": {path: file_entry(package, custom) for path, package, custom in targets},
    }


class DRepo:
    """The delegated repository as data; `render` signs it into files."""

    def __init__(self):
        self.keys = ["pub-alpha", "pub-beta"]
        self.delegations = [delegation("alpha", ["pub-alpha"]), delegation("beta", ["pub-beta"])]
        self.top_version = 1
        # Role name -> [signed, signers, mutate(bytes) -> bytes or None].
        self.roles: dict[str, list] = {
            "pub-alpha": [role_signed(2, [ALPHA]), ["pub-alpha"], None],
            "pub-beta": [role_signed(1, [BETA]), ["pub-beta"], None],
        }
        self.snapshot_version = 1
        self.snapshot_drop: set[str] = set()
        # Role name -> the version its file is named and listed by, if not its own.
        self.listed_versions: dict[str, int] = {}
        self.timestamp_version = TS_VERSION
        self.post = []

    def top(self) -> dict:
        return {
            "_type": "targets", "spec_version": SPEC, "version": self.top_version,
            "expires": iso(TARGETS_EXPIRES),
            "targets": {p: file_entry(b) for p, b in DELEGATED_TOP_BODIES.items()},
            "delegations": {"keys": {keyid_of(k): key_dict(k) for k in self.keys}, "roles": self.delegations},
        }

    def render(self) -> dict[str, bytes]:
        files = {"metadata/1.root.json": V2_ROOT}
        top = sign_raw(self.top(), "targets")
        files[f"metadata/{self.top_version}.targets.json"] = top
        meta = {"targets.json": meta_entry(self.top_version, top)}
        for name, (signed, signers, mutate) in self.roles.items():
            data = sign_raw(signed, *signers)
            if mutate is not None:
                data = mutate(data)
            version = self.listed_versions.get(name, signed["version"])
            files[f"metadata/{version}.{name}.json"] = data
            meta[f"{name}.json"] = meta_entry(version, data)
        for name in self.snapshot_drop:
            del meta[name]
        snapshot = sign_raw(
            {"_type": "snapshot", "spec_version": SPEC, "version": self.snapshot_version,
             "expires": iso(SNAPSHOT_EXPIRES), "meta": meta},
            "v2-snapshot",
        )
        files[f"metadata/{self.snapshot_version}.snapshot.json"] = snapshot
        files["metadata/timestamp.json"] = sign_raw(
            {"_type": "timestamp", "spec_version": SPEC, "version": self.timestamp_version,
             "expires": iso(TIMESTAMP_EXPIRES), "meta": {"snapshot.json": meta_entry(self.snapshot_version, snapshot)}},
            "v2-timestamp",
        )
        for p, body in DELEGATED_TOP_BODIES.items():
            files[target_file_name(p, body)] = body
        for fn in self.post:
            fn(files)
        return files


V2_ROOT = sign_with(
    build_root(1, {"root": ["v2-root"], "targets": ["targets"], "snapshot": ["v2-snapshot"],
                   "timestamp": ["v2-timestamp"]}),
    "v2-root",
)


def flip_signature(data: bytes) -> bytes:
    """The file with the last hex digit of its first signature flipped: same length."""
    doc = json.loads(data)
    doc["signatures"][0]["sig"] = flip_hex_char(doc["signatures"][0]["sig"])
    return json.dumps(doc, indent=1, separators=(",", ": "), sort_keys=True).encode()


def d_bad_signature(r: DRepo):
    r.roles["pub-beta"][2] = flip_signature


def d_threshold(r: DRepo):
    r.keys.append("pub-beta-2")
    r.delegations[1] = delegation("beta", ["pub-beta", "pub-beta-2"], threshold=2)


def d_version_mismatch(r: DRepo):
    # metadata/1.pub-beta.json, listed as version 1, is version 2 inside.
    r.roles["pub-beta"][0]["version"] = 2
    r.listed_versions["pub-beta"] = 1


def d_hash_mismatch(r: DRepo):
    # After the snapshot lists it: the file changes, same length.
    def tamper(files):
        files["metadata/1.pub-beta.json"] = flip_signature(files["metadata/1.pub-beta.json"])
    r.post.append(tamper)


def d_expired(r: DRepo):
    r.roles["pub-beta"][0]["expires"] = iso(EXPIRED)


def d_rollback(r: DRepo):
    # After pub-alpha version 2 was accepted: a newer timestamp and snapshot 2 list version 1.
    r.roles["pub-alpha"][0]["version"] = 1
    r.snapshot_version = 2
    r.timestamp_version = TS_VERSION + 3600


def d_not_in_snapshot(r: DRepo):
    r.snapshot_drop.add("pub-beta.json")


def d_removed(r: DRepo):
    # The delegation is gone; the snapshot still lists the role (a dropped entry would be a
    # rollback), and its file is still published.
    r.keys.remove("pub-beta")
    del r.delegations[1]


EVIL_ALPHA = plugin("alpha", "kz.alpha.evil", "9.0.0")


def d_path_outside(r: DRepo):
    r.roles["pub-beta"][0] = role_signed(1, [BETA, EVIL_ALPHA])


DEEP_BETA = plugin("beta", "kz.beta.deep", "1.0.0")


def d_nested(r: DRepo):
    signed = role_signed(1, [BETA])
    signed["delegations"] = {
        "keys": {keyid_of("pub-beta-2"): key_dict("pub-beta-2")},
        "roles": [{"name": "pub-beta-sub", "keyids": [keyid_of("pub-beta-2")], "threshold": 1,
                   "paths": ["plugins/beta/*/*"], "terminating": True}],
    }
    r.roles["pub-beta"][0] = signed
    r.roles["pub-beta-sub"] = [role_signed(1, [DEEP_BETA]), ["pub-beta-2"], None]


def d_hash_prefixes(r: DRepo):
    role = delegation("beta", ["pub-beta"])
    del role["paths"]
    role["path_hash_prefixes"] = [hashlib.sha256(BETA[0].encode()).hexdigest()[:2]]
    r.delegations[1] = role


def d_key_reuse(r: DRepo):
    # pub-beta is delegated to the top-level targets key, and signed by it.
    r.keys = ["pub-alpha", "targets"]
    r.delegations[1] = delegation("beta", ["targets"])
    r.roles["pub-beta"][1] = ["targets"]


DEEP_ALPHA = ("plugins/alpha/kz.alpha.signer/extra/1.0.0.onclp", b"synthetic deep package\n", ALPHA[2])


def d_glob_depth(r: DRepo):
    r.roles["pub-alpha"][0] = role_signed(2, [ALPHA, DEEP_ALPHA])


def d_duplicate_role(r: DRepo):
    r.delegations.append(delegation("beta", ["pub-beta"]))


def d_top_level_name(r: DRepo):
    # (timestamp: its file, metadata/1.timestamp.json, is no other file's name.)
    r.delegations[1] = {**delegation("beta", ["pub-beta"]), "name": "timestamp"}
    r.roles["timestamp"] = r.roles.pop("pub-beta")


class DVector:
    def __init__(self, name, attack, build, python, contract, prior=None, probes=()):
        self.name, self.attack, self.build = name, attack, build
        self.python, self.contract, self.prior = python, contract, prior
        self.probes = [ALPHA[0], BETA[0], *probes]


def py(refresh="ok", **targets):
    """What python-tuf is expected to do: refresh, then get_targetinfo per probe path."""
    return {"refresh": refresh, "targets": targets}


FOUND_BOTH = {ALPHA[0]: "found", BETA[0]: "found"}


def beta(outcome: str, **more: str) -> dict:
    """python-tuf refreshes, finds pub-alpha's target, and `outcome` for pub-beta's."""
    return {"refresh": "ok", "targets": {ALPHA[0]: "found", BETA[0]: outcome, **more}}


DVECTORS = [
    DVector("delegated-valid", "two publishers, publishers.json, each role verified",
            lambda r: None, {"refresh": "ok", "targets": FOUND_BOTH},
            {"refresh": "accepted", "roles": {"pub-alpha": "verified", "pub-beta": "verified"}}),
    DVector("delegated-bad-signature", "the only signature of pub-beta has its last hex digit flipped "
            "(the snapshot lists the file as it is)", d_bad_signature, beta("UnsignedMetadataError"),
            {"refresh": "accepted", "roles": {"pub-alpha": "verified", "pub-beta": "refused: signature"}}),
    DVector("delegated-threshold-not-met", "pub-beta is delegated 2 of {pub-beta, pub-beta-2} and signed by one",
            d_threshold, beta("UnsignedMetadataError"),
            {"refresh": "accepted", "roles": {"pub-alpha": "verified", "pub-beta": "refused: signature"}}),
    DVector("delegated-version-mismatch", "metadata/1.pub-beta.json (listed as version 1) is version 2",
            d_version_mismatch, beta("BadVersionNumberError"),
            {"refresh": "accepted", "roles": {"pub-alpha": "verified", "pub-beta": "refused: version mismatch"}}),
    DVector("delegated-hash-mismatch", "metadata/1.pub-beta.json changed after the snapshot listed it (same length)",
            d_hash_mismatch, beta("LengthOrHashMismatchError"),
            {"refresh": "accepted", "roles": {"pub-alpha": "verified", "pub-beta": "refused: hash"}}),
    DVector("delegated-expired", "pub-beta is past its expires", d_expired, beta("ExpiredMetadataError"),
            {"refresh": "accepted", "roles": {"pub-alpha": "verified", "pub-beta": "refused: expired"}}),
    DVector("delegated-rollback", "after pub-alpha version 2 was accepted, a newer timestamp and snapshot 2 "
            "list pub-alpha version 1", d_rollback, py("BadVersionNumberError"),
            {"refresh": "refused at the snapshot: rollback of pub-alpha.json", "roles": {}},
            prior="delegated-valid"),
    DVector("delegated-not-in-snapshot", "the snapshot does not list pub-beta.json", d_not_in_snapshot,
            beta("RepositoryError"),
            {"refresh": "accepted", "roles": {"pub-alpha": "verified", "pub-beta": "refused: not in snapshot"}}),
    DVector("delegated-removed", "the top-level targets no longer delegate to pub-beta; the snapshot still "
            "lists it", d_removed, beta("absent"),
            {"refresh": "accepted", "roles": {"pub-alpha": "verified"}}),
    DVector("delegated-path-outside", "pub-beta also lists a target under plugins/alpha/", d_path_outside,
            beta("found", **{EVIL_ALPHA[0]: "absent"}),
            {"refresh": "accepted", "roles": {"pub-alpha": "verified", "pub-beta": "refused: path outside"}},
            probes=[EVIL_ALPHA[0]]),
    DVector("delegated-nested", "pub-beta delegates plugins/beta/*/* further to pub-beta-sub", d_nested,
            beta("found", **{DEEP_BETA[0]: "found"}),
            {"refresh": "accepted", "roles": {"pub-alpha": "verified", "pub-beta": "refused: nested"}},
            probes=[DEEP_BETA[0]]),
    DVector("delegated-path-hash-prefixes", "pub-beta is delegated by path_hash_prefixes", d_hash_prefixes,
            beta("found"),
            {"refresh": "accepted", "roles": {"pub-alpha": "verified", "pub-beta": "refused: path_hash_prefixes"}}),
    DVector("delegated-key-reuse", "pub-beta is delegated to (and signed by) the top-level targets key",
            d_key_reuse, beta("found"),
            {"refresh": "accepted", "roles": {"pub-alpha": "verified", "pub-beta": "refused: key reused"}}),
    DVector("delegated-glob-depth", "pub-alpha (plugins/alpha/*/*) lists a target one segment deeper",
            d_glob_depth, beta("found", **{DEEP_ALPHA[0]: "absent"}),
            {"refresh": "accepted", "roles": {"pub-alpha": "refused: path outside", "pub-beta": "verified"}},
            probes=[DEEP_ALPHA[0]]),
    DVector("delegated-duplicate-role", "the top-level targets delegate to pub-beta twice", d_duplicate_role,
            py("DeserializationError"), {"refresh": "refused at the targets: a role listed twice", "roles": {}}),
    DVector("delegated-top-level-name", "a delegated role is named timestamp", d_top_level_name,
            py("DeserializationError"), {"refresh": "refused at the targets: not a pub-<name> role", "roles": {}}),
]


def run_delegated(repo: Path, cache: Path, dl: Path, probes: list[str]) -> dict:
    """refresh, the top-level targets, then get_targetinfo of every probe path."""
    srv = serve(repo)
    base = f"http://127.0.0.1:{srv.server_address[1]}"
    try:
        up = Updater(
            metadata_dir=str(cache),
            metadata_base_url=base + "/metadata/",
            target_dir=str(dl),
            target_base_url=base + "/targets/",
            bootstrap=(repo.parent / DELEGATED_ANCHOR).read_bytes(),
            config=UpdaterConfig(),
        )
        up._trusted_set.reference_time = NOW  # the fixed clock
        try:
            up.refresh()
        except Exception as e:  # noqa: BLE001
            cause = f" ({type(e.__cause__).__name__}: {e.__cause__})" if e.__cause__ else ""
            return {"refresh": type(e).__name__, "error": f"{e}{cause}"[:150], "targets": {}}
        for p, body in DELEGATED_TOP_BODIES.items():
            info = up.get_targetinfo(p)
            if info is None or Path(up.download_target(info)).read_bytes() != body:
                return {"refresh": "ok", "error": f"top-level target {p} not as published", "targets": {}}
        targets = {}
        for p in probes:
            try:
                targets[p] = "found" if up.get_targetinfo(p) is not None else "absent"
            except Exception as e:  # noqa: BLE001
                targets[p] = type(e).__name__
        return {"refresh": "ok", "targets": targets}
    finally:
        srv.shutdown()


def check_delegated(repo: Path, prior: str | None, probes: list[str]) -> dict:
    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)
        cache = tmp / "meta"
        cache.mkdir()
        if prior:
            first = run_delegated(repo.parent / prior, cache, tmp / "dl0", [ALPHA[0], BETA[0]])
            assert first["refresh"] == "ok", f"prior state {prior} was not accepted: {first}"
        return run_delegated(repo, cache, tmp / "dl", probes)


def write_delegated(out: Path) -> list[tuple[str, bool, str]]:
    """Writes the delegated vectors; returns (name, as expected, python-tuf said)."""
    results = []
    base = DRepo().render()
    for v in DVECTORS:
        r = DRepo()
        v.build(r)
        files = r.render()
        changed = sorted(k for k in set(files) | set(base) if files.get(k) != base.get(k))
        write_repo(out / v.name, files)
        got = check_delegated(out / v.name, v.prior, v.probes)
        want = v.python
        same = got["refresh"] == want["refresh"] and got["targets"] == (want["targets"] if want["refresh"] == "ok" else {})
        (out / v.name / "expected.json").write_text(json.dumps({
            "name": v.name,
            "attack": v.attack,
            "now": iso(NOW),
            "trust_anchor": DELEGATED_ANCHOR,
            "prior_state": (f"client already accepted the '{v.prior}' repository at the same clock"
                            if v.prior else None),
            "probes": v.probes,
            "contract": v.contract,
            "changed_files_vs_delegated_valid": changed if v.name != "delegated-valid" else [],
            "python_tuf": got,
        }, indent=2) + "\n")
        results.append((v.name, same, json.dumps(got, sort_keys=True)))
    return results




# ------------------------------------------------------------------ python-tuf run


class Quiet(http.server.SimpleHTTPRequestHandler):
    def log_message(self, *a):
        pass


def serve(root: Path):
    handler = lambda *a, **k: Quiet(*a, directory=str(root), **k)  # noqa: E731
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def run_client(repo: Path, cache: Path, dl: Path):
    """One ngclient update against `repo`. Returns (verdict, step, error)."""
    srv = serve(repo)
    base = f"http://127.0.0.1:{srv.server_address[1]}"
    step = "bootstrap"
    try:
        bootstrap = (repo.parent / "valid" / "metadata" / "1.root.json").read_bytes()
        up = Updater(
            metadata_dir=str(cache),
            metadata_base_url=base + "/metadata/",
            target_dir=str(dl),
            target_base_url=base + "/targets/",
            bootstrap=bootstrap,
            config=UpdaterConfig(),
        )
        up._trusted_set.reference_time = NOW  # the fixed clock
        step = "refresh"
        up.refresh()
        for p in TARGET_PATHS:
            step = "target-info"
            info = up.get_targetinfo(p)
            if info is None:
                return "REJECT", step, f"no target {p}"
            step = "target"
            got = Path(up.download_target(info)).read_bytes()
            if got != BODIES[p]:
                return "REJECT", step, f"{p}: downloaded bytes differ"
        return "ACCEPT", "-", ""
    except Exception as e:  # noqa: BLE001
        return "REJECT", step, f"{type(e).__name__}: {e}"[:150]
    finally:
        srv.shutdown()


def check(repo: Path, prior: str | None):
    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)
        cache, dl = tmp / "meta", tmp / "dl"
        cache.mkdir()
        dl.mkdir()
        if prior:
            v, s, e = run_client(repo.parent / prior, cache, tmp / "dl0")
            assert v == "ACCEPT", f"prior state {prior} was not accepted: {e}"
        return run_client(repo, cache, dl)


# --------------------------------------------------------------------------- main

# Where python-tuf is KNOWN to disagree with the contract (verdict it gives, and why).
PYTHON_TUF_DIVERGENCE = {
    "wrong-keyid-in-root": "ACCEPT",
}


def write_repo(root: Path, files: dict[str, bytes]):
    for rel, data in files.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(data)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", type=Path, default=OUT_DEFAULT)
    args = ap.parse_args()
    out: Path = args.out
    for child in out.iterdir() if out.exists() else []:
        if child.is_dir():
            shutil.rmtree(child)
    out.mkdir(parents=True, exist_ok=True)

    valid = build_valid()
    write_repo(out / "valid", valid)
    (out / "valid" / "expected.json").write_text(
        json.dumps(
            {
                "name": "valid",
                "now": NOW.strftime("%Y-%m-%dT%H:%M:%SZ"),
                "trust_anchor": "metadata/1.root.json",
                "result": "accepted: root 1 -> 2 -> 3, timestamp, snapshot 2, targets 2, "
                "both targets download and match",
                "targets": {p: target_file_name(p, BODIES[p]) for p in TARGET_PATHS},
            },
            indent=2,
        )
        + "\n"
    )

    keys = {
        "seed_prefix": SEED_PREFIX,
        "note": "SYNTHETIC test keys. seed = sha256(seed_prefix + name); Ed25519 private key from the 32-byte seed.",
        "keys": {
            n: {
                "seed_hex": SEEDS[n].hex(),
                "public_hex": key_of(n).keyval["public"],
                "keyid": keyid_of(n),
            }
            for n in [*KEY_NAMES, *V2_KEY_NAMES]
        },
        "roles": {
            "root-v1": {"root": "root-a", "targets": "targets", "snapshot": "snapshot", "timestamp": "timestamp-1"},
            "root-v2": {"root": "root-a", "targets": "targets", "snapshot": "snapshot", "timestamp": "timestamp-2"},
            "root-v3": {"root": "root-b", "targets": "targets", "snapshot": "snapshot", "timestamp": "timestamp-2"},
            "delegated-root-v1": {"root": "v2-root", "targets": "targets", "snapshot": "v2-snapshot",
                                  "timestamp": "v2-timestamp"},
            "delegations": {"pub-alpha": "pub-alpha", "pub-beta": "pub-beta",
                            "pub-beta (threshold 2, delegated-threshold-not-met)": "pub-beta + pub-beta-2"},
        },
        "times": {
            "signed_at": T0.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "now": NOW.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "timestamp_version": TS_VERSION,
        },
    }
    (out / "keys.json").write_text(json.dumps(keys, indent=2) + "\n")

    results = [("valid", "ACCEPT", *check(out / "valid", None))]
    ok = results[0][2] == "ACCEPT"
    for a in ATTACKS:
        files = copy.deepcopy(valid)
        a.build(files)
        changed = sorted(k for k in set(files) | set(valid) if files.get(k) != valid.get(k))
        write_repo(out / a.name, {k: v for k, v in files.items()})
        verdict, step, err = check(out / a.name, a.prior_state)
        divergence = PYTHON_TUF_DIVERGENCE.get(a.name)
        (out / a.name / "expected.json").write_text(
            json.dumps(
                {
                    "name": a.name,
                    "attack": a.attack,
                    "now": NOW.strftime("%Y-%m-%dT%H:%M:%SZ"),
                    "trust_anchor": "valid/metadata/1.root.json",
                    "prior_state": ("client already accepted the 'valid' repository at the same clock"
                                    if a.prior_state else None),
                    "must_fail_at": a.fails_at,
                    "error_class": a.error,
                    "changed_files_vs_valid": changed,
                    "python_tuf": {"verdict": verdict, "step": step, "error": err,
                                   "diverges_from_contract": divergence is not None},
                },
                indent=2,
            )
            + "\n"
        )
        results.append((a.name, divergence or "REJECT", verdict, step, err))
        if verdict != (divergence or "REJECT"):
            ok = False

    delegated = write_delegated(out)
    ok = ok and all(same for _, same, _ in delegated)

    w = max(len(r[0]) for r in results)
    print(f"{'repository'.ljust(w)}  python-tuf  step         error")
    for name, want, verdict, step, err in results:
        flag = "" if verdict == want else "  <-- UNEXPECTED"
        if want == "ACCEPT" and name != "valid":
            flag = "  (known divergence from the contract)"
        print(f"{name.ljust(w)}  {verdict:<10}  {step:<11}  {err}{flag}")
    print()
    for name, same, got in delegated:
        print(f"{name}: {got}{'' if same else '  <-- UNEXPECTED'}")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
