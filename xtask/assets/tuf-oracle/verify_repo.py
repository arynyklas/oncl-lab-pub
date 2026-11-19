#!/usr/bin/env python3
"""A second implementation reads the TUF repository about to be published.

python-tuf's ngclient is pointed at a directory served by `http.server` on loopback, starts
from the trust anchor (`crates/oncl-update/keys/root.json`), refreshes the metadata and
downloads the update indexes (`indexes/stable.json`, `indexes/beta.json`), which must be the
bytes of `<index dir>/<channel>.json`.

Its acceptance is NECESSARY, NOT SUFFICIENT: python-tuf accepts things the Rust client
(`oncl_update::tuf`, the contract) refuses (for instance a root shared between roles, or
metadata with fields it ignores). `cargo xtask tuf check` is the check that decides; this one
catches a mistake both sides of this repository's own code could share.

    verify_repo.py --dir <repository> --root <root.json> [--index <updates/v1>]
"""

import argparse
import functools
import http.server
import pathlib
import sys
import tempfile
import threading

from tuf.ngclient import Updater

CHANNELS = ("stable", "beta")


class QuietHandler(http.server.SimpleHTTPRequestHandler):
    def log_message(self, *_args):
        pass


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--dir", required=True, type=pathlib.Path, help="the repository directory")
    parser.add_argument("--root", required=True, type=pathlib.Path, help="the trust anchor")
    parser.add_argument("--index", type=pathlib.Path, help="the directory of the indexes to compare")
    args = parser.parse_args()

    handler = functools.partial(QuietHandler, directory=str(args.dir))
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{server.server_address[1]}"

    failures = []
    with tempfile.TemporaryDirectory() as scratch:
        metadata = pathlib.Path(scratch) / "metadata"
        targets = pathlib.Path(scratch) / "targets"
        metadata.mkdir()
        targets.mkdir()
        updater = Updater(
            metadata_dir=str(metadata),
            metadata_base_url=f"{base}/metadata/",
            target_base_url=f"{base}/targets/",
            target_dir=str(targets),
            bootstrap=args.root.read_bytes(),
        )
        updater.refresh()
        for channel in CHANNELS:
            name = f"indexes/{channel}.json"
            info = updater.get_targetinfo(name)
            index = args.index / f"{channel}.json" if args.index else None
            if info is None:
                if index is not None and index.exists():
                    failures.append(f"{name} is not a target, but {index} exists")
                continue
            path = updater.download_target(info)
            body = pathlib.Path(path).read_bytes()
            print(f"python-tuf: {name}: {len(body)} bytes, hashes verified")
            if index is not None:
                if not index.exists():
                    failures.append(f"{name} is a target, but {index} does not exist")
                elif index.read_bytes() != body:
                    failures.append(f"{name} is not the bytes of {index}")
    server.shutdown()
    for failure in failures:
        print(f"python-tuf: {failure}", file=sys.stderr)
    if failures:
        return 1
    print("python-tuf: ok")
    return 0


if __name__ == "__main__":
    sys.exit(main())
