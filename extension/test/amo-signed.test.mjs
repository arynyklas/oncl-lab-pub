// extension/sign/amo-signed.mjs (the AMO recovery of release.yml) against a fake AMO: the JWT
// it sends, what it reuses, what it refuses, and where its Authorization header goes.
import assert from 'node:assert/strict';
import { createHash, createHmac } from 'node:crypto';
import { mkdtempSync, readdirSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';

import {
  allowedUrl,
  DOWNLOAD_HOSTS,
  EXIT_ABSENT,
  Fatal,
  jwt,
  parseArgs,
  run,
  versionUrl,
} from '../sign/amo-signed.mjs';

const KEY = 'user:12345:67';
const SECRET = 'a-test-secret-that-is-not-real';
const ID = 'openncalayer@arynyklas.github.io';
const VERSION = '0.1.2';
const VERSION_URL = versionUrl(ID, VERSION).href;
const FILE_URL = 'https://addons.mozilla.org/firefox/downloads/file/42/openncalayer-0.1.2.xpi';
const XPI = Buffer.concat([Buffer.from('PK\x03\x04', 'latin1'), Buffer.from('signed bytes')]);
const sha256 = (bytes) => createHash('sha256').update(bytes).digest('hex');

function decode(part) {
  return JSON.parse(Buffer.from(part, 'base64url').toString('utf8'));
}

test('the JWT is HS256 with iss, a random jti, iat and exp within 300 s', () => {
  const token = jwt(KEY, SECRET, 1_700_000_000);
  const [header, payload, signature] = token.split('.');
  assert.deepEqual(decode(header), { alg: 'HS256', typ: 'JWT' });
  const claims = decode(payload);
  assert.deepEqual(Object.keys(claims).sort(), ['exp', 'iat', 'iss', 'jti']);
  assert.equal(claims.iss, KEY);
  assert.equal(claims.iat, 1_700_000_000);
  assert.ok(claims.exp > claims.iat && claims.exp <= claims.iat + 300);
  assert.match(claims.jti, /^[0-9a-f-]{36}$/);
  const expected = createHmac('sha256', SECRET).update(`${header}.${payload}`).digest('base64url');
  assert.equal(signature, expected);
  assert.notEqual(decode(jwt(KEY, SECRET, 1_700_000_000).split('.')[1]).jti, claims.jti);
});

test('the version URL looks the version up by number', () => {
  assert.equal(
    VERSION_URL,
    'https://addons.mozilla.org/api/v5/addons/addon/openncalayer%40arynyklas.github.io/versions/v0.1.2/',
  );
});

test('only https on the listed hosts is allowed', () => {
  assert.equal(allowedUrl(FILE_URL, DOWNLOAD_HOSTS).hostname, 'addons.mozilla.org');
  assert.equal(allowedUrl('https://addons.cdn.mozilla.net/x.xpi', DOWNLOAD_HOSTS).pathname, '/x.xpi');
  for (const bad of [
    'http://addons.mozilla.org/x.xpi',
    'https://evil.example/x.xpi',
    'https://addons.mozilla.org.evil.example/x.xpi',
    'https://user:pw@addons.mozilla.org/x.xpi',
    'https://addons.mozilla.org:8443/x.xpi',
    'file:///etc/passwd',
    'not a url',
  ]) {
    assert.throws(() => allowedUrl(bad, DOWNLOAD_HOSTS), Fatal, bad);
  }
});

test('arguments', () => {
  assert.deepEqual(parseArgs(['--source-dir', 's', '--artifacts-dir', 'a']), {
    sourceDir: 's',
    artifactsDir: 'a',
    timeoutMinutes: 20,
  });
  assert.throws(() => parseArgs(['--source-dir', 's']));
  assert.throws(() => parseArgs(['--source-dir', 's', '--artifacts-dir', 'a', '--timeout-minutes', '0']));
  assert.throws(() => parseArgs(['--what', 'x']));
});

/** A version as AMO lists it. */
function version(status, overrides = {}) {
  return {
    version: VERSION,
    channel: 'unlisted',
    is_disabled: false,
    file: { status, url: FILE_URL, size: XPI.length, hash: `sha256:${sha256(XPI)}` },
    ...overrides,
  };
}

const json = (body, status = 200) =>
  new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } });

/**
 * A run against `routes`: url → a function returning the next Response (or throwing). Records
 * every request; time only moves when the script sleeps.
 */
async function fake(routes, timeoutMs = 20 * 60_000) {
  const dir = mkdtempSync(join(tmpdir(), 'amo-signed-'));
  const requests = [];
  const logs = [];
  let clock = 1_700_000_000_000;
  const ctx = {
    key: KEY,
    secret: SECRET,
    id: ID,
    version: VERSION,
    artifactsDir: join(dir, 'signed'),
    timeoutMs,
    fetch: async (url, init) => {
      assert.equal(init.redirect, 'manual');
      requests.push({ url: url.href, authorization: init.headers.Authorization });
      const route = routes[url.href];
      assert.ok(route, `unexpected request ${url.href}`);
      return route();
    },
    now: () => clock,
    sleep: async (ms) => {
      clock += ms;
    },
    log: (line) => logs.push(line),
  };
  try {
    let outcome;
    try {
      outcome = await run(ctx);
    } catch (e) {
      outcome = e;
    }
    let files = [];
    try {
      files = readdirSync(ctx.artifactsDir).map((name) => [name, readFileSync(join(ctx.artifactsDir, name))]);
    } catch {}
    return { outcome, requests, logs, files, elapsed: clock - 1_700_000_000_000 };
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

/** Answers in turn, the last one forever. */
function sequence(...answers) {
  let i = 0;
  return () => {
    const answer = answers[Math.min(i++, answers.length - 1)];
    if (answer instanceof Error) {
      throw answer;
    }
    return answer();
  };
}

test('a version AMO does not have exits 3 and saves nothing', async () => {
  const r = await fake({ [VERSION_URL]: () => json({ detail: 'Not found.' }, 404) });
  assert.equal(r.outcome, EXIT_ABSENT);
  assert.deepEqual(r.files, []);
});

test('a signed version is downloaded, retrying 5xx and network errors, auth only to AMO', async () => {
  const r = await fake({
    [VERSION_URL]: sequence(
      () => json({}, 502),
      new TypeError('fetch failed'),
      () => json(version('unreviewed')),
      () => json(version('public')),
    ),
    [FILE_URL]: sequence(
      () => new Response(null, { status: 503 }),
      () => new Response(null, { status: 302, headers: { location: 'https://addons.cdn.mozilla.net/user-media/x.xpi?sig=1' } }),
    ),
    'https://addons.cdn.mozilla.net/user-media/x.xpi?sig=1': () => new Response(XPI),
  });
  assert.equal(r.outcome, 0);
  assert.deepEqual(r.files, [[`amo-${VERSION}.xpi`, XPI]]);
  for (const { url, authorization } of r.requests) {
    if (new URL(url).hostname === 'addons.mozilla.org') {
      assert.match(authorization, /^JWT [\w-]+\.[\w-]+\.[\w-]+$/);
    } else {
      assert.equal(authorization, undefined, url);
    }
  }
  // A fresh token per request.
  const tokens = r.requests.filter((q) => q.authorization).map((q) => q.authorization);
  assert.equal(new Set(tokens).size, tokens.length);
  // Neither the secret nor a token reaches the log.
  for (const line of r.logs) {
    assert.ok(!line.includes(SECRET) && !line.includes('JWT '), line);
  }
});

test('a redirect off AMO is refused before it is requested', async () => {
  const r = await fake({
    [VERSION_URL]: () => json(version('public')),
    [FILE_URL]: () =>
      new Response(null, { status: 302, headers: { location: 'https://evil.example/x.xpi' } }),
  });
  assert.ok(r.outcome instanceof Fatal, String(r.outcome));
  assert.match(r.outcome.message, /evil\.example/);
  assert.ok(!r.requests.some((q) => q.url.startsWith('https://evil.example')));
  assert.deepEqual(r.files, []);
});

test('a file URL off AMO is refused', async () => {
  const r = await fake({
    [VERSION_URL]: () => json(version('public', { file: { ...version('public').file, url: 'https://evil.example/x.xpi' } })),
  });
  assert.ok(r.outcome instanceof Fatal);
  assert.equal(r.requests.length, 1);
});

for (const [what, data] of [
  ['a rejected file', version('disabled')],
  ['a disabled version', version('public', { is_disabled: true })],
  ['a listed version', version('public', { channel: 'listed' })],
  ['another version', version('public', { version: '0.1.1' })],
]) {
  test(`${what} is never used`, async () => {
    const r = await fake({ [VERSION_URL]: () => json(data) });
    assert.ok(r.outcome instanceof Fatal, `${what}: ${r.outcome}`);
    assert.deepEqual(r.files, []);
  });
}

test('a version still unreviewed when the time is up fails', async () => {
  const r = await fake({ [VERSION_URL]: () => json(version('unreviewed')) }, 60_000);
  assert.ok(r.outcome instanceof Fatal);
  assert.match(r.outcome.message, /not signed/);
  assert.equal(r.elapsed, 60_000);
});

test('rejected keys fail at once', async () => {
  const r = await fake({ [VERSION_URL]: () => json({}, 401) });
  assert.ok(r.outcome instanceof Fatal);
  assert.equal(r.requests.length, 1);
});

test('a file whose hash is not AMO\'s is not saved', async () => {
  const r = await fake(
    {
      [VERSION_URL]: () => json(version('public')),
      [FILE_URL]: () => new Response(Buffer.concat([XPI.subarray(0, XPI.length - 1), Buffer.from('X')])),
    },
    60_000,
  );
  assert.ok(r.outcome instanceof Fatal);
  assert.deepEqual(r.files, []);
});

test('a file that is not a zip is not saved', async () => {
  const notZip = Buffer.from('<html>error</html>');
  const r = await fake({
    [VERSION_URL]: () =>
      json(version('public', { file: { ...version('public').file, size: notZip.length, hash: `sha256:${sha256(notZip)}` } })),
    [FILE_URL]: () => new Response(notZip),
  });
  assert.ok(r.outcome instanceof Fatal);
  assert.match(r.outcome.message, /not a zip/);
  assert.deepEqual(r.files, []);
});
