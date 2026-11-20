// The AMO-signed xpi of this build's version, when addons.mozilla.org already has it: the
// recovery half of the `extension` job of release.yml. AMO signs a version once, so after an
// upload whose signing step failed (a 5xx while web-ext polled, a lost connection, a rerun of
// the whole workflow) the signed file can only come from the version AMO made then.
//
//   node extension/sign/amo-signed.mjs --source-dir <dir> --artifacts-dir <dir>
//       [--timeout-minutes 20]
//
// The add-on id and version come from `<source-dir>/manifest.json`
// (`browser_specific_settings.gecko.id`, `version`); the API keys from WEB_EXT_API_KEY and
// WEB_EXT_API_SECRET, as web-ext reads them. Every request carries a fresh JWT; neither the
// secret nor a token is ever printed.
//
// Exit codes:
//   0  the version is on AMO, its file is `public` (signed), and it is saved as
//      `<artifacts-dir>/amo-<version>.xpi` after checking its size, sha256 and zip signature;
//   3  AMO has no such version (HTTP 404): nothing was uploaded yet;
//   1  anything else: the keys refused, a version that is not unlisted or disabled, a file
//      that AMO did not sign (`disabled`, or still `unreviewed` when the time is up), a
//      download from a host other than AMO's, a file that does not match AMO's hash;
//   2  wrong arguments or environment.
//
// 5xx, 429 and network errors are retried with backoff until the time is up. Only Node's own
// modules and global fetch are used: this runs with the secrets, after `npm ci` of web-ext,
// and must not load anything from node_modules.

import { createHash, createHmac, randomUUID } from 'node:crypto';
import { mkdirSync, readFileSync, renameSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';

export const API = 'https://addons.mozilla.org/api/v5/';
/** The only host that gets the Authorization header. */
export const API_HOST = 'addons.mozilla.org';
/** Where the signed file may come from, redirects included. */
export const DOWNLOAD_HOSTS = ['addons.mozilla.org', 'addons.cdn.mozilla.net'];
export const EXIT_ABSENT = 3;
/** AMO takes `exp` up to `iat` + 300. */
const JWT_LIFETIME_S = 60;
const MAX_REDIRECTS = 5;
const MAX_XPI_BYTES = 64 * 1024 * 1024;
const REQUEST_TIMEOUT_MS = 60_000;
const PENDING_WAIT_MS = 10_000;
const RETRY_FIRST_MS = 5_000;
const RETRY_MAX_MS = 60_000;
const USER_AGENT = 'OpenNCALayer-release-amo-signed';
const REDIRECTS = new Set([301, 302, 303, 307, 308]);

/** A failure that no retry can fix. */
export class Fatal extends Error {}

const base64url = (data) => Buffer.from(data).toString('base64url');

/** An HS256 JWT as AMO wants it: `iss` the key, a random `jti`, `iat` now, `exp` within 300 s. */
export function jwt(key, secret, nowSeconds) {
  const header = base64url(JSON.stringify({ alg: 'HS256', typ: 'JWT' }));
  const payload = base64url(
    JSON.stringify({ iss: key, jti: randomUUID(), iat: nowSeconds, exp: nowSeconds + JWT_LIFETIME_S }),
  );
  const signature = createHmac('sha256', Buffer.from(secret, 'utf8'))
    .update(`${header}.${payload}`)
    .digest('base64url');
  return `${header}.${payload}.${signature}`;
}

/** `raw` (relative to `base`) as a URL if it is https on one of `hosts` with no user or port. */
export function allowedUrl(raw, hosts, base) {
  let url;
  try {
    url = new URL(raw, base);
  } catch {
    throw new Fatal(`not a URL: ${JSON.stringify(String(raw)).slice(0, 200)}`);
  }
  if (
    url.protocol !== 'https:' ||
    !hosts.includes(url.hostname) ||
    url.username !== '' ||
    url.password !== '' ||
    url.port !== ''
  ) {
    throw new Fatal(`refusing ${url.protocol}//${url.host}: only https on ${hosts.join(', ')}`);
  }
  return url;
}

/** The URL without its query: what the log may show. */
const shown = (url) => `${url.origin}${url.pathname}`;

/** The API URL of version `version` of add-on `id` (`v` forces a lookup by version number). */
export function versionUrl(id, version) {
  return new URL(
    `addons/addon/${encodeURIComponent(id)}/versions/v${encodeURIComponent(version)}/`,
    API,
  );
}

/**
 * GET `start`, following redirects by hand: each Location must be on `hosts`, and only
 * requests to API_HOST carry the JWT. Returns the first response that is not a redirect.
 */
async function get(ctx, start, hosts, accept) {
  let url = allowedUrl(start, hosts);
  for (let hop = 0; ; hop++) {
    const headers = { Accept: accept, 'User-Agent': USER_AGENT };
    if (url.hostname === API_HOST) {
      headers.Authorization = `JWT ${jwt(ctx.key, ctx.secret, Math.floor(ctx.now() / 1000))}`;
    }
    const response = await ctx.fetch(url, {
      headers,
      redirect: 'manual',
      signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
    });
    if (!REDIRECTS.has(response.status)) {
      return response;
    }
    await response.body?.cancel();
    if (hop >= MAX_REDIRECTS) {
      throw new Fatal(`more than ${MAX_REDIRECTS} redirects from ${shown(allowedUrl(start, hosts))}`);
    }
    const location = response.headers.get('location');
    if (!location) {
      throw new Fatal(`redirect ${response.status} without Location from ${shown(url)}`);
    }
    url = allowedUrl(location, hosts, url);
  }
}

/** Whether `status` is worth asking again. */
const transient = (status) => status >= 500 || status === 429;

/** The version's JSON; `null` when AMO has no such version. Throws Fatal or a retryable Error. */
async function fetchVersion(ctx) {
  const response = await get(ctx, versionUrl(ctx.id, ctx.version), [API_HOST], 'application/json');
  if (response.status === 404) {
    await response.body?.cancel();
    return null;
  }
  if (transient(response.status)) {
    await response.body?.cancel();
    throw new Error(`AMO answered ${response.status}`);
  }
  if (response.status === 401 || response.status === 403) {
    await response.body?.cancel();
    throw new Fatal(`AMO refused the API keys (${response.status})`);
  }
  if (response.status !== 200) {
    await response.body?.cancel();
    throw new Fatal(`AMO answered ${response.status} for the version`);
  }
  try {
    return await response.json();
  } catch (e) {
    throw new Error(`the version's JSON did not parse: ${e.message}`);
  }
}

/** `'public'` (signed), `'pending'`, or throws Fatal for a version that will never do. */
function verdict(ctx, data) {
  if (data?.version !== ctx.version) {
    throw new Fatal(`AMO returned version ${JSON.stringify(data?.version)}, not ${ctx.version}`);
  }
  if (data.channel !== 'unlisted') {
    throw new Fatal(`version ${ctx.version} is in channel ${JSON.stringify(data.channel)}, not unlisted`);
  }
  if (data.is_disabled === true) {
    throw new Fatal(`version ${ctx.version} is disabled on AMO`);
  }
  const status = data.file?.status;
  if (status === 'public') {
    return 'public';
  }
  if (status === 'unreviewed' || status === 'nominated') {
    return 'pending';
  }
  throw new Fatal(`the file of version ${ctx.version} has status ${JSON.stringify(status)}: AMO did not sign it`);
}

/** The signed file's bytes, checked against AMO's size and sha256 and for a zip signature. */
async function fetchFile(ctx, file) {
  const url = allowedUrl(file.url, DOWNLOAD_HOSTS);
  const hash = /^sha256:([0-9a-f]{64})$/.exec(String(file.hash ?? ''));
  if (!hash) {
    throw new Fatal(`AMO gave no sha256 for the file (hash ${JSON.stringify(file.hash)})`);
  }
  const response = await get(ctx, url, DOWNLOAD_HOSTS, 'application/x-xpinstall, */*');
  if (transient(response.status)) {
    await response.body?.cancel();
    throw new Error(`the download answered ${response.status}`);
  }
  if (response.status !== 200) {
    await response.body?.cancel();
    throw new Fatal(`the download answered ${response.status}`);
  }
  if (Number(response.headers.get('content-length') ?? 0) > MAX_XPI_BYTES) {
    await response.body?.cancel();
    throw new Fatal(`the file is larger than ${MAX_XPI_BYTES} bytes`);
  }
  const bytes = Buffer.from(await response.arrayBuffer());
  if (bytes.length > MAX_XPI_BYTES) {
    throw new Fatal(`the file is larger than ${MAX_XPI_BYTES} bytes`);
  }
  if (typeof file.size === 'number' && bytes.length !== file.size) {
    throw new Error(`downloaded ${bytes.length} bytes, AMO says ${file.size}`);
  }
  const sha256 = createHash('sha256').update(bytes).digest('hex');
  if (sha256 !== hash[1]) {
    throw new Error(`the downloaded file's sha256 ${sha256} is not AMO's ${hash[1]}`);
  }
  if (bytes.length < 4 || bytes.readUInt32LE(0) !== 0x04034b50) {
    throw new Fatal('the signed file is not a zip archive');
  }
  return bytes;
}

/**
 * Looks the version up, waits while AMO is signing it, and saves the signed file. Returns
 * the exit code. `ctx`: `{ key, secret, id, version, artifactsDir, timeoutMs, fetch, now,
 * sleep, log }`.
 */
export async function run(ctx) {
  const deadline = ctx.now() + ctx.timeoutMs;
  let retryWait = RETRY_FIRST_MS;
  let file = null;
  for (;;) {
    let wait;
    try {
      if (file === null) {
        const data = await fetchVersion(ctx);
        if (data === null) {
          ctx.log(`AMO has no version ${ctx.version} of ${ctx.id}`);
          return EXIT_ABSENT;
        }
        if (verdict(ctx, data) === 'public') {
          file = data.file;
          ctx.log(`AMO has version ${ctx.version} of ${ctx.id} signed; downloading ${shown(allowedUrl(file.url, DOWNLOAD_HOSTS))}`);
          continue;
        }
        ctx.log(`version ${ctx.version} is on AMO, not signed yet (${data.file?.status})`);
        wait = PENDING_WAIT_MS;
      } else {
        const bytes = await fetchFile(ctx, file);
        const name = `amo-${ctx.version}.xpi`;
        try {
          mkdirSync(ctx.artifactsDir, { recursive: true });
          const part = join(ctx.artifactsDir, `.${name}.part`);
          writeFileSync(part, bytes);
          renameSync(part, join(ctx.artifactsDir, name));
        } catch (e) {
          throw new Fatal(`saving the file: ${e.message}`);
        }
        ctx.log(`saved ${join(ctx.artifactsDir, name)} (${bytes.length} bytes, sha256 as AMO lists it)`);
        return 0;
      }
    } catch (e) {
      if (e instanceof Fatal) {
        throw e;
      }
      ctx.log(`retrying: ${e.message}${e.cause?.code ? ` (${e.cause.code})` : ''}`);
      wait = retryWait;
      retryWait = Math.min(retryWait * 2, RETRY_MAX_MS);
    }
    const left = deadline - ctx.now();
    if (left <= 0) {
      throw new Fatal(
        `gave up after ${Math.round(ctx.timeoutMs / 60_000)} minutes: ${file === null ? 'the version is not signed' : 'the download did not succeed'}`,
      );
    }
    await ctx.sleep(Math.min(wait, left));
  }
}

/** `{ sourceDir, artifactsDir, timeoutMinutes }` from argv, or throws a usage message. */
export function parseArgs(argv) {
  const args = { timeoutMinutes: 20 };
  for (let i = 0; i < argv.length; i += 2) {
    const value = argv[i + 1];
    if (value === undefined) {
      throw new Error(`${argv[i]} needs a value`);
    }
    switch (argv[i]) {
      case '--source-dir':
        args.sourceDir = value;
        break;
      case '--artifacts-dir':
        args.artifactsDir = value;
        break;
      case '--timeout-minutes':
        args.timeoutMinutes = Number(value);
        if (!(args.timeoutMinutes > 0)) {
          throw new Error(`--timeout-minutes: not a positive number: ${value}`);
        }
        break;
      default:
        throw new Error(`unknown argument ${argv[i]}`);
    }
  }
  if (!args.sourceDir || !args.artifactsDir) {
    throw new Error('usage: amo-signed.mjs --source-dir <dir> --artifacts-dir <dir> [--timeout-minutes N]');
  }
  return args;
}

/** The add-on id and version of the unsigned build in `sourceDir`. */
export function readManifest(sourceDir) {
  const manifest = JSON.parse(readFileSync(join(sourceDir, 'manifest.json'), 'utf8'));
  const id = manifest?.browser_specific_settings?.gecko?.id;
  const version = manifest?.version;
  if (typeof id !== 'string' || id === '') {
    throw new Error('manifest.json has no browser_specific_settings.gecko.id');
  }
  if (typeof version !== 'string' || !/^\d+(\.\d+){0,3}$/.test(version)) {
    throw new Error(`manifest.json: version ${JSON.stringify(version)} is not a Firefox version`);
  }
  return { id, version };
}

async function main() {
  let ctx;
  try {
    const args = parseArgs(process.argv.slice(2));
    const key = process.env.WEB_EXT_API_KEY ?? '';
    const secret = process.env.WEB_EXT_API_SECRET ?? '';
    if (key === '' || secret === '') {
      throw new Error('WEB_EXT_API_KEY and WEB_EXT_API_SECRET must be set');
    }
    ctx = {
      key,
      secret,
      ...readManifest(args.sourceDir),
      artifactsDir: args.artifactsDir,
      timeoutMs: args.timeoutMinutes * 60_000,
      fetch: globalThis.fetch,
      now: Date.now,
      sleep: (ms) => new Promise((resolve) => setTimeout(resolve, ms)),
      log: (line) => console.log(`amo-signed: ${line}`),
    };
  } catch (e) {
    console.log(`::error::amo-signed: ${e.message}`);
    return 2;
  }
  try {
    return await run(ctx);
  } catch (e) {
    console.log(`::error::amo-signed: ${e instanceof Fatal ? e.message : `unexpected: ${e.message}`}`);
    return 1;
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  process.exitCode = await main();
}
