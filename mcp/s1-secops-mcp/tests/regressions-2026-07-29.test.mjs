/**
 * Regression tests for the 2026-07-29 defect-review fixes.
 *
 * 1. resolveLrqWindow: each time bound must default INDEPENDENTLY.
 *    The original bug overwrote BOTH bounds when either was missing, so a
 *    startTime-only call silently ran over the last `hours` window.
 *    Live A/B (prod tenant, read-only): startTime-only for a 7.4-day window
 *    returned 12,880 events == the 24h control (12,875), vs 73,099 for the
 *    correctly pinned window.
 *
 * 2. pickMatchCount: matchCount lives at data.matchCount on current LRQ
 *    engines. Reading only the top level returned null on all 22 live calls.
 *
 * 3. sdlToken + sdlFetch: every SDL call authenticates with the console API
 *    token as `Authorization: Bearer <token>`, and a missing token fails
 *    fast with an actionable message rather than sending `Bearer undefined`.
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { resolveLrqWindow, pickMatchCount } from '../lib/s1.js';
import { sdlToken } from '../lib/sdl.js';

// ─── resolveLrqWindow ─────────────────────────────────────────────────────────

test('resolveLrqWindow: both bounds omitted → endTime≈now, startTime = endTime - hours', () => {
  const before = Date.now();
  const { startTime, endTime } = resolveLrqWindow({ hours: 24 });
  const after = Date.now();
  const end = new Date(endTime).getTime();
  const start = new Date(startTime).getTime();
  assert.ok(end >= before - 2000 && end <= after + 2000, 'endTime should be ~now');
  assert.equal(end - start, 24 * 3600 * 1000, 'window should be exactly `hours` wide');
});

test('resolveLrqWindow: startTime-only must be PRESERVED (the 2026-07-29 bug)', () => {
  const { startTime, endTime } = resolveLrqWindow({ startTime: '2026-07-22T00:00:00Z' });
  assert.equal(startTime, '2026-07-22T00:00:00Z',
    'caller-supplied startTime must never be overwritten');
  assert.ok(new Date(endTime).getTime() > new Date('2026-07-28T00:00:00Z').getTime(),
    'endTime should default to now, not to startTime + hours');
});

test('resolveLrqWindow: endTime-only → startTime = endTime - hours', () => {
  const { startTime, endTime } = resolveLrqWindow({ endTime: '2026-07-29T00:00:00Z', hours: 48 });
  assert.equal(endTime, '2026-07-29T00:00:00Z');
  assert.equal(startTime, '2026-07-27T00:00:00Z');
});

test('resolveLrqWindow: both provided → untouched', () => {
  const { startTime, endTime } = resolveLrqWindow({
    startTime: '2026-07-01T00:00:00Z',
    endTime: '2026-07-15T12:34:56Z',
  });
  assert.equal(startTime, '2026-07-01T00:00:00Z');
  assert.equal(endTime, '2026-07-15T12:34:56Z');
});

// ─── pickMatchCount ───────────────────────────────────────────────────────────

test('pickMatchCount: reads data.matchCount (current engines)', () => {
  assert.equal(pickMatchCount({ data: { matchCount: 42 } }), 42);
});

test('pickMatchCount: data.matchCount of 0 is a real value, not "missing"', () => {
  assert.equal(pickMatchCount({ data: { matchCount: 0 }, matchCount: 99 }), 0);
});

test('pickMatchCount: falls back to top level (legacy engines)', () => {
  assert.equal(pickMatchCount({ matchCount: 7, data: {} }), 7);
});

test('pickMatchCount: null when absent everywhere', () => {
  assert.equal(pickMatchCount({ data: {} }), null);
  assert.equal(pickMatchCount({}), null);
});

// ─── sdlToken ─────────────────────────────────────────────────────────────────

test('sdlToken: returns the console API token', () => {
  process.env.S1_CONSOLE_API_TOKEN = 'console-token';
  try {
    assert.equal(sdlToken(), 'console-token');
  } finally {
    delete process.env.S1_CONSOLE_API_TOKEN;
  }
});

test('sdlToken: throws an actionable error when the token is absent', async () => {
  // Runs in a CHILD PROCESS on purpose.
  //
  // credentials.js resolves the credentials file ONCE, at module import
  // (`const _file = discoverCredentials()`), and discovery walks up from cwd as
  // well as reading env vars. So no amount of deleting process.env inside this
  // process can make the token absent: the file still supplies it. The original
  // version of this test asserted an exception that could only be thrown on a
  // machine with no credentials configured anywhere, i.e. the one environment
  // where the error message does not matter. It passed by accident in CI and
  // failed the moment anyone ran the suite on a working machine.
  //
  // A fresh process with a scrubbed environment and a neutral cwd is the only
  // honest way to test "credential missing" for a module that caches discovery
  // at import time.
  const { execFileSync } = await import('node:child_process');
  const here = new URL('.', import.meta.url).pathname;
  const src = `
    import { sdlToken } from '${here}../lib/sdl.js';
    try { sdlToken(); console.log('NO_THROW'); }
    catch (e) { console.log('THREW:' + e.message); }
  `;
  const out = execFileSync(process.execPath, ['--input-type=module', '-e', src], {
    cwd: '/',
    env: { PATH: process.env.PATH, HOME: '/nonexistent',
           S1_CREDS_FILE: '/nonexistent/creds.json',
           COWORK_WORKSPACE: '/nonexistent',
           CLAUDE_CONFIG_DIR: '/nonexistent' },
    encoding: 'utf-8',
  }).trim();
  assert.match(out, /^THREW:/, `expected a throw, got: ${out}`);
  assert.match(out, /S1_CONSOLE_API_TOKEN not configured/);
});

// ─── hecIngest Content-Type per endpoint (mocked fetch, no network) ──────────
// /event takes HEC JSON envelopes and must be application/json or the envelope
// (including per-event "time" backdating) is indexed as opaque text at receive
// time. Live-verified 2026-07-29: with the fix, a {"time": <epoch>} envelope
// posted via hec_ingest indexed at exactly the backdated timestamp.

test('hecIngest: /event posts application/json, /raw posts text/plain', async () => {
  process.env.S1_HEC_INGEST_URL = 'https://ingest.example.invalid';
  process.env.S1_HEC_TOKEN = 'write-key';
  const seen = [];
  const realFetch = globalThis.fetch;
  globalThis.fetch = async (url, opts) => {
    seen.push({ url, headers: opts.headers, contentType: opts.headers['Content-Type'] });
    return new Response(JSON.stringify({ text: 'Success', code: 0 }), {
      status: 200, headers: { 'Content-Type': 'application/json' },
    });
  };
  try {
    const { hecIngest } = await import('../lib/hec.js');
    await hecIngest('{"time":123,"event":"x"}', { endpoint: 'event' });
    await hecIngest('plain line', { endpoint: 'raw' });
    assert.equal(seen[0].contentType, 'application/json');
    assert.equal(seen[1].contentType, 'text/plain');
  } finally {
    globalThis.fetch = realFetch;
    delete process.env.S1_HEC_INGEST_URL;
    delete process.env.S1_HEC_TOKEN;
  }
});

// ─── log ingest uses the SDL Log Write Key, and sends no scope ───────────────
// Measured on a live tenant: the write key returns 200 with no S1-Scope header,
// while the console token on the identical request returns 400 "Missing S1-Scope
// header". The key is minted per account/site and fixes the destination, so
// there is nothing for a scope header to override.

test('hecIngest: authenticates with S1_HEC_TOKEN, not the console token', async () => {
  process.env.S1_HEC_INGEST_URL = 'https://ingest.example.invalid';
  process.env.S1_HEC_TOKEN = 'write-key';
  process.env.S1_CONSOLE_API_TOKEN = 'console-token-must-not-be-used';
  let auth;
  const realFetch = globalThis.fetch;
  globalThis.fetch = async (url, opts) => {
    auth = opts.headers.Authorization;
    return new Response('{}', { status: 200, headers: { 'Content-Type': 'application/json' } });
  };
  try {
    const { hecIngest } = await import('../lib/hec.js');
    await hecIngest('line', { endpoint: 'raw' });
    assert.equal(auth, 'Bearer write-key');
    assert.ok(!/console-token/.test(auth), 'the console token must never reach the collector');
  } finally {
    globalThis.fetch = realFetch;
    delete process.env.S1_HEC_INGEST_URL;
    delete process.env.S1_HEC_TOKEN;
    delete process.env.S1_CONSOLE_API_TOKEN;
  }
});

test('hecIngest: sends no S1-Scope header, even when a scope is passed', async () => {
  process.env.S1_HEC_INGEST_URL = 'https://ingest.example.invalid';
  process.env.S1_HEC_TOKEN = 'write-key';
  let headers;
  const realFetch = globalThis.fetch;
  globalThis.fetch = async (url, opts) => {
    headers = opts.headers;
    return new Response('{}', { status: 200, headers: { 'Content-Type': 'application/json' } });
  };
  try {
    const { hecIngest } = await import('../lib/hec.js');
    // A caller written against the old signature still passes scope. It must be
    // ignored rather than sent: an empty or wrong scope is a different request
    // to no scope at all.
    await hecIngest('line', { endpoint: 'raw', scope: '123456:789' });
    assert.ok(!('S1-Scope' in headers), `S1-Scope must not be sent, got ${JSON.stringify(headers)}`);
  } finally {
    globalThis.fetch = realFetch;
    delete process.env.S1_HEC_INGEST_URL;
    delete process.env.S1_HEC_TOKEN;
  }
});

test('hecIngest: a missing write key names the credential and where to mint it', async () => {
  const saved = { url: process.env.S1_HEC_INGEST_URL, tok: process.env.S1_HEC_TOKEN,
                  f: process.env.S1_CREDS_FILE, w: process.env.COWORK_WORKSPACE, c: process.env.CLAUDE_CONFIG_DIR };
  process.env.S1_HEC_INGEST_URL = 'https://ingest.example.invalid';
  delete process.env.S1_HEC_TOKEN;
  process.env.S1_CREDS_FILE = '/nonexistent/creds.json';
  process.env.COWORK_WORKSPACE = '/nonexistent';
  process.env.CLAUDE_CONFIG_DIR = '/nonexistent';
  try {
    const { hecIngest } = await import('../lib/hec.js');
    await assert.rejects(() => hecIngest('line', { endpoint: 'raw' }),
      /S1_HEC_TOKEN not configured[\s\S]*Log Write Key/);
  } finally {
    for (const [k, v] of Object.entries({ S1_HEC_INGEST_URL: saved.url, S1_HEC_TOKEN: saved.tok,
        S1_CREDS_FILE: saved.f, COWORK_WORKSPACE: saved.w, CLAUDE_CONFIG_DIR: saved.c })) {
      if (v !== undefined) process.env[k] = v; else delete process.env[k];
    }
  }
});

// ─── doFetch write-retry semantics (mocked fetch, no network) ────────────────
// A 5xx after a mutating POST may land after the server committed; auto-retry
// would double-write. GET (idempotent) still retries; POST does not unless the
// caller opts in for a read-only POST (GraphQL query, Purple launch).

test('apiGet retries on 500 (idempotent)', async () => {
  process.env.S1_CONSOLE_URL = 'https://mgmt.example.invalid';
  process.env.S1_CONSOLE_API_TOKEN = 'tok';
  let calls = 0;
  const realFetch = globalThis.fetch;
  globalThis.fetch = async () => {
    calls++;
    if (calls === 1) return new Response('err', { status: 500 });
    return new Response(JSON.stringify({ data: { ok: true } }), { status: 200, headers: { 'Content-Type': 'application/json' } });
  };
  try {
    const { apiGet } = await import('../lib/s1.js');
    const r = await apiGet('/web/api/v2.1/agents');
    assert.equal(calls, 2, 'GET should retry once then succeed');
    assert.deepEqual(r, { data: { ok: true } });
  } finally {
    globalThis.fetch = realFetch;
    delete process.env.S1_CONSOLE_URL; delete process.env.S1_CONSOLE_API_TOKEN;
  }
});

test('apiPost does NOT retry a mutating POST on 500 (no double-write)', async () => {
  process.env.S1_CONSOLE_URL = 'https://mgmt.example.invalid';
  process.env.S1_CONSOLE_API_TOKEN = 'tok';
  let calls = 0;
  const realFetch = globalThis.fetch;
  globalThis.fetch = async () => { calls++; return new Response('boom', { status: 500 }); };
  try {
    const { apiPost } = await import('../lib/s1.js');
    await assert.rejects(() => apiPost('/web/api/v2.1/cloud-detection/rules', { data: {} }));
    assert.equal(calls, 1, 'mutating POST must be attempted exactly once');
  } finally {
    globalThis.fetch = realFetch;
    delete process.env.S1_CONSOLE_URL; delete process.env.S1_CONSOLE_API_TOKEN;
  }
});

test('apiPost with allowRetry:true retries a read-only POST on 500', async () => {
  process.env.S1_CONSOLE_URL = 'https://mgmt.example.invalid';
  process.env.S1_CONSOLE_API_TOKEN = 'tok';
  let calls = 0;
  const realFetch = globalThis.fetch;
  globalThis.fetch = async () => {
    calls++;
    if (calls === 1) return new Response('err', { status: 503 });
    return new Response(JSON.stringify({ data: {} }), { status: 200, headers: { 'Content-Type': 'application/json' } });
  };
  try {
    const { apiPost } = await import('../lib/s1.js');
    await apiPost('/web/api/v2.1/graphql', { query: '{x}' }, { allowRetry: true });
    assert.equal(calls, 2, 'opted-in read-only POST should retry');
  } finally {
    globalThis.fetch = realFetch;
    delete process.env.S1_CONSOLE_URL; delete process.env.S1_CONSOLE_API_TOKEN;
  }
});

// ─── sdlFetch auth header (mocked fetch, no network) ─────────────────────────

test('sdlFetch: sends the console API token as a Bearer header', async () => {
  process.env.S1_CONSOLE_URL = 'https://console.example.invalid';
  process.env.S1_CONSOLE_API_TOKEN = 'console-token';

  const seenTokens = [];
  const realFetch = globalThis.fetch;
  globalThis.fetch = async (url, opts) => {
    seenTokens.push(opts.headers.Authorization);
    return new Response(JSON.stringify({ matches: [] }), {
      status: 200, headers: { 'Content-Type': 'application/json' },
    });
  };

  try {
    const { v1Query } = await import('../lib/sdl.js');
    const res = await v1Query("dataSource.name=='x'", { maxCount: 1 });
    assert.deepEqual(res, { matches: [] });
    assert.deepEqual(seenTokens, ['Bearer console-token'],
      'exactly one credential is used: the console API token');
  } finally {
    globalThis.fetch = realFetch;
    delete process.env.S1_CONSOLE_URL;
    delete process.env.S1_CONSOLE_API_TOKEN;
  }
});

test('sdlFetch: a 403 is raised, not silently retried against another credential', async () => {
  process.env.S1_CONSOLE_URL = 'https://console.example.invalid';
  process.env.S1_CONSOLE_API_TOKEN = 'console-token';

  let calls = 0;
  const realFetch = globalThis.fetch;
  globalThis.fetch = async () => {
    calls += 1;
    return new Response(JSON.stringify({ message: 'forbidden' }), {
      status: 403, headers: { 'Content-Type': 'application/json' },
    });
  };

  try {
    const { v1Query } = await import('../lib/sdl.js');
    await assert.rejects(
      () => v1Query("dataSource.name=='x'", { maxCount: 1 }),
      /403/,
    );
    assert.equal(calls, 1, 'no credential fallthrough: one request, one failure');
  } finally {
    globalThis.fetch = realFetch;
    delete process.env.S1_CONSOLE_URL;
    delete process.env.S1_CONSOLE_API_TOKEN;
  }
});
