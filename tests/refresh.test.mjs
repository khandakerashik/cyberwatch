import test from 'node:test';
import assert from 'node:assert/strict';
import { createFeedClient, RefreshError } from '../dist/refresh.js';

const BASE = 'https://example.github.io/cyberwatch/';
const TIME = '2026-10-23T12:00:00Z';
const envelope = (state = 'idle', id = null, error = null) => ({
  service: 'cyberwatch', apiVersion: 1, refreshIntervalSeconds: 1800,
  nextCheckAt: '2026-10-23T12:30:00Z', lastCheckedAt: TIME,
  refresh: { id, status: state, startedAt: state === 'idle' ? null : TIME,
    finishedAt: ['succeeded', 'partial', 'failed'].includes(state) ? TIME : null, error },
});
const json = (data, status = 200, headers = {}) => new Response(JSON.stringify(data), {
  status, headers: { 'content-type': 'application/json', ...headers },
});
const sequence = responses => {
  const calls = [];
  const fetchImpl = async (url, options) => {
    calls.push({ url, ...options });
    assert.ok(responses.length, `Unexpected request: ${url}`);
    const response = responses.shift();
    return typeof response === 'function' ? response(url, options) : response;
  };
  return { calls, fetchImpl };
};
const clientFor = (responses, options = {}) => {
  const transport = sequence(responses);
  return { ...transport, client: createFeedClient({ baseURL: BASE, fetchImpl: transport.fetchImpl, sleep: async () => {}, ...options }) };
};

test('a static Pages deployment reloads its snapshot without claiming a fresh collection', async () => {
  const snapshot = { schemaVersion: 1, generatedAt: TIME, lastCheckedAt: TIME, events: [], sources: [] };
  const { client, calls } = clientFor([new Response('<html>Not found</html>', { status: 404 }), json(snapshot)]);
  const discovery = await client.discover();
  assert.equal(discovery.supportsLive, false);
  assert.equal(client.mode, 'static');
  assert.equal(discovery.error.status, 404);
  assert.deepEqual(await client.snapshot(), snapshot);
  await assert.rejects(client.refresh(), error => error instanceof RefreshError && error.code === 'live_unavailable');
  assert.equal(calls[1].url, `${BASE}data/incidents.json`);
  assert.equal(calls[1].credentials, 'same-origin');
  assert.ok(calls.every(call => call.method === 'GET'));
});

test('manual refresh starts immediately, follows its exact job, then reads the new snapshot', async () => {
  const updated = { schemaVersion: 1, lastCheckedAt: '2026-10-23T12:01:00Z', events: [], sources: [] };
  const { client, calls } = clientFor([
    json(envelope()), json(envelope('running', 'job-one'), 202),
    json(envelope('running', 'job-one')), json(envelope('succeeded', 'job-one')), json(updated),
  ]);
  assert.equal((await client.discover()).supportsLive, true);
  const seen = [];
  const result = await client.refresh({ onStatus: state => seen.push(state.refresh.status) });
  assert.equal(result.refresh.status, 'succeeded');
  assert.deepEqual(seen, ['running', 'running', 'succeeded']);
  assert.equal(calls[1].method, 'POST');
  assert.equal(calls[1].url, `${BASE}api/refresh`);
  assert.equal(calls[1].body, '{}');
  assert.equal(calls[1].headers['X-CyberWatch-Request'], 'refresh');
  assert.ok(calls.slice(2, 4).every(call => new URL(call.url).searchParams.get('job') === 'job-one'));
  assert.deepEqual(await client.snapshot(), updated);
  assert.ok(calls.every(call => call.credentials === 'omit' && call.cache === 'no-store' && call.redirect === 'error'));
});

test('partial source failures remain a partial terminal result for the UI to explain', async () => {
  const { client } = clientFor([
    json(envelope()), json(envelope('running', 'partial-job'), 202), json(envelope('partial', 'partial-job')),
  ]);
  const result = await client.refresh();
  assert.equal(result.refresh.status, 'partial');
  assert.equal(client.status.refresh.status, 'partial');
});

test('a failed collection is not presented as a successful refresh', async () => {
  const failed = envelope('failed', 'failed-job', 'Collector exceeded the time limit; previous records retained.');
  const { client } = clientFor([json(envelope()), json(envelope('running', 'failed-job'), 202), json(failed)]);
  await assert.rejects(client.refresh(), error => error.code === 'collection_failed' &&
    error.details.refresh.id === 'failed-job' && /previous records retained/.test(error.message));
  assert.equal(client.status.refresh.status, 'failed');
});

test('cooldown reports Retry-After without issuing another job or polling', async () => {
  const { client, calls } = clientFor([
    json(envelope()), json({ ...envelope('succeeded', 'recent-job'), retryAfter: 17 }, 429, { 'retry-after': '17' }),
  ]);
  await assert.rejects(client.refresh(), error => error.code === 'cooldown' && error.status === 429 && error.retryAfter === 17);
  assert.equal(calls.length, 2);
});

test('a different job or an expired job cannot be mistaken for the requested collection', async () => {
  for (const [response, code] of [
    [json(envelope('succeeded', 'someone-elses-job')), 'job_mismatch'],
    [json({ error: 'Unknown collection' }, 404), 'http_error'],
  ]) {
    const { client } = clientFor([json(envelope()), json(envelope('running', 'our-job'), 202), response]);
    await assert.rejects(client.refresh(), error => error.code === code);
  }
});

test('requests have a deadline even when a broken fetch implementation ignores AbortSignal', async () => {
  const { client } = clientFor([json(envelope()), () => new Promise(() => {})], { requestTimeoutMs: 5 });
  await assert.rejects(client.refresh(), error => error.code === 'request_timeout');
});

test('cancelling a refresh stops client polling without falsely cancelling the server job', async () => {
  const { client, calls } = clientFor([json(envelope()), json(envelope('running', 'still-running'), 202)]);
  const controller = new AbortController();
  await assert.rejects(client.refresh({ signal: controller.signal, onStatus: () => controller.abort() }),
    error => error.code === 'aborted' && /server may still finish/.test(error.message));
  assert.equal(calls.length, 2);
  assert.equal(client.status.refresh.status, 'running');
});

test('the overall collection deadline bounds an otherwise healthy endless polling stream', async () => {
  let clock = 0;
  const { client, calls } = clientFor([
    json(envelope()), json(envelope('running', 'slow-job'), 202), json(envelope('running', 'slow-job')),
  ], { now: () => clock, sleep: async milliseconds => { clock += milliseconds; }, refreshTimeoutMs: 2000, pollIntervalMs: 1000 });
  await assert.rejects(client.refresh(), error => error.code === 'refresh_timeout');
  assert.equal(clock, 2000);
  assert.equal(calls.length, 3);
});

test('explicit backend configuration requires HTTPS except on loopback and cannot include credentials or URL payloads', async () => {
  for (const apiBase of ['http://feeds.example/', 'javascript:alert(1)', '//feeds.example/', '/api/',
    'https://user:secret@feeds.example/', 'https://feeds.example/?token=secret', 'https://feeds.example/#fragment',
    'https:\\feeds.example/', ' https://feeds.example/']) {
    assert.throws(() => createFeedClient({ baseURL: BASE, apiBase }), error => error.code === 'invalid_config', apiBase);
  }
  const { client, calls } = clientFor([json(envelope())], { apiBase: 'https://feeds.example/cyberwatch' });
  await client.discover();
  assert.equal(calls[0].url, 'https://feeds.example/cyberwatch/api/status');
  for (const apiBase of ['http://localhost:8000/', 'http://127.0.0.1:8000/', 'http://[::1]:8000/']) {
    assert.doesNotThrow(() => createFeedClient({ baseURL: BASE, apiBase }));
  }
});

test('malformed or unrelated JSON status cannot enable live mode', async () => {
  for (const bad of [{ ...envelope(), service: 'other' }, { ...envelope(), apiVersion: 2 },
    { ...envelope(), refresh: { ...envelope().refresh, status: 'finished' } }, { ...envelope(), lastCheckedAt: 'yesterday' }]) {
    const { client } = clientFor([json(bad)]);
    const found = await client.discover();
    assert.equal(found.mode, 'static');
    assert.equal(found.error.code, 'invalid_response');
  }
});

test('bounded payload reads reject oversized control and snapshot responses', async () => {
  const { client } = clientFor([
    new Response(' '.repeat(64 * 1024 + 1)),
    new Response('{}', { headers: { 'content-length': String(8 * 1024 * 1024 + 1) } }),
  ]);
  const found = await client.discover();
  assert.equal(found.error.code, 'response_too_large');
  await assert.rejects(client.snapshot(), error => error.code === 'response_too_large');
});

test('discovery can be retried after a static or unavailable backend becomes live', async () => {
  const { client } = clientFor([new Response('Not found', { status: 404 }), json(envelope())]);
  assert.equal((await client.discover()).mode, 'static');
  assert.equal((await client.discover()).mode, 'live');
  assert.equal(client.discoveryError, null);
});
