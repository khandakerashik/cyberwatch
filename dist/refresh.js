/* Public-feed transport. Collection happens on the server, never by changing
 * timestamps in the browser. GitHub Pages alone remains an explicit static mode. */

const CONTROL_LIMIT = 64 * 1024;
const SNAPSHOT_LIMIT = 8 * 1024 * 1024;
const JOB_STATES = new Set(['idle', 'running', 'succeeded', 'partial', 'failed']);

export class RefreshError extends Error {
  constructor(message, { code = 'request_failed', status = null, retryAfter = null, details = null, cause } = {}) {
    super(message);
    this.name = 'RefreshError';
    this.code = code;
    this.status = status;
    this.retryAfter = retryAfter;
    this.details = details;
    if (cause !== undefined) this.cause = cause;
  }
}

function cancelled() {
  return new RefreshError('The request was cancelled. The server may still finish its collection.', { code: 'aborted' });
}

function backendBase(value, { allowSameOriginHTTP = false } = {}) {
  const raw = value instanceof URL ? value.href : value;
  if (typeof raw !== 'string' || !raw || raw.length > 2000 || /[\u0000-\u0020\u007f\\]/.test(raw)) {
    throw new RefreshError('The live refresh service URL is invalid.', { code: 'invalid_config' });
  }
  let url;
  try { url = new URL(raw); } catch {
    throw new RefreshError('The live refresh service must use an absolute URL.', { code: 'invalid_config' });
  }
  const loopback = url.hostname === 'localhost' || url.hostname === '[::1]' || /^127(?:\.\d{1,3}){3}$/.test(url.hostname);
  if (url.username || url.password || url.search || url.hash ||
      !(url.protocol === 'https:' || (url.protocol === 'http:' && (loopback || allowSameOriginHTTP)))) {
    throw new RefreshError('Use HTTPS for the live refresh service, without credentials, a query, or a fragment.', { code: 'invalid_config' });
  }
  if (!url.pathname.endsWith('/')) url.pathname += '/';
  return url;
}

function validTimestamp(value) {
  return value === null || (typeof value === 'string' && value.length <= 50 && Number.isFinite(Date.parse(value)));
}

function checkedStatus(value, expectedJob = null) {
  const job = value?.refresh;
  if (!value || typeof value !== 'object' || value.service !== 'cyberwatch' || value.apiVersion !== 1 ||
      !Number.isInteger(value.refreshIntervalSeconds) || value.refreshIntervalSeconds <= 0 ||
      !validTimestamp(value.nextCheckAt) || !validTimestamp(value.lastCheckedAt) ||
      !job || typeof job !== 'object' || !JOB_STATES.has(job.status) ||
      !validTimestamp(job.startedAt) || !validTimestamp(job.finishedAt) ||
      !(job.error === null || typeof job.error === 'string') ||
      !(job.status === 'idle' && job.id === null || typeof job.id === 'string' && /^[A-Za-z0-9_-]{1,180}$/.test(job.id))) {
    throw new RefreshError('The server returned an unsupported refresh status.', { code: 'invalid_response' });
  }
  if (expectedJob !== null && job.id !== expectedJob) {
    throw new RefreshError('The refresh response belongs to a different collection. Reload the feed and try again.', {
      code: 'job_mismatch', details: value,
    });
  }
  return value;
}

async function boundedText(response, maximum) {
  const declared = Number(response.headers?.get('content-length'));
  if (Number.isFinite(declared) && declared > maximum) {
    await response.body?.cancel?.();
    throw new RefreshError('The server response exceeds the supported size.', { code: 'response_too_large', status: response.status });
  }
  if (!response.body?.getReader) {
    const text = await response.text();
    if (new TextEncoder().encode(text).byteLength > maximum) {
      throw new RefreshError('The server response exceeds the supported size.', { code: 'response_too_large', status: response.status });
    }
    return text;
  }
  const reader = response.body.getReader();
  const decoder = new TextDecoder();
  let size = 0, text = '';
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      size += value.byteLength;
      if (size > maximum) {
        await reader.cancel();
        throw new RefreshError('The server response exceeds the supported size.', { code: 'response_too_large', status: response.status });
      }
      text += decoder.decode(value, { stream: true });
    }
    return text + decoder.decode();
  } finally { reader.releaseLock(); }
}

function pause(milliseconds, signal) {
  if (signal?.aborted) return Promise.reject(cancelled());
  return new Promise((resolve, reject) => {
    const onAbort = () => { clearTimeout(timer); signal.removeEventListener('abort', onAbort); reject(cancelled()); };
    const timer = setTimeout(() => { signal?.removeEventListener('abort', onAbort); resolve(); }, milliseconds);
    signal?.addEventListener('abort', onAbort, { once: true });
  });
}

/**
 * apiBase is the application's backend base, e.g. https://feeds.example/.
 * The API paths are appended below it. `auto` uses this app's own directory.
 * Pass config.apiBase from config.json; this module never reads browser secrets.
 */
export function createFeedClient({
  baseURL = new URL('./', import.meta.url), apiBase = 'auto', fetchImpl = globalThis.fetch,
  requestTimeoutMs = 15000, refreshTimeoutMs = 180000, pollIntervalMs = 1000,
  sleep = pause, now = Date.now,
} = {}) {
  const appBase = backendBase(baseURL, { allowSameOriginHTTP: true });
  const serviceBase = apiBase === 'auto' ? appBase : backendBase(apiBase);
  const apiURL = path => new URL(`api/${path}`, serviceBase);
  const staticSnapshotURL = new URL('data/incidents.json', appBase);
  let mode = 'unknown', latestStatus = null, discoveryError = null;

  async function requestJSON(url, { signal, method = 'GET', maximum = CONTROL_LIMIT,
    timeoutMs = requestTimeoutMs, credentials = 'omit' } = {}) {
    if (signal?.aborted) throw cancelled();
    const controller = new AbortController();
    let timedOut = false;
    const onAbort = () => controller.abort();
    signal?.addEventListener('abort', onAbort, { once: true });
    const timer = setTimeout(() => { timedOut = true; controller.abort(); }, Math.max(1, timeoutMs));
    const interrupted = new Promise((_, reject) => {
      controller.signal.addEventListener('abort', () => reject(timedOut
        ? new RefreshError('The refresh service request timed out.', { code: 'request_timeout' })
        : cancelled()), { once: true });
    });
    try {
      const response = await Promise.race([fetchImpl(url.href, {
        method, cache: 'no-store', credentials, redirect: 'error', signal: controller.signal,
        headers: method === 'POST'
          ? { Accept: 'application/json', 'Content-Type': 'application/json', 'X-CyberWatch-Request': 'refresh' }
          : { Accept: 'application/json' },
        ...(method === 'POST' ? { body: '{}' } : {}),
      }), interrupted]);
      const raw = await Promise.race([boundedText(response, maximum), interrupted]);
      let data;
      try { data = JSON.parse(raw); } catch {
        throw new RefreshError('The refresh service did not return JSON.', { code: 'invalid_response', status: response.status });
      }
      if (response.status === 429) {
        const seconds = Number(data?.retryAfter ?? response.headers?.get('retry-after'));
        const retryAfter = Number.isFinite(seconds) && seconds >= 0 ? Math.min(Math.ceil(seconds), 3600) : 60;
        throw new RefreshError(`The feeds were just checked. Try again in ${retryAfter} seconds.`, {
          code: 'cooldown', status: 429, retryAfter, details: data,
        });
      }
      if (!response.ok) {
        throw new RefreshError(`The refresh service returned HTTP ${response.status}.`, {
          code: 'http_error', status: response.status, details: data,
        });
      }
      return data;
    } catch (error) {
      if (controller.signal.aborted) {
        if (timedOut) throw new RefreshError('The refresh service request timed out.', { code: 'request_timeout', cause: error });
        throw cancelled();
      }
      if (error instanceof RefreshError) throw error;
      throw new RefreshError('Could not reach the feed service. The previously loaded data is still available.', {
        code: 'network_error', cause: error,
      });
    } finally {
      clearTimeout(timer);
      signal?.removeEventListener('abort', onAbort);
    }
  }

  async function discover({ signal } = {}) {
    try {
      latestStatus = checkedStatus(await requestJSON(apiURL('status'), { signal }));
      mode = 'live'; discoveryError = null;
    } catch (error) {
      if (error.code === 'aborted') throw error;
      mode = 'static'; latestStatus = null; discoveryError = error;
    }
    return { supportsLive: mode === 'live', mode, status: latestStatus, error: discoveryError };
  }

  async function snapshot({ signal } = {}) {
    if (mode === 'unknown') await discover({ signal });
    return requestJSON(mode === 'live' ? apiURL('snapshot') : staticSnapshotURL, {
      signal, maximum: SNAPSHOT_LIMIT, credentials: mode === 'live' ? 'omit' : 'same-origin',
    });
  }

  async function refresh({ signal, onStatus = () => {} } = {}) {
    if (mode === 'unknown') await discover({ signal });
    if (mode !== 'live') {
      throw new RefreshError('Live collection is unavailable on this deployment. Reload the published snapshot or connect the refresh service.', {
        code: 'live_unavailable', details: discoveryError,
      });
    }
    const deadline = now() + refreshTimeoutMs;
    const remaining = () => {
      if (signal?.aborted) throw cancelled();
      const left = deadline - now();
      if (left <= 0) throw new RefreshError('The collection is taking longer than expected. It may continue on the server; reload the feed shortly.', {
        code: 'refresh_timeout', details: latestStatus,
      });
      return left;
    };
    latestStatus = checkedStatus(await requestJSON(apiURL('refresh'), {
      signal, method: 'POST', timeoutMs: Math.min(requestTimeoutMs, remaining()),
    }));
    const jobId = latestStatus.refresh.id;
    if (!jobId || latestStatus.refresh.status === 'idle') {
      throw new RefreshError('The service did not start a collection.', { code: 'invalid_response', details: latestStatus });
    }
    onStatus(latestStatus);
    while (latestStatus.refresh.status === 'running') {
      await sleep(Math.min(pollIntervalMs, remaining()), signal);
      const statusURL = apiURL('status');
      statusURL.searchParams.set('job', jobId);
      latestStatus = checkedStatus(await requestJSON(statusURL, {
        signal, timeoutMs: Math.min(requestTimeoutMs, remaining()),
      }), jobId);
      onStatus(latestStatus);
    }
    if (latestStatus.refresh.status === 'failed') {
      throw new RefreshError(latestStatus.refresh.error || 'The collection failed. The last available snapshot was retained.', {
        code: 'collection_failed', details: latestStatus,
      });
    }
    if (!['succeeded', 'partial'].includes(latestStatus.refresh.status)) {
      throw new RefreshError('The collection ended with an unsupported status.', { code: 'invalid_response', details: latestStatus });
    }
    return latestStatus;
  }

  return {
    discover, snapshot, refresh,
    get mode() { return mode; },
    get supportsLive() { return mode === 'live'; },
    get status() { return latestStatus; },
    get discoveryError() { return discoveryError; },
  };
}
