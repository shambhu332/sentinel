// SENTINEL frontend API client — talks to the FastAPI gateway.
//
// All scan/finding data the GUI shows comes through here. The base URL
// auto-detects: when the page is served from the gateway itself (port
// 8000) we use the same origin; otherwise we fall back to
// http://localhost:8000 so the static frontend works when opened via
// file:// or `python -m http.server`.

const DEFAULT_API = 'http://localhost:8000';

function inferBase() {
  try {
    const stored = localStorage.getItem('sentinel.apiBase');
    if (stored) return stored.replace(/\/+$/, '');
  } catch (_) { /* localStorage unavailable */ }
  const origin = window.location.origin;
  if (!origin || origin === 'null' || origin.startsWith('file://')) {
    return DEFAULT_API;
  }
  // If the gateway is serving us (typically port 8000), use the same origin.
  // If we are served from another port (e.g. 8765 via python -m http.server), fallback to DEFAULT_API.
  if (window.location.port === '8000') {
    return origin.replace(/\/+$/, '');
  }
  return DEFAULT_API;
}

export const API_BASE = inferBase();

export function setApiBase(url) {
  try { localStorage.setItem('sentinel.apiBase', url); } catch (_) {}
}

// Token retrieval — checks localStorage first, falls back to a global the
// host page can set (window.SENTINEL_TOKEN). Returning "" disables the
// Authorization header so the dev-bypass mode (SENTINEL_DEV_AUTH_BYPASS=1
// on the gateway) still works untouched.
function getAuthToken() {
  try {
    const t = localStorage.getItem('sentinel.token');
    if (t) return t;
  } catch (_) { /* no localStorage */ }
  if (typeof window !== 'undefined' && window.SENTINEL_TOKEN) {
    return String(window.SENTINEL_TOKEN);
  }
  return '';
}

export function setAuthToken(token) {
  try {
    if (token) localStorage.setItem('sentinel.token', token);
    else localStorage.removeItem('sentinel.token');
  } catch (_) {}
}

function applyAuth(headers) {
  const t = getAuthToken();
  if (t && !headers['Authorization']) {
    headers['Authorization'] = t.startsWith('Bearer ') ? t : `Bearer ${t}`;
  }
  return headers;
}

async function request(path, opts = {}) {
  const url = `${API_BASE}${path}`;
  const init = {
    method: opts.method || 'GET',
    headers: applyAuth({ ...(opts.headers || {}) }),
    body: opts.body,
    signal: opts.signal,
  };
  if (init.body && !(init.body instanceof FormData) && typeof init.body !== 'string') {
    init.body = JSON.stringify(init.body);
    init.headers['Content-Type'] = 'application/json';
  }
  let res;
  try {
    res = await fetch(url, init);
  } catch (e) {
    throw new ApiError(
      `Cannot reach SENTINEL API at ${API_BASE}. Is "poetry run sentinel serve" running?`,
      0, null,
    );
  }
  const text = await res.text();
  let body = null;
  if (text) {
    try { body = JSON.parse(text); } catch (_) { body = text; }
  }
  if (!res.ok) {
    const detail = (body && body.detail) || res.statusText || 'request failed';
    throw new ApiError(`${res.status} ${detail}`, res.status, body);
  }
  return body;
}

export class ApiError extends Error {
  constructor(message, status, body) {
    super(message);
    this.status = status;
    this.body = body;
  }
}

// ---------- Endpoints ----------

export const api = {
  health() { return request('/health'); },
  status() { return request('/status'); },
  listAgents()   { return request('/agents'); },
  listScans()    { return request('/scans'); },
  listDevices()  { return request('/devices'); },
  devicePreflight(serial) {
    return request(`/devices/${encodeURIComponent(serial)}/preflight`, { method: 'POST' });
  },
  disableVerifier(serial) {
    return request(`/devices/${encodeURIComponent(serial)}/disable-verifier`, { method: 'POST' });
  },
  setupFrida(serial) {
    return request(`/devices/${encodeURIComponent(serial)}/frida/setup`, { method: 'POST' });
  },
  fridaStatus(serial) {
    return request(`/devices/${encodeURIComponent(serial)}/frida/status`);
  },
  installOnDevice(serial, { files = [], replace = true, grantPermissions = true } = {}) {
    const form = new FormData();
    for (const file of files) form.append('apks', file, file.name);
    form.append('replace', replace ? 'true' : 'false');
    form.append('grant_permissions', grantPermissions ? 'true' : 'false');
    return request(`/devices/${encodeURIComponent(serial)}/install`, {
      method: 'POST',
      body: form,
    });
  },
  launchOnDevice(serial, { packageName, activity = '' }) {
    return request(`/devices/${encodeURIComponent(serial)}/launch`, {
      method: 'POST',
      body: { package: packageName, activity },
    });
  },
  packageStatus(serial, packageName) {
    return request(
      `/devices/${encodeURIComponent(serial)}/packages/${encodeURIComponent(packageName)}`,
    );
  },
  clearLogcat(serial) {
    return request(`/devices/${encodeURIComponent(serial)}/logcat/clear`, { method: 'POST' });
  },
  readLogcat(serial, { lines = 250 } = {}) {
    return request(`/devices/${encodeURIComponent(serial)}/logcat?lines=${encodeURIComponent(lines)}`);
  },
  adbConnect(address) {
    return request('/devices/connect', { method: 'POST', body: { address } });
  },
  injectTap(serial, x, y) {
    return request(`/devices/${encodeURIComponent(serial)}/tap`, {
      method: 'POST', body: { x, y },
    });
  },
  // Open a WebSocket screen mirror session.
  // Returns a handle: { stop(), onFrame(cb), onError(cb) }
  mirrorScreen(serial, { onFrame, onStatus } = {}) {
    const wsBase = API_BASE.replace(/^http/, 'ws');
    const url    = `${wsBase}/devices/${encodeURIComponent(serial)}/mirror`;
    let ws       = null;
    let active   = true;

    function connect() {
      ws = new WebSocket(url);
      ws.onopen  = () => onStatus?.('connected');
      ws.onerror = () => onStatus?.('error');
      ws.onclose = () => { if (active) onStatus?.('disconnected'); };
      ws.onmessage = (e) => {
        try {
          const msg = JSON.parse(e.data);
          if (msg.type === 'frame') onFrame?.(msg.data, msg.fps);
          else if (msg.type === 'error') onStatus?.('error: ' + msg.message);
        } catch (_) {}
      };
    }

    connect();
    return {
      stop() {
        active = false;
        try { ws?.send(JSON.stringify({ type: 'stop' })); } catch (_) {}
        ws?.close();
      },
      sendTap(x, y) {
        try { ws?.send(JSON.stringify({ type: 'tap', x, y })); } catch (_) {}
      },
    };
  },
  getScan(id)    { return request(`/scans/${id}`); },
  getFindings(id){ return request(`/scans/${id}/findings`); },
  getResult(id)  { return request(`/scans/${id}/result`); },
  deleteScan(id) { return request(`/scans/${id}`, { method: 'DELETE' }); },
  listReports()  { return request('/reports'); },
  regenerateReport(id) { return request(`/reports/${encodeURIComponent(id)}/regenerate`, { method: 'POST' }); },
  reportUrl(sessionId, fmt) {
    // Absolute URL the browser can hit directly — the API streams the
    // bytes back as a FileResponse, so this works for ``download``
    // links and ``<a target=_blank>`` opens alike.
    return `${API_BASE}/reports/${encodeURIComponent(sessionId)}/${encodeURIComponent(fmt)}`;
  },

  // Open an SSE stream for real-time scan progress.
  // Uses fetch (not EventSource) so the Authorization header is sent.
  // Returns a handle with a .close() method.
  //
  // Callbacks:
  //   onState(ev)  — called on every state snapshot (phase/severity updates)
  //   onDone(ev)   — called once when the scan reaches a terminal state
  //   onError(err) — called on connection failure (caller should fall back to poll)
  scanEvents(sessionId, { onState, onDone, onError } = {}) {
    const url = `${API_BASE}/scans/${encodeURIComponent(sessionId)}/events`;
    const controller = new AbortController();
    const headers = applyAuth({ Accept: 'text/event-stream', 'Cache-Control': 'no-cache' });
    let active = true;

    (async () => {
      try {
        const res = await fetch(url, { headers, signal: controller.signal });
        if (!res.ok) {
          onError?.(new ApiError(`SSE ${res.status}`, res.status, null));
          return;
        }
        const reader = res.body.getReader();
        const dec = new TextDecoder();
        let buf = '';
        while (active) {
          const { done, value } = await reader.read();
          if (done) break;
          buf += dec.decode(value, { stream: true });
          const parts = buf.split('\n');
          buf = parts.pop(); // keep the last incomplete line in the buffer
          for (const line of parts) {
            if (!line.startsWith('data: ')) continue;
            try {
              const ev = JSON.parse(line.slice(6));
              if (ev.type === 'state') onState?.(ev);
              else if (ev.type === 'done') { onDone?.(ev); active = false; }
              else if (ev.type === 'error') onError?.(new ApiError(ev.detail || 'SSE error', 0, ev));
            } catch (_) { /* skip malformed lines */ }
          }
        }
      } catch (err) {
        if (err.name !== 'AbortError') onError?.(err);
      }
    })();

    return { close() { active = false; controller.abort(); } };
  },

  async createScan({ file, options = {}, onProgress }) {
    const form = new FormData();
    form.append('apk', file, file.name);
    form.append('options', JSON.stringify(options));

    // Use XHR so we get an upload progress callback (fetch doesn't).
    return await new Promise((resolve, reject) => {
      const xhr = new XMLHttpRequest();
      xhr.open('POST', `${API_BASE}/scans`);
      const token = getAuthToken();
      if (token) {
        xhr.setRequestHeader(
          'Authorization',
          token.startsWith('Bearer ') ? token : `Bearer ${token}`,
        );
      }
      if (onProgress) {
        xhr.upload.addEventListener('progress', (e) => {
          if (e.lengthComputable) onProgress(e.loaded, e.total);
        });
      }
      xhr.onload = () => {
        let body = null;
        try { body = JSON.parse(xhr.responseText); } catch (_) { body = xhr.responseText; }
        if (xhr.status >= 200 && xhr.status < 300) {
          resolve(body);
        } else {
          const msg = (body && body.detail) || xhr.statusText || 'upload failed';
          reject(new ApiError(`${xhr.status} ${msg}`, xhr.status, body));
        }
      };
      xhr.onerror = () => reject(new ApiError(
        `Cannot reach SENTINEL API at ${API_BASE}`, 0, null,
      ));
      xhr.send(form);
    });
  },
};

// Poll a scan until it reaches a terminal state.
// onUpdate(summary) is called every tick.
// Returns the final summary.
export async function pollScan(sessionId, { intervalMs = 1500, onUpdate } = {}) {
  while (true) {
    const summary = await api.getScan(sessionId);
    if (onUpdate) onUpdate(summary);
    if (['completed', 'failed', 'cancelled'].includes(summary.status)) {
      return summary;
    }
    await new Promise(r => setTimeout(r, intervalMs));
  }
}
