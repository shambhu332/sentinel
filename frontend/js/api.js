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

async function request(path, opts = {}) {
  const url = `${API_BASE}${path}`;
  const init = {
    method: opts.method || 'GET',
    headers: opts.headers || {},
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
  getScan(id)    { return request(`/scans/${id}`); },
  getFindings(id){ return request(`/scans/${id}/findings`); },
  getResult(id)  { return request(`/scans/${id}/result`); },
  deleteScan(id) { return request(`/scans/${id}`, { method: 'DELETE' }); },

  async createScan({ file, options = {}, onProgress }) {
    const form = new FormData();
    form.append('apk', file, file.name);
    form.append('options', JSON.stringify(options));

    // Use XHR so we get an upload progress callback (fetch doesn't).
    return await new Promise((resolve, reject) => {
      const xhr = new XMLHttpRequest();
      xhr.open('POST', `${API_BASE}/scans`);
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
