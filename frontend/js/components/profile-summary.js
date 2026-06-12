// App-profile summary card — sits at the top of scan-detail.
// Sources from the META_005 ProfilerAgent finding (evidence carries
// frameworks, native_libs, obfuscation, api_types).
import { el } from '../utils.js';

export function renderProfileSummary(findings) {
  if (!findings || !findings.length) return null;
  // Find the META_005 INFO finding (one per scan).
  const profile = findings.find(f =>
    f.agentId === 'META_005' && f.evidence && f.evidence.frameworks !== undefined
  );
  if (!profile) return null;
  const ev = profile.evidence || {};

  const card = el('section', { class: 'profile-card' },
    el('div', { class: 'profile-card-head' },
      el('h3', {}, el('i', { 'data-lucide': 'cpu' }), ' App Profile'),
      el('span', { class: 'text-muted', style: 'font-size:12px;' },
        ev.summary || 'Phase 1.5 fingerprint'),
    ),
    el('div', { class: 'profile-card-grid' },
      _block('Frameworks',
        formatList(ev.frameworks, 'Pure Android / Java')),
      _block('Native libs',
        ev.native_libs && ev.native_libs.count
          ? `${ev.native_libs.count} (${formatSize(ev.native_libs.total_size_bytes)})`
          : 'none'),
      _block('ABIs',
        formatList(ev.native_libs && ev.native_libs.abis, '—')),
      _block('Obfuscation',
        ev.obfuscation && ev.obfuscation.tier || 'unknown'),
      _block('API types',
        formatList(ev.api_types, 'standard REST/HTTP')),
      _block('Agents skipped',
        ev.agents_skipped != null
          ? `${ev.agents_skipped} of catalog`
          : 'none'),
    ),
  );
  return card;
}

function _block(label, value) {
  return el('div', { class: 'profile-block' },
    el('div', { class: 'profile-label' }, label),
    el('div', { class: 'profile-value' }, value),
  );
}

function formatList(arr, fallback) {
  if (!arr || !arr.length) return fallback;
  return Array.isArray(arr) ? arr.join(' · ') : String(arr);
}

function formatSize(bytes) {
  if (!bytes) return '0';
  const mb = bytes / (1024 * 1024);
  if (mb >= 1) return `${mb.toFixed(1)} MB`;
  return `${(bytes / 1024).toFixed(0)} KB`;
}
