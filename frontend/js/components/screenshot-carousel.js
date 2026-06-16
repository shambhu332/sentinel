// Lazy-loaded screenshot carousel for finding evidence.
// Renders nothing when given an empty list (caller can null-check).
import { el, refreshIcons } from '../utils.js';

const IO_OPTS = { rootMargin: '200px 0px', threshold: 0.01 };

let _io = null;
function getObserver() {
  if (_io) return _io;
  if (typeof IntersectionObserver === 'undefined') return null;
  _io = new IntersectionObserver((entries, obs) => {
    entries.forEach((entry) => {
      if (!entry.isIntersecting) return;
      const img = entry.target;
      const src = img.dataset.src;
      if (src) {
        img.src = src;
        img.removeAttribute('data-src');
      }
      obs.unobserve(img);
    });
  }, IO_OPTS);
  return _io;
}

// `paths` are Finding-relative strings like "evidence/before_exploit_…png".
// `sessionId` is the scan session_id; the URL is built as
// `/reports/{sessionId}/{path}`.
export function screenshotCarousel(paths, sessionId, opts = {}) {
  const items = Array.isArray(paths) ? paths.filter(Boolean) : [];
  if (!items.length) return null;

  const { caption } = opts;
  const root = el('div', { class: 'screenshot-carousel' });
  if (caption) root.appendChild(el('div', { class: 'screenshot-caption' }, caption));

  const strip = el('div', { class: 'screenshot-strip', role: 'list' });
  const io = getObserver();
  items.forEach((rel, i) => {
    const url = `/reports/${encodeURIComponent(sessionId)}/${rel}`;
    const label = labelFor(rel, i);
    const fig = el('figure', { class: 'screenshot-item', role: 'listitem' });
    const img = el('img', {
      class: 'screenshot-img',
      alt: `Evidence screenshot ${i + 1}: ${label}`,
      loading: 'lazy',
      decoding: 'async',
    });
    if (io) {
      img.dataset.src = url;
      io.observe(img);
    } else {
      img.src = url;
    }
    img.addEventListener('click', () => openLightbox(url, label));
    img.addEventListener('error', () => {
      fig.classList.add('screenshot-missing');
      img.replaceWith(el('div', { class: 'screenshot-placeholder' },
        el('i', { 'data-lucide': 'image-off', 'aria-hidden': 'true' }),
        el('span', {}, 'Image unavailable'),
      ));
      refreshIcons();
    });
    fig.appendChild(img);
    fig.appendChild(el('figcaption', { class: 'screenshot-label' }, label));
    strip.appendChild(fig);
  });
  root.appendChild(strip);
  return root;
}

function labelFor(rel, i) {
  // "evidence/after_resume_1718537400123.png" -> "after resume"
  const base = rel.split('/').pop() || `step ${i + 1}`;
  const stem = base.replace(/\.(png|jpe?g|webp)$/i, '');
  const without_ts = stem.replace(/_\d{10,}$/, '');
  return without_ts.replace(/_/g, ' ');
}

function openLightbox(url, label) {
  const backdrop = el('div', {
    class: 'screenshot-lightbox',
    role: 'dialog',
    'aria-label': `Screenshot: ${label}`,
    tabindex: '-1',
  });
  const img = el('img', { src: url, alt: label, class: 'screenshot-lightbox-img' });
  const close = el('button', {
    class: 'screenshot-lightbox-close',
    'aria-label': 'Close screenshot',
  }, '×');
  const dismiss = () => backdrop.remove();
  close.addEventListener('click', dismiss);
  backdrop.addEventListener('click', (ev) => {
    if (ev.target === backdrop) dismiss();
  });
  document.addEventListener('keydown', function esc(e) {
    if (e.key === 'Escape') {
      dismiss();
      document.removeEventListener('keydown', esc);
    }
  });
  backdrop.appendChild(close);
  backdrop.appendChild(img);
  document.body.appendChild(backdrop);
  backdrop.focus();
}
