/**
 * toast.js — tiny toast notification system.
 *
 * Usage:
 *   import { toast } from './toast.js';
 *   toast('Saved', { type: 'success' });
 */

let stack;
function ensureStack() {
  if (stack) return stack;
  stack = document.createElement('div');
  stack.className = 'toast-stack';
  document.body.appendChild(stack);
  return stack;
}

const ICONS = { info: 'info', success: 'check-circle-2', error: 'alert-octagon', warning: 'alert-triangle' };

/**
 * Show a toast.
 * @param {string} message  – plain text content
 * @param {object} [opts]
 * @param {'info'|'success'|'error'|'warning'} [opts.type='info']
 * @param {number} [opts.duration=3200]  – auto-dismiss in ms
 */
export function toast(message, opts = {}) {
  const { type = 'info', duration = 3200 } = opts;
  const root = ensureStack();
  const el = document.createElement('div');
  el.className = `toast is-${type}`;
  el.innerHTML = `
    <i data-lucide="${ICONS[type] || 'info'}" aria-hidden="true"></i>
    <div class="toast-msg"></div>
  `;
  el.querySelector('.toast-msg').textContent = message;
  root.appendChild(el);

  if (window.lucide?.createIcons) window.lucide.createIcons({ nameAttr: 'data-lucide' });

  /* Trigger entry animation on the next frame */
  requestAnimationFrame(() => el.classList.add('is-show'));

  const close = () => {
    el.classList.remove('is-show');
    setTimeout(() => el.remove(), 250);
  };
  setTimeout(close, duration);
  el.addEventListener('click', close);
  return close;
}
