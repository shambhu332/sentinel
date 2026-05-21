/**
 * modal.js — generic modal + slide-over sheet handler.
 *
 * Usage:
 *   const m = openModal({ title: 'Hi', body: '<p>…</p>', footer: '<button>X</button>' });
 *   m.close();
 *
 *   const s = openSheet({ title: 'Scan detail', body: '…' });
 *
 * Both honour Escape to close, click-outside to close, focus trap-lite,
 * and re-init Lucide icons after mount.
 */

function relucide() {
  if (window.lucide?.createIcons) window.lucide.createIcons({ nameAttr: 'data-lucide' });
}

function focusFirst(root) {
  const el = root.querySelector('button, [href], input, select, textarea, [tabindex]:not([tabindex="-1"])');
  if (el) el.focus();
}

/** Create a centred modal. Returns { el, close }. */
export function openModal({ title = '', body = '', footer = '', width = 640, onClose, className = '' } = {}) {
  const backdrop = document.createElement('div');
  backdrop.className = 'modal-backdrop';
  backdrop.innerHTML = `
    <div class="modal ${className}" role="dialog" aria-modal="true" aria-label="${title}" style="max-width:${width}px;">
      <header class="modal-header">
        <h3 class="modal-title">${title}</h3>
        <button class="btn-icon" aria-label="Close"><i data-lucide="x"></i></button>
      </header>
      <div class="modal-body">${body}</div>
      ${footer ? `<footer class="modal-footer">${footer}</footer>` : ''}
    </div>
  `;
  document.body.appendChild(backdrop);
  relucide();
  requestAnimationFrame(() => backdrop.classList.add('is-open'));
  focusFirst(backdrop);

  const close = () => {
    backdrop.classList.remove('is-open');
    setTimeout(() => {
      backdrop.remove();
      document.removeEventListener('keydown', onKey);
      onClose?.();
    }, 220);
  };
  const onKey = (e) => { if (e.key === 'Escape') close(); };
  document.addEventListener('keydown', onKey);
  backdrop.addEventListener('click', (e) => {
    if (e.target === backdrop) close();
  });
  backdrop.querySelector('.btn-icon[aria-label="Close"]').addEventListener('click', close);

  return { el: backdrop, close };
}

/** Create a right-anchored slide-over sheet. Returns { el, close, setBody }. */
export function openSheet({ title = '', subtitle = '', body = '', actions = '', onClose, width = 720 } = {}) {
  const backdrop = document.createElement('div');
  backdrop.className = 'sheet-backdrop';
  document.body.appendChild(backdrop);

  const sheet = document.createElement('aside');
  sheet.className = 'sheet';
  sheet.style.maxWidth = `${width}px`;
  sheet.innerHTML = `
    <header class="sheet-header">
      <div>
        <h3 style="font-size: var(--fs-md);">${title}</h3>
        ${subtitle ? `<div class="text-sm text-dim">${subtitle}</div>` : ''}
      </div>
      <div class="row-sm">
        ${actions}
        <button class="btn-icon" aria-label="Close sheet"><i data-lucide="x"></i></button>
      </div>
    </header>
    <div class="sheet-body">${body}</div>
  `;
  document.body.appendChild(sheet);
  relucide();
  requestAnimationFrame(() => {
    backdrop.classList.add('is-open');
    sheet.classList.add('is-open');
  });
  focusFirst(sheet);

  const close = () => {
    sheet.classList.remove('is-open');
    backdrop.classList.remove('is-open');
    setTimeout(() => {
      sheet.remove();
      backdrop.remove();
      document.removeEventListener('keydown', onKey);
      onClose?.();
    }, 280);
  };
  const onKey = (e) => { if (e.key === 'Escape') close(); };
  document.addEventListener('keydown', onKey);
  backdrop.addEventListener('click', close);
  sheet.querySelector('.btn-icon[aria-label="Close sheet"]').addEventListener('click', close);

  const setBody = (html) => {
    sheet.querySelector('.sheet-body').innerHTML = html;
    relucide();
  };

  return { el: sheet, close, setBody };
}
