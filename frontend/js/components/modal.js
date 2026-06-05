// Modal component — open/close, click outside, ESC handling
import { el, refreshIcons } from '../utils.js';

let activeModal = null;

export function openModal({ title, body, footer, size = '', onClose }) {
  closeModal();

  const closeBtn = el('button', { class: 'btn-icon', 'aria-label': 'Close' }, el('i', { 'data-lucide': 'x' }));
  closeBtn.addEventListener('click', closeModal);

  const modal = el('div', { class: `modal ${size ? 'modal-' + size : ''}` },
    el('div', { class: 'modal-header' },
      el('div', { class: 'modal-title' }, title),
      closeBtn,
    ),
    el('div', { class: 'modal-body' }, body),
    footer ? el('div', { class: 'modal-footer' }, footer) : null,
  );

  const overlay = el('div', { class: 'modal-overlay' }, modal);
  overlay.addEventListener('click', (e) => {
    if (e.target === overlay) closeModal();
  });

  document.body.appendChild(overlay);
  // Force reflow then animate
  requestAnimationFrame(() => overlay.classList.add('active'));

  activeModal = { overlay, onClose };
  document.addEventListener('keydown', escClose);
  document.body.style.overflow = 'hidden';

  refreshIcons();
  return overlay;
}

export function closeModal() {
  if (!activeModal) return;
  const { overlay, onClose } = activeModal;
  overlay.classList.remove('active');
  setTimeout(() => {
    overlay.remove();
    if (typeof onClose === 'function') onClose();
  }, 160);
  activeModal = null;
  document.removeEventListener('keydown', escClose);
  document.body.style.overflow = '';
}

function escClose(e) {
  if (e.key === 'Escape') closeModal();
}
