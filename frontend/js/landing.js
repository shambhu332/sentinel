// Landing page interactions
import { refreshIcons } from './utils.js';

document.addEventListener('DOMContentLoaded', () => {
  refreshIcons();

  // Smooth-scroll anchor links on the landing page
  document.querySelectorAll('a[href^="#"]').forEach(a => {
    if (a.getAttribute('href').length > 1 && !a.getAttribute('href').includes('://')) {
      a.addEventListener('click', (e) => {
        const id = a.getAttribute('href').slice(1);
        const target = document.getElementById(id);
        if (target) {
          e.preventDefault();
          target.scrollIntoView({ behavior: 'smooth', block: 'start' });
        }
      });
    }
  });
});
