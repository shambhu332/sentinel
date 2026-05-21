/**
 * grid-bg.js — animated dot-grid background canvas.
 *
 * Mounts a single fixed <canvas id="grid-bg"> behind all page content
 * and renders a slowly drifting dot grid (40px spacing, ~4% opacity).
 * Falls back to a static grid when prefers-reduced-motion is on.
 *
 * Auto-mounts on DOMContentLoaded — just include via:
 *   <script type="module" src="./js/grid-bg.js"></script>
 */

const GRID_SPACING = 40;
const DOT_RADIUS   = 1.0;
const DOT_COLOR    = 'rgba(156, 168, 192, 0.10)';   /* matches --text-dim @ 10% */
const DRIFT_SPEED  = 0.06;   /* px / frame */

function mountCanvas() {
  let canvas = document.getElementById('grid-bg');
  if (!canvas) {
    canvas = document.createElement('canvas');
    canvas.id = 'grid-bg';
    document.body.prepend(canvas);
  }
  return canvas;
}

function start() {
  const canvas = mountCanvas();
  const ctx = canvas.getContext('2d', { alpha: true });
  const dpr = Math.max(1, window.devicePixelRatio || 1);
  const reduced = matchMedia('(prefers-reduced-motion: reduce)').matches;

  let w = 0, h = 0;
  let offset = 0;

  function resize() {
    w = canvas.clientWidth = window.innerWidth;
    h = canvas.clientHeight = window.innerHeight;
    canvas.width  = Math.floor(w * dpr);
    canvas.height = Math.floor(h * dpr);
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    draw();
  }

  function draw() {
    ctx.clearRect(0, 0, w, h);
    ctx.fillStyle = DOT_COLOR;

    /* Use offset modulo spacing so dots wrap seamlessly when drifting. */
    const off = ((offset % GRID_SPACING) + GRID_SPACING) % GRID_SPACING;

    for (let x = -GRID_SPACING + off; x < w + GRID_SPACING; x += GRID_SPACING) {
      for (let y = -GRID_SPACING + off; y < h + GRID_SPACING; y += GRID_SPACING) {
        ctx.beginPath();
        ctx.arc(x, y, DOT_RADIUS, 0, Math.PI * 2);
        ctx.fill();
      }
    }
  }

  function tick() {
    offset += DRIFT_SPEED;
    draw();
    if (!reduced) requestAnimationFrame(tick);
  }

  window.addEventListener('resize', resize, { passive: true });
  resize();
  if (!reduced) requestAnimationFrame(tick);
}

if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', start);
} else {
  start();
}
