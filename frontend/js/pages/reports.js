// Reports page
import { el, refreshIcons, formatDate, timeAgo } from '../utils.js';
import { SCANS } from '../data/scans.js';

export function renderReportsPage(main) {
  main.appendChild(el('div', { class: 'page-header' },
    el('div', {},
      el('div', { class: 'page-title' }, 'Reports'),
      el('div', { class: 'page-subtitle' }, 'Exported PDF / JSON reports across your scans'),
    ),
    el('div', { class: 'page-actions' },
      el('button', { class: 'btn btn-secondary' },
        el('i', { 'data-lucide': 'plus' }), 'New report'),
    ),
  ));

  const wrap = el('div', { class: 'table-wrap' });
  const table = el('table', { class: 'table' });
  table.appendChild(el('thead', {}, el('tr', {},
    el('th', {}, 'Report'),
    el('th', {}, 'Source scan'),
    el('th', {}, 'Format'),
    el('th', {}, 'Size'),
    el('th', {}, 'Generated'),
    el('th', { style: 'width: 50px;' }, ''),
  )));
  const tbody = el('tbody');

  SCANS.slice(0, 12).forEach((scan, i) => {
    const fmt = i % 3 === 0 ? 'JSON' : i % 3 === 1 ? 'PDF' : 'HTML';
    const sizes = ['18 KB', '64 KB', '128 KB', '512 KB', '2.1 MB', '4.8 MB'];
    const tr = el('tr', { class: 'clickable' },
      el('td', {}, el('span', { class: 'mono', style: 'color: var(--accent-primary);' }, `report-${scan.id}.${fmt.toLowerCase()}`)),
      el('td', {}, el('span', {}, scan.appName), ' ', el('span', { class: 'mono text-muted', style: 'font-size: 11px;' }, scan.id)),
      el('td', {}, el('span', { class: 'badge accent badge-sm' }, fmt)),
      el('td', {}, el('span', { class: 'text-muted' }, sizes[i % sizes.length])),
      el('td', {}, el('span', { class: 'text-muted', style: 'font-size: 12px;' }, timeAgo(scan.startedAt))),
      el('td', {}, el('button', { class: 'btn-icon' }, el('i', { 'data-lucide': 'download' }))),
    );
    tbody.appendChild(tr);
  });
  table.appendChild(tbody);
  wrap.appendChild(table);
  main.appendChild(wrap);
  refreshIcons();
}
