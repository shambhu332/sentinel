/**
 * charts.js — thin wrappers around Chart.js for the dashboard.
 * Requires Chart.js loaded via CDN (window.Chart).
 */

const PALETTE = {
  critical: '#EF4444',
  high:     '#F97316',
  medium:   '#FBBF24',
  low:      '#3B82F6',
  info:     '#6B7280',
};

const COMMON = {
  responsive: true,
  maintainAspectRatio: false,
  plugins: {
    legend: {
      labels: { color: '#9CA8C0', font: { family: 'Inter', size: 12 } },
      position: 'bottom',
    },
    tooltip: {
      backgroundColor: '#141B2E',
      borderColor: '#2A3454',
      borderWidth: 1,
      titleColor: '#E6EAF2',
      bodyColor: '#9CA8C0',
      titleFont: { family: 'Inter', size: 13, weight: '600' },
      bodyFont:  { family: 'JetBrains Mono', size: 12 },
      padding: 10,
      cornerRadius: 6,
    },
  },
};

/** Render a severity donut into a <canvas>. */
export function severityDonut(canvas, counts) {
  if (!window.Chart) return;
  return new window.Chart(canvas, {
    type: 'doughnut',
    data: {
      labels: ['Critical', 'High', 'Medium', 'Low', 'Info'],
      datasets: [{
        data: [counts.critical, counts.high, counts.medium, counts.low, counts.info],
        backgroundColor: [PALETTE.critical, PALETTE.high, PALETTE.medium, PALETTE.low, PALETTE.info],
        borderColor: '#0E1322',
        borderWidth: 2,
        hoverOffset: 6,
      }],
    },
    options: {
      ...COMMON,
      cutout: '62%',
    },
  });
}

/** Findings trend (last N days) — critical + high line chart. */
export function trendChart(canvas, series) {
  if (!window.Chart) return;
  return new window.Chart(canvas, {
    type: 'line',
    data: {
      labels: series.labels,
      datasets: [
        {
          label: 'Critical',
          data: series.critical,
          borderColor: PALETTE.critical,
          backgroundColor: 'rgba(239, 68, 68, 0.12)',
          borderWidth: 2,
          tension: 0.35,
          fill: true,
          pointRadius: 3,
          pointHoverRadius: 5,
        },
        {
          label: 'High',
          data: series.high,
          borderColor: PALETTE.high,
          backgroundColor: 'rgba(249, 115, 22, 0.12)',
          borderWidth: 2,
          tension: 0.35,
          fill: true,
          pointRadius: 3,
          pointHoverRadius: 5,
        },
      ],
    },
    options: {
      ...COMMON,
      scales: {
        x: {
          ticks: { color: '#5C6788', font: { family: 'JetBrains Mono', size: 10 } },
          grid:  { color: 'rgba(31, 41, 64, 0.4)' },
        },
        y: {
          beginAtZero: true,
          ticks: { color: '#5C6788', stepSize: 1, font: { family: 'JetBrains Mono', size: 10 } },
          grid:  { color: 'rgba(31, 41, 64, 0.4)' },
        },
      },
    },
  });
}

/** Tiny rate-limit bar (Settings · LLM providers). */
export function rateLimitBar(canvas, data) {
  if (!window.Chart) return;
  return new window.Chart(canvas, {
    type: 'bar',
    data: {
      labels: data.labels,
      datasets: [{
        data: data.values,
        backgroundColor: 'rgba(124, 58, 237, 0.6)',
        borderColor: 'transparent',
        borderRadius: 3,
        barThickness: 4,
      }],
    },
    options: {
      ...COMMON,
      plugins: { ...COMMON.plugins, legend: { display: false } },
      scales: {
        x: { display: false },
        y: { display: false, beginAtZero: true },
      },
    },
  });
}
