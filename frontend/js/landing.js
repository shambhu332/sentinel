/**
 * landing.js — landing-page interactions:
 *   · Sticky navbar blur on scroll
 *   · Hero terminal typewriter (cycles 3 sample commands)
 *   · IntersectionObserver reveals for sections
 *   · Stats row count-up easing
 *   · Agent showcase tab filter
 *   · DynamicAnalysis section tabs
 */

import { AGENTS, groupedAgents } from './data/agents.js';
import { severityDot } from './components/severity-chip.js';

const COMMANDS = [
  {
    cmd: 'poetry run sentinel scan corpus/campus.apk --dynamic --frida',
    out: [
      { c: 'info', t: '[phase=0] hash=sha256:0d4e3a… size=28.4MB' },
      { c: 'info', t: '[phase=1] JADX + Androguard + apktool · async' },
      { c: 'ok',   t: '[phase=2] 20 agents complete · 12 findings' },
      { c: 'warn', t: '[phase=3] groq 429 · falling through to cerebras' },
      { c: 'ok',   t: '[phase=4.5] N_005 X509TrustManager bypass_success' },
      { c: 'ok',   t: '✓ scan complete · 6 verified · 4 filtered · 2 uncertain' },
    ],
  },
  {
    cmd: 'poetry run sentinel scope parse --url hackerone.com/programs/twitter',
    out: [
      { c: 'info', t: 'fetching scope · com.twitter.android · 12 in-scope domains' },
      { c: 'ok',   t: 'parsed 4 reward tiers · 3 forbidden techniques' },
      { c: 'ok',   t: 'scope written to .sentinel/scope/twitter.json' },
    ],
  },
  {
    cmd: 'poetry run sentinel agents --category network',
    out: [
      { c: 'info', t: 'N_001 MissingCertPinning  · High'   },
      { c: 'info', t: 'N_002 CleartextTraffic    · High'   },
      { c: 'info', t: 'N_003 ImproperTLS         · High'   },
      { c: 'info', t: 'N_004 DataInTransit       · Critical'},
      { c: 'info', t: 'N_005 CertPinningBypass   · Info → High'},
    ],
  },
];

function navbarScroll() {
  const nav = document.querySelector('.landing-nav');
  if (!nav) return;
  const onScroll = () => nav.classList.toggle('is-scrolled', window.scrollY > 6);
  window.addEventListener('scroll', onScroll, { passive: true });
  onScroll();
}

function typewriter(termBody) {
  if (!termBody) return;
  const reduced = matchMedia('(prefers-reduced-motion: reduce)').matches;
  let cmdIdx = 0;

  function runOne() {
    const { cmd, out } = COMMANDS[cmdIdx];
    termBody.innerHTML = `<div><span class="terminal-prompt">nehal@sentinel</span>:<span class="terminal-cmd">~</span>$ <span id="tw-line"></span><span class="cursor-blink"></span></div>`;
    const target = termBody.querySelector('#tw-line');
    let i = 0;

    function step() {
      if (reduced) {
        target.textContent = cmd;
        return finishCmd();
      }
      if (i < cmd.length) {
        target.textContent += cmd[i++];
        setTimeout(step, 22 + Math.random() * 18);
      } else {
        finishCmd();
      }
    }
    function finishCmd() {
      out.forEach((line, j) => {
        setTimeout(() => {
          const el = document.createElement('div');
          el.className = 'terminal-out';
          el.innerHTML = `<span class="${line.c}">${line.t}</span>`;
          termBody.appendChild(el);
          termBody.scrollTop = termBody.scrollHeight;
        }, 200 + j * 320);
      });
      setTimeout(() => {
        cmdIdx = (cmdIdx + 1) % COMMANDS.length;
        runOne();
      }, 1200 + out.length * 320 + 1800);
    }
    step();
  }
  runOne();
}

function reveals() {
  if (matchMedia('(prefers-reduced-motion: reduce)').matches) {
    document.querySelectorAll('.reveal').forEach((el) => el.classList.add('is-visible'));
    return;
  }
  const io = new IntersectionObserver(
    (entries) => {
      entries.forEach((e) => {
        if (e.isIntersecting) {
          e.target.classList.add('is-visible');
          io.unobserve(e.target);
        }
      });
    },
    { threshold: 0.18, rootMargin: '0px 0px -40px 0px' },
  );
  document.querySelectorAll('.reveal').forEach((el) => io.observe(el));
}

function countUp(el, end, dur = 1500) {
  const reduced = matchMedia('(prefers-reduced-motion: reduce)').matches;
  if (reduced) { el.textContent = end; return; }
  const start = performance.now();
  function frame(now) {
    const t = Math.min(1, (now - start) / dur);
    const eased = 1 - Math.pow(1 - t, 3);
    el.textContent = Math.round(end * eased);
    if (t < 1) requestAnimationFrame(frame);
  }
  requestAnimationFrame(frame);
}

function statsAnim() {
  const io = new IntersectionObserver((entries) => {
    entries.forEach((e) => {
      if (e.isIntersecting) {
        e.target.querySelectorAll('.stat-num[data-count]').forEach((el) => {
          countUp(el, +el.dataset.count);
        });
        io.unobserve(e.target);
      }
    });
  }, { threshold: 0.4 });
  document.querySelectorAll('.stats-row').forEach((el) => io.observe(el));
}

function renderAgentGrid(filter = 'all') {
  const grid = document.querySelector('#landing-agent-grid');
  if (!grid) return;
  const pick = filter === 'all'  ? AGENTS
             : filter === 'sast' ? AGENTS.filter((a) => a.group === 'sast')
             : filter === 'dast' ? AGENTS.filter((a) => a.group === 'dast')
             :                     AGENTS.filter((a) => a.group === 'meta');
  grid.innerHTML = pick.map((a) => `
    <article class="agent-card">
      <div class="agent-card-head">
        <span class="agent-id">${a.id}</span>
        <span class="chip chip-phase">${a.phase}</span>
      </div>
      <div class="row-between">
        <span class="agent-name">${a.name}</span>
        <span class="chip chip-cat">${a.category}</span>
      </div>
      <p class="agent-desc">${a.description}</p>
      <div class="row-sm">${a.severity.map((s) => severityDot(s)).join('')}</div>
    </article>`).join('');
}

function agentTabs() {
  const strip = document.querySelector('#agent-tabs');
  if (!strip) return;
  strip.querySelectorAll('.tab').forEach((tab) => {
    tab.addEventListener('click', () => {
      strip.querySelectorAll('.tab').forEach((t) => t.classList.remove('is-active'));
      tab.classList.add('is-active');
      renderAgentGrid(tab.dataset.filter);
    });
  });
  renderAgentGrid('all');
}

function dastTabs() {
  const strip = document.querySelector('#dast-tabs');
  if (!strip) return;
  strip.querySelectorAll('.tab').forEach((tab) => {
    tab.addEventListener('click', () => {
      strip.querySelectorAll('.tab').forEach((t) => t.classList.remove('is-active'));
      tab.classList.add('is-active');
      document.querySelectorAll('[data-dast-panel]').forEach((p) => {
        p.classList.toggle('hidden', p.dataset.dastPanel !== tab.dataset.dast);
      });
    });
  });
}

function init() {
  navbarScroll();
  typewriter(document.querySelector('#hero-terminal-body'));
  reveals();
  statsAnim();
  agentTabs();
  dastTabs();
  if (window.lucide?.createIcons) window.lucide.createIcons({ nameAttr: 'data-lucide' });
}

if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', init);
else init();
