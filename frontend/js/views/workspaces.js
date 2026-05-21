/**
 * workspaces.js — Workspace grid + Workspace detail.
 *
 * Detail tabs: Members · Projects · Settings · Audit log.
 */

import { WORKSPACES, WORKSPACE_AUDIT, getWorkspace } from '../data/workspaces.js';
import { projectsByWorkspace } from '../data/projects.js';

const PLAN_CHIP = {
  Free:       '<span class="chip chip-cat">Free</span>',
  Pro:        '<span class="chip chip-status-active">Pro</span>',
  Enterprise: '<span class="chip chip-status-completed">Enterprise</span>',
};

function avatarStack(members) {
  return `<div class="avatar-stack">${members.slice(0, 4).map((m) =>
    `<span class="avatar avatar-sm" style="background:${m.avatarColor};color:#0B0F1E;" title="${m.name}">${m.initials}</span>`
  ).join('')}</div>`;
}

export function renderWorkspaces(mount) {
  mount.innerHTML = `
    <div class="page-head">
      <div>
        <h1 class="page-title">Workspaces</h1>
        <div class="page-sub">Multi-tenant org isolation — switch from the sidebar dropdown</div>
      </div>
      <div class="page-actions">
        <button class="btn btn-primary btn-sm"><i data-lucide="plus"></i> New workspace</button>
      </div>
    </div>

    <div class="grid-3">
      ${WORKSPACES.map((w) => {
        const projects = projectsByWorkspace(w.id);
        return `
          <article class="card card-hoverable" data-ws="${w.id}" style="cursor:pointer;">
            <div class="row-between mb-3">
              ${PLAN_CHIP[w.plan]}
              <span class="text-mute text-xs">since ${w.createdAt}</span>
            </div>
            <h3 style="font-size: var(--fs-md);">${w.name}</h3>
            <p class="text-dim text-sm mt-2">${w.description}</p>
            <div class="row-between mt-4">
              <div class="row-sm">
                ${avatarStack(w.members)}
                <span class="text-xs text-dim">${w.members.length} member${w.members.length>1?'s':''}</span>
              </div>
              <span class="text-xs text-mute">${projects.length} project${projects.length===1?'':'s'}</span>
            </div>
            <div class="mt-4">
              <button class="btn btn-secondary btn-sm btn-block"><i data-lucide="settings"></i> Manage</button>
            </div>
          </article>`;
      }).join('')}
    </div>
  `;

  if (window.lucide?.createIcons) window.lucide.createIcons({ nameAttr: 'data-lucide' });

  mount.querySelectorAll('[data-ws]').forEach((card) => {
    card.addEventListener('click', () => { location.hash = `workspaces/${card.dataset.ws}`; });
  });
}

export function renderWorkspaceDetail(mount, params = []) {
  const w = getWorkspace(params[0]);
  if (!w) { mount.innerHTML = `<div class="empty"><h3>Workspace not found</h3><a class="btn btn-secondary" href="#workspaces">Back</a></div>`; return; }
  const projects = projectsByWorkspace(w.id);
  const audit = WORKSPACE_AUDIT[w.id] || [];

  mount.innerHTML = `
    <div class="page-head">
      <div>
        <a href="#workspaces" class="text-dim text-sm row-sm"><i data-lucide="arrow-left" style="width:14px;height:14px;"></i> Workspaces</a>
        <h1 class="page-title mt-2">${w.name}</h1>
        <p class="text-dim mt-2">${w.description}</p>
      </div>
      <div class="page-actions">
        ${PLAN_CHIP[w.plan]}
        <button class="btn btn-primary btn-sm"><i data-lucide="user-plus"></i> Invite</button>
      </div>
    </div>

    <div class="tabs mb-6" id="wd-tabs">
      <button class="tab is-active" data-tab="members">Members <span class="text-mute">· ${w.members.length}</span></button>
      <button class="tab" data-tab="projects">Projects <span class="text-mute">· ${projects.length}</span></button>
      <button class="tab" data-tab="settings">Settings</button>
      <button class="tab" data-tab="audit">Audit log <span class="text-mute">· ${audit.length}</span></button>
    </div>
    <div id="wd-body"></div>
  `;

  const body = mount.querySelector('#wd-body');

  function paint(tab) {
    mount.querySelectorAll('#wd-tabs .tab').forEach((t) => t.classList.toggle('is-active', t.dataset.tab === tab));
    if (tab === 'members') {
      body.innerHTML = `<div class="table-wrap"><table class="table">
        <thead><tr><th>Member</th><th>Email</th><th>Role</th><th>Status</th><th>Last active</th><th></th></tr></thead>
        <tbody>
          ${w.members.map((m) => `<tr>
            <td><div class="row-sm"><span class="avatar avatar-sm" style="background:${m.avatarColor};color:#0B0F1E;">${m.initials}</span> ${m.name}</div></td>
            <td class="text-dim text-sm">${m.email}</td>
            <td><span class="chip chip-cat">${m.role}</span></td>
            <td><span class="chip chip-status-active">${m.status}</span></td>
            <td class="text-dim text-xs">${m.lastActive}</td>
            <td class="col-actions"><button class="btn btn-ghost btn-sm">Remove</button></td>
          </tr>`).join('')}
        </tbody></table></div>`;
    } else if (tab === 'projects') {
      body.innerHTML = `<div class="grid-3">
        ${projects.map((p) => `
          <article class="card card-hoverable" onclick="location.hash='projects/${p.id}'" style="cursor:pointer;">
            <h3 style="font-size: var(--fs-md);">${p.name}</h3>
            <code class="mono" style="font-size:12px;">${p.targetPackage}</code>
            <p class="text-dim text-sm mt-2">${p.description}</p>
          </article>`).join('') || '<div class="empty"><h3>No projects yet</h3></div>'}
      </div>`;
    } else if (tab === 'settings') {
      body.innerHTML = `
        <div class="card">
          <div class="card-title mb-3">Workspace name</div>
          <input class="input" value="${w.name}"/>
          <div class="card-title mt-6 mb-2">Description</div>
          <textarea class="textarea" rows="3">${w.description}</textarea>
          <div class="card-title mt-6 mb-2">Default LLM provider</div>
          <select class="select"><option>Auto (Groq → Cerebras → Ollama)</option><option>Ollama only</option></select>
          <hr/>
          <div class="card-title mb-2">Danger zone</div>
          <p class="text-dim text-sm mb-3">Transferring ownership requires the new owner to accept within 7 days. Deleting permanently removes all projects, scans, findings, and reports.</p>
          <div class="row-sm">
            <button class="btn btn-secondary btn-sm">Transfer ownership</button>
            <button class="btn btn-danger btn-sm"><i data-lucide="trash-2"></i> Delete workspace</button>
          </div>
        </div>`;
    } else if (tab === 'audit') {
      body.innerHTML = `<div class="card"><div class="activity-feed">
        ${audit.map((e) => `<div class="activity-item">
          <span class="activity-icon"><i data-lucide="clock"></i></span>
          <div class="activity-text"><strong>${e.actor}</strong> ${e.action}<div class="activity-time">${e.ts}</div></div>
        </div>`).join('')}
      </div></div>`;
    }
    if (window.lucide?.createIcons) window.lucide.createIcons({ nameAttr: 'data-lucide' });
  }

  paint('members');
  mount.querySelectorAll('#wd-tabs .tab').forEach((btn) => btn.addEventListener('click', () => paint(btn.dataset.tab)));
}
