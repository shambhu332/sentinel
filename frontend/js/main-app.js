/**
 * main-app.js — bootstraps app.html.
 * Mounts the sidebar + topbar, starts the router, hydrates Lucide.
 */

import { renderSidebar } from './components/sidebar.js';
import { renderTopbar }  from './components/topbar.js';
import { startRouter }   from './router.js';

const APP_STATE = {
  currentWorkspaceId: 'ws_personal',
};

function init() {
  const sidebarSlot = document.getElementById('sidebar-slot');
  const topbarSlot  = document.getElementById('topbar-slot');
  if (!sidebarSlot || !topbarSlot) {
    console.error('[main-app] expected #sidebar-slot and #topbar-slot in DOM');
    return;
  }

  const handleWorkspaceSwitch = (id) => {
    APP_STATE.currentWorkspaceId = id;
    renderSidebar(sidebarSlot, {
      currentWorkspaceId: id,
      onWorkspaceSwitch: handleWorkspaceSwitch,
    });
    window.dispatchEvent(new HashChangeEvent('hashchange'));
  };
  renderSidebar(sidebarSlot, {
    currentWorkspaceId: APP_STATE.currentWorkspaceId,
    onWorkspaceSwitch: handleWorkspaceSwitch,
  });
  renderTopbar(topbarSlot);
  startRouter();

  if (window.lucide?.createIcons) window.lucide.createIcons({ nameAttr: 'data-lucide' });
}

if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', init);
} else {
  init();
}
