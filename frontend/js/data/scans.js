// SENTINEL — Scan history mock data (40 scans)

const STATUSES = ['completed', 'completed', 'completed', 'completed', 'completed', 'in_progress', 'failed'];
const PLATFORMS = ['Android', 'Android', 'Android', 'Android']; // mostly Android
const APP_VERSIONS = ['1.0.0', '2.4.1', '3.0.0-beta', '1.7.3', '4.2.0', '0.9.1', '2.8.5'];

const APPS = [
  { name: 'Campus', pkg: 'com.global.edu.campus' },
  { name: 'Signal', pkg: 'org.thoughtcrime.securesms' },
  { name: 'InsecureBankv2', pkg: 'com.android.insecurebankv2' },
  { name: 'MeshFin Banking', pkg: 'com.meshfin.android' },
  { name: 'DriveNow Ride', pkg: 'co.drivenow.app' },
  { name: 'QuickNotes', pkg: 'me.quicknotes.android' },
  { name: 'BetaHealth Tracker', pkg: 'health.beta.tracker' },
  { name: 'CryptoVault', pkg: 'io.cryptovault.wallet' },
  { name: 'PetalPay', pkg: 'com.petalpay.app' },
  { name: 'NebulaChat', pkg: 'chat.nebula.android' },
  { name: 'OmniFlex Workforce', pkg: 'com.omniflex.workforce' },
  { name: 'GreenLeaf Garden', pkg: 'app.greenleaf.garden' },
];

function daysAgoISO(d, h = 0) {
  const t = new Date('2026-05-24T20:00:00Z');
  t.setDate(t.getDate() - d);
  t.setHours(t.getHours() - h);
  return t.toISOString();
}

function pick(arr, seed) {
  return arr[seed % arr.length];
}

function genSev(status, seed) {
  if (status === 'in_progress' || status === 'failed') {
    return { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  }
  // pseudo-random based on seed
  const r = (n) => (seed * 31 + n * 17) % 8;
  return {
    critical: r(1),
    high: 1 + r(2) * 2,
    medium: 2 + r(3) * 3,
    low: 3 + r(4) * 4,
    info: 1 + r(5) * 2,
  };
}

export const SCANS = [
  // recent / in-progress
  { id: 'SCN-2026-040', appName: 'Campus', package: 'com.global.edu.campus', version: '3.0.0-beta', platform: 'Android', status: 'in_progress', startedAt: daysAgoISO(0, 0.2), duration: null, severity: { critical: 0, high: 2, medium: 4, low: 1, info: 0 }, triage: { verified: 0, filtered: 0, uncertain: 0, skipped: 0 }, warnings: ['mitmproxy disabled — anti-MITM Signal-like behavior detected'], scanFlags: ['--dynamic', '--frida'], duration_sec: null, scopeUrl: null, sizeMB: 24.1 },
  { id: 'SCN-2026-039', appName: 'Signal', package: 'org.thoughtcrime.securesms', version: '7.18.4', platform: 'Android', status: 'completed', startedAt: daysAgoISO(0, 4), duration: '00:08:12', duration_sec: 492, severity: { critical: 0, high: 1, medium: 3, low: 2, info: 4 }, triage: { verified: 6, filtered: 3, uncertain: 1, skipped: 0 }, warnings: ['Proxy killed Signal launch — fell back to no-proxy mode'], scanFlags: ['--dynamic', '--no-proxy'], scopeUrl: null, sizeMB: 142.3 },
  { id: 'SCN-2026-038', appName: 'MeshFin Banking', package: 'com.meshfin.android', version: '2.4.1', platform: 'Android', status: 'completed', startedAt: daysAgoISO(0, 9), duration: '00:14:33', duration_sec: 873, severity: { critical: 1, high: 5, medium: 8, low: 6, info: 3 }, triage: { verified: 18, filtered: 4, uncertain: 1, skipped: 0 }, warnings: [], scanFlags: ['--dynamic', '--frida', '--llm-triage'], scopeUrl: 'https://hackerone.com/meshfin', sizeMB: 88.7 },
  { id: 'SCN-2026-037', appName: 'CryptoVault', package: 'io.cryptovault.wallet', version: '1.0.0', platform: 'Android', status: 'completed', startedAt: daysAgoISO(1, 2), duration: '00:11:42', duration_sec: 702, severity: { critical: 2, high: 4, medium: 5, low: 3, info: 2 }, triage: { verified: 13, filtered: 2, uncertain: 1, skipped: 0 }, warnings: ['Frida attach timeout for 1 of 12 hooks'], scanFlags: ['--dynamic', '--frida'], scopeUrl: null, sizeMB: 56.0 },
  { id: 'SCN-2026-036', appName: 'InsecureBankv2', package: 'com.android.insecurebankv2', version: '1.7.3', platform: 'Android', status: 'completed', startedAt: daysAgoISO(1, 6), duration: '00:06:48', duration_sec: 408, severity: { critical: 3, high: 6, medium: 4, low: 2, info: 1 }, triage: { verified: 14, filtered: 1, uncertain: 1, skipped: 0 }, warnings: [], scanFlags: ['--dynamic'], scopeUrl: null, sizeMB: 18.4 },
  { id: 'SCN-2026-035', appName: 'PetalPay', package: 'com.petalpay.app', version: '4.2.0', platform: 'Android', status: 'completed', startedAt: daysAgoISO(2, 1), duration: '00:09:17', duration_sec: 557, severity: { critical: 1, high: 3, medium: 7, low: 4, info: 2 }, triage: { verified: 12, filtered: 4, uncertain: 1, skipped: 0 }, warnings: [], scanFlags: ['--llm-triage'], scopeUrl: 'https://bugcrowd.com/petalpay', sizeMB: 62.5 },
  { id: 'SCN-2026-034', appName: 'DriveNow Ride', package: 'co.drivenow.app', version: '2.8.5', platform: 'Android', status: 'failed', startedAt: daysAgoISO(2, 4), duration: '00:01:23', duration_sec: 83, severity: { critical: 0, high: 0, medium: 0, low: 0, info: 0 }, triage: { verified: 0, filtered: 0, uncertain: 0, skipped: 0 }, warnings: ['APK parse failed — corrupt resources.arsc'], scanFlags: [], scopeUrl: null, sizeMB: 41.2 },
  { id: 'SCN-2026-033', appName: 'QuickNotes', package: 'me.quicknotes.android', version: '0.9.1', platform: 'Android', status: 'completed', startedAt: daysAgoISO(3, 0), duration: '00:04:51', duration_sec: 291, severity: { critical: 0, high: 2, medium: 5, low: 6, info: 3 }, triage: { verified: 9, filtered: 5, uncertain: 2, skipped: 0 }, warnings: [], scanFlags: ['--llm-triage'], scopeUrl: null, sizeMB: 8.3 },
  { id: 'SCN-2026-032', appName: 'NebulaChat', package: 'chat.nebula.android', version: '1.0.0', platform: 'Android', status: 'completed', startedAt: daysAgoISO(3, 6), duration: '00:07:55', duration_sec: 475, severity: { critical: 0, high: 2, medium: 4, low: 3, info: 2 }, triage: { verified: 8, filtered: 3, uncertain: 0, skipped: 0 }, warnings: [], scanFlags: ['--llm-triage', '--privacy-mode'], scopeUrl: null, sizeMB: 32.1 },
  { id: 'SCN-2026-031', appName: 'BetaHealth Tracker', package: 'health.beta.tracker', version: '1.0.0', platform: 'Android', status: 'completed', startedAt: daysAgoISO(4, 2), duration: '00:10:28', duration_sec: 628, severity: { critical: 1, high: 3, medium: 6, low: 5, info: 4 }, triage: { verified: 14, filtered: 3, uncertain: 2, skipped: 0 }, warnings: ['LLM rate limit 429 — fell back to Cerebras'], scanFlags: ['--dynamic', '--llm-triage'], scopeUrl: null, sizeMB: 47.6 },
  { id: 'SCN-2026-030', appName: 'OmniFlex Workforce', package: 'com.omniflex.workforce', version: '2.1.0', platform: 'Android', status: 'completed', startedAt: daysAgoISO(4, 8), duration: '00:12:04', duration_sec: 724, severity: { critical: 0, high: 4, medium: 7, low: 4, info: 3 }, triage: { verified: 13, filtered: 4, uncertain: 1, skipped: 0 }, warnings: [], scanFlags: ['--llm-triage'], scopeUrl: null, sizeMB: 71.0 },
  { id: 'SCN-2026-029', appName: 'GreenLeaf Garden', package: 'app.greenleaf.garden', version: '3.4.0', platform: 'Android', status: 'completed', startedAt: daysAgoISO(5, 1), duration: '00:05:42', duration_sec: 342, severity: { critical: 0, high: 1, medium: 3, low: 4, info: 3 }, triage: { verified: 8, filtered: 2, uncertain: 1, skipped: 0 }, warnings: [], scanFlags: ['--llm-triage'], scopeUrl: null, sizeMB: 22.4 },
  { id: 'SCN-2026-028', appName: 'Campus', package: 'com.global.edu.campus', version: '2.9.4', platform: 'Android', status: 'completed', startedAt: daysAgoISO(5, 5), duration: '00:13:12', duration_sec: 792, severity: { critical: 0, high: 4, medium: 8, low: 5, info: 2 }, triage: { verified: 16, filtered: 2, uncertain: 1, skipped: 0 }, warnings: [], scanFlags: ['--dynamic', '--frida', '--llm-triage'], scopeUrl: 'https://hackerone.com/global-edu', sizeMB: 24.0 },
  { id: 'SCN-2026-027', appName: 'MeshFin Banking', package: 'com.meshfin.android', version: '2.4.0', platform: 'Android', status: 'completed', startedAt: daysAgoISO(6, 3), duration: '00:11:50', duration_sec: 710, severity: { critical: 2, high: 5, medium: 6, low: 5, info: 2 }, triage: { verified: 16, filtered: 3, uncertain: 1, skipped: 0 }, warnings: ['Cert pinning prevented Frida hook on payment SDK'], scanFlags: ['--dynamic', '--frida', '--llm-triage'], scopeUrl: 'https://hackerone.com/meshfin', sizeMB: 88.5 },
  { id: 'SCN-2026-026', appName: 'CryptoVault', package: 'io.cryptovault.wallet', version: '0.9.8', platform: 'Android', status: 'completed', startedAt: daysAgoISO(7, 0), duration: '00:09:24', duration_sec: 564, severity: { critical: 1, high: 3, medium: 4, low: 3, info: 1 }, triage: { verified: 10, filtered: 2, uncertain: 0, skipped: 0 }, warnings: [], scanFlags: ['--dynamic'], scopeUrl: null, sizeMB: 55.8 },
  { id: 'SCN-2026-025', appName: 'InsecureBankv2', package: 'com.android.insecurebankv2', version: '1.7.2', platform: 'Android', status: 'completed', startedAt: daysAgoISO(7, 6), duration: '00:06:21', duration_sec: 381, severity: { critical: 4, high: 7, medium: 5, low: 3, info: 1 }, triage: { verified: 18, filtered: 2, uncertain: 0, skipped: 0 }, warnings: [], scanFlags: ['--dynamic', '--frida'], scopeUrl: null, sizeMB: 18.2 },
  { id: 'SCN-2026-024', appName: 'PetalPay', package: 'com.petalpay.app', version: '4.1.5', platform: 'Android', status: 'completed', startedAt: daysAgoISO(8, 2), duration: '00:08:43', duration_sec: 523, severity: { critical: 1, high: 2, medium: 6, low: 5, info: 2 }, triage: { verified: 11, filtered: 4, uncertain: 1, skipped: 0 }, warnings: [], scanFlags: ['--llm-triage'], scopeUrl: 'https://bugcrowd.com/petalpay', sizeMB: 62.0 },
  { id: 'SCN-2026-023', appName: 'DriveNow Ride', package: 'co.drivenow.app', version: '2.8.4', platform: 'Android', status: 'completed', startedAt: daysAgoISO(8, 7), duration: '00:07:18', duration_sec: 438, severity: { critical: 0, high: 3, medium: 4, low: 4, info: 2 }, triage: { verified: 10, filtered: 3, uncertain: 0, skipped: 0 }, warnings: [], scanFlags: ['--llm-triage'], scopeUrl: null, sizeMB: 40.7 },
  { id: 'SCN-2026-022', appName: 'QuickNotes', package: 'me.quicknotes.android', version: '0.9.0', platform: 'Android', status: 'completed', startedAt: daysAgoISO(9, 0), duration: '00:04:11', duration_sec: 251, severity: { critical: 0, high: 1, medium: 4, low: 5, info: 3 }, triage: { verified: 8, filtered: 4, uncertain: 1, skipped: 0 }, warnings: [], scanFlags: ['--llm-triage'], scopeUrl: null, sizeMB: 8.0 },
  { id: 'SCN-2026-021', appName: 'NebulaChat', package: 'chat.nebula.android', version: '0.9.0', platform: 'Android', status: 'completed', startedAt: daysAgoISO(9, 4), duration: '00:07:30', duration_sec: 450, severity: { critical: 1, high: 3, medium: 3, low: 4, info: 2 }, triage: { verified: 10, filtered: 2, uncertain: 1, skipped: 0 }, warnings: [], scanFlags: ['--llm-triage'], scopeUrl: null, sizeMB: 31.8 },
  { id: 'SCN-2026-020', appName: 'Campus', package: 'com.global.edu.campus', version: '2.9.3', platform: 'Android', status: 'completed', startedAt: daysAgoISO(10, 1), duration: '00:12:48', duration_sec: 768, severity: { critical: 0, high: 4, medium: 7, low: 5, info: 2 }, triage: { verified: 15, filtered: 3, uncertain: 0, skipped: 0 }, warnings: [], scanFlags: ['--dynamic', '--frida', '--llm-triage'], scopeUrl: null, sizeMB: 23.8 },
  { id: 'SCN-2026-019', appName: 'BetaHealth Tracker', package: 'health.beta.tracker', version: '0.9.5', platform: 'Android', status: 'failed', startedAt: daysAgoISO(10, 6), duration: '00:00:34', duration_sec: 34, severity: { critical: 0, high: 0, medium: 0, low: 0, info: 0 }, triage: { verified: 0, filtered: 0, uncertain: 0, skipped: 0 }, warnings: ['adb device disconnected during dynamic phase'], scanFlags: ['--dynamic'], scopeUrl: null, sizeMB: 47.3 },
  { id: 'SCN-2026-018', appName: 'MeshFin Banking', package: 'com.meshfin.android', version: '2.3.9', platform: 'Android', status: 'completed', startedAt: daysAgoISO(11, 2), duration: '00:11:14', duration_sec: 674, severity: { critical: 1, high: 4, medium: 6, low: 4, info: 3 }, triage: { verified: 14, filtered: 3, uncertain: 1, skipped: 0 }, warnings: [], scanFlags: ['--dynamic', '--llm-triage'], scopeUrl: 'https://hackerone.com/meshfin', sizeMB: 88.2 },
  { id: 'SCN-2026-017', appName: 'CryptoVault', package: 'io.cryptovault.wallet', version: '0.9.7', platform: 'Android', status: 'completed', startedAt: daysAgoISO(11, 8), duration: '00:09:01', duration_sec: 541, severity: { critical: 2, high: 4, medium: 4, low: 2, info: 1 }, triage: { verified: 11, filtered: 2, uncertain: 0, skipped: 0 }, warnings: [], scanFlags: ['--dynamic', '--frida'], scopeUrl: null, sizeMB: 55.4 },
  { id: 'SCN-2026-016', appName: 'OmniFlex Workforce', package: 'com.omniflex.workforce', version: '2.0.8', platform: 'Android', status: 'completed', startedAt: daysAgoISO(12, 1), duration: '00:11:39', duration_sec: 699, severity: { critical: 0, high: 3, medium: 7, low: 4, info: 3 }, triage: { verified: 12, filtered: 4, uncertain: 1, skipped: 0 }, warnings: [], scanFlags: ['--llm-triage'], scopeUrl: null, sizeMB: 70.8 },
  { id: 'SCN-2026-015', appName: 'GreenLeaf Garden', package: 'app.greenleaf.garden', version: '3.3.5', platform: 'Android', status: 'completed', startedAt: daysAgoISO(12, 5), duration: '00:05:21', duration_sec: 321, severity: { critical: 0, high: 1, medium: 3, low: 3, info: 3 }, triage: { verified: 7, filtered: 2, uncertain: 1, skipped: 0 }, warnings: [], scanFlags: ['--llm-triage'], scopeUrl: null, sizeMB: 22.2 },
  { id: 'SCN-2026-014', appName: 'InsecureBankv2', package: 'com.android.insecurebankv2', version: '1.7.0', platform: 'Android', status: 'completed', startedAt: daysAgoISO(13, 3), duration: '00:05:58', duration_sec: 358, severity: { critical: 3, high: 6, medium: 4, low: 3, info: 1 }, triage: { verified: 15, filtered: 2, uncertain: 0, skipped: 0 }, warnings: [], scanFlags: ['--dynamic'], scopeUrl: null, sizeMB: 18.0 },
  { id: 'SCN-2026-013', appName: 'DriveNow Ride', package: 'co.drivenow.app', version: '2.8.3', platform: 'Android', status: 'completed', startedAt: daysAgoISO(14, 0), duration: '00:07:02', duration_sec: 422, severity: { critical: 0, high: 2, medium: 5, low: 4, info: 2 }, triage: { verified: 9, filtered: 4, uncertain: 0, skipped: 0 }, warnings: [], scanFlags: ['--llm-triage'], scopeUrl: null, sizeMB: 40.4 },
  { id: 'SCN-2026-012', appName: 'NebulaChat', package: 'chat.nebula.android', version: '0.8.5', platform: 'Android', status: 'completed', startedAt: daysAgoISO(14, 7), duration: '00:07:11', duration_sec: 431, severity: { critical: 1, high: 2, medium: 3, low: 3, info: 2 }, triage: { verified: 9, filtered: 2, uncertain: 0, skipped: 0 }, warnings: [], scanFlags: ['--llm-triage'], scopeUrl: null, sizeMB: 31.5 },
  { id: 'SCN-2026-011', appName: 'PetalPay', package: 'com.petalpay.app', version: '4.1.0', platform: 'Android', status: 'completed', startedAt: daysAgoISO(15, 2), duration: '00:08:25', duration_sec: 505, severity: { critical: 1, high: 2, medium: 5, low: 5, info: 2 }, triage: { verified: 10, filtered: 4, uncertain: 1, skipped: 0 }, warnings: [], scanFlags: ['--llm-triage'], scopeUrl: 'https://bugcrowd.com/petalpay', sizeMB: 61.6 },
  { id: 'SCN-2026-010', appName: 'Campus', package: 'com.global.edu.campus', version: '2.9.0', platform: 'Android', status: 'completed', startedAt: daysAgoISO(16, 1), duration: '00:12:18', duration_sec: 738, severity: { critical: 0, high: 3, medium: 7, low: 5, info: 2 }, triage: { verified: 13, filtered: 3, uncertain: 1, skipped: 0 }, warnings: [], scanFlags: ['--dynamic', '--llm-triage'], scopeUrl: null, sizeMB: 23.5 },
  { id: 'SCN-2026-009', appName: 'CryptoVault', package: 'io.cryptovault.wallet', version: '0.9.5', platform: 'Android', status: 'completed', startedAt: daysAgoISO(17, 3), duration: '00:08:48', duration_sec: 528, severity: { critical: 2, high: 3, medium: 4, low: 2, info: 1 }, triage: { verified: 10, filtered: 2, uncertain: 0, skipped: 0 }, warnings: [], scanFlags: ['--dynamic'], scopeUrl: null, sizeMB: 55.0 },
  { id: 'SCN-2026-008', appName: 'MeshFin Banking', package: 'com.meshfin.android', version: '2.3.0', platform: 'Android', status: 'completed', startedAt: daysAgoISO(18, 4), duration: '00:10:51', duration_sec: 651, severity: { critical: 1, high: 3, medium: 5, low: 4, info: 3 }, triage: { verified: 12, filtered: 3, uncertain: 1, skipped: 0 }, warnings: [], scanFlags: ['--dynamic', '--llm-triage'], scopeUrl: 'https://hackerone.com/meshfin', sizeMB: 87.6 },
  { id: 'SCN-2026-007', appName: 'QuickNotes', package: 'me.quicknotes.android', version: '0.8.5', platform: 'Android', status: 'completed', startedAt: daysAgoISO(19, 0), duration: '00:04:32', duration_sec: 272, severity: { critical: 0, high: 1, medium: 3, low: 4, info: 3 }, triage: { verified: 6, filtered: 4, uncertain: 1, skipped: 0 }, warnings: [], scanFlags: ['--llm-triage'], scopeUrl: null, sizeMB: 7.8 },
  { id: 'SCN-2026-006', appName: 'BetaHealth Tracker', package: 'health.beta.tracker', version: '0.9.0', platform: 'Android', status: 'completed', startedAt: daysAgoISO(20, 5), duration: '00:09:54', duration_sec: 594, severity: { critical: 1, high: 2, medium: 5, low: 4, info: 4 }, triage: { verified: 11, filtered: 4, uncertain: 1, skipped: 0 }, warnings: [], scanFlags: ['--llm-triage'], scopeUrl: null, sizeMB: 46.8 },
  { id: 'SCN-2026-005', appName: 'InsecureBankv2', package: 'com.android.insecurebankv2', version: '1.6.0', platform: 'Android', status: 'completed', startedAt: daysAgoISO(22, 2), duration: '00:05:34', duration_sec: 334, severity: { critical: 3, high: 5, medium: 4, low: 2, info: 1 }, triage: { verified: 13, filtered: 2, uncertain: 0, skipped: 0 }, warnings: [], scanFlags: ['--dynamic'], scopeUrl: null, sizeMB: 17.8 },
  { id: 'SCN-2026-004', appName: 'Signal', package: 'org.thoughtcrime.securesms', version: '7.15.0', platform: 'Android', status: 'completed', startedAt: daysAgoISO(23, 0), duration: '00:07:42', duration_sec: 462, severity: { critical: 0, high: 1, medium: 2, low: 3, info: 5 }, triage: { verified: 5, filtered: 4, uncertain: 2, skipped: 0 }, warnings: ['Proxy disabled — Signal would not connect through mitmproxy'], scanFlags: ['--dynamic', '--no-proxy'], scopeUrl: null, sizeMB: 141.0 },
  { id: 'SCN-2026-003', appName: 'OmniFlex Workforce', package: 'com.omniflex.workforce', version: '2.0.0', platform: 'Android', status: 'completed', startedAt: daysAgoISO(25, 4), duration: '00:10:48', duration_sec: 648, severity: { critical: 0, high: 3, medium: 6, low: 4, info: 3 }, triage: { verified: 11, filtered: 4, uncertain: 1, skipped: 0 }, warnings: [], scanFlags: ['--llm-triage'], scopeUrl: null, sizeMB: 70.4 },
  { id: 'SCN-2026-002', appName: 'GreenLeaf Garden', package: 'app.greenleaf.garden', version: '3.2.0', platform: 'Android', status: 'completed', startedAt: daysAgoISO(27, 6), duration: '00:05:01', duration_sec: 301, severity: { critical: 0, high: 1, medium: 2, low: 3, info: 3 }, triage: { verified: 6, filtered: 2, uncertain: 1, skipped: 0 }, warnings: [], scanFlags: ['--llm-triage'], scopeUrl: null, sizeMB: 21.9 },
  { id: 'SCN-2026-001', appName: 'Campus', package: 'com.global.edu.campus', version: '2.8.0', platform: 'Android', status: 'completed', startedAt: daysAgoISO(29, 0), duration: '00:11:28', duration_sec: 688, severity: { critical: 0, high: 3, medium: 6, low: 4, info: 2 }, triage: { verified: 12, filtered: 2, uncertain: 1, skipped: 0 }, warnings: [], scanFlags: ['--dynamic', '--llm-triage'], scopeUrl: null, sizeMB: 22.9 },
];

export function getScanById(id) {
  return SCANS.find(s => s.id === id);
}

// Phase timing breakdown for scan detail
export function getPhaseTimings(scan) {
  if (!scan || !scan.duration_sec) return [];
  const total = scan.duration_sec;
  return [
    { name: 'Phase 1: APK Parse', sec: Math.round(total * 0.04) },
    { name: 'Phase 2: Manifest Audit', sec: Math.round(total * 0.06) },
    { name: 'Phase 3: SAST Scan', sec: Math.round(total * 0.32) },
    { name: 'Phase 4: Agent Sweep', sec: Math.round(total * 0.28) },
    { name: 'Phase 4.5: Dynamic/Frida', sec: scan.scanFlags?.includes('--dynamic') ? Math.round(total * 0.22) : 0 },
    { name: 'Phase 5: LLM Triage', sec: scan.scanFlags?.includes('--llm-triage') ? Math.round(total * 0.08) : 0 },
  ].filter(p => p.sec > 0);
}

// Frida events (mock) for scan detail Frida Events tab
export const FRIDA_EVENTS_SAMPLE = [
  { ts: '00:01.245', group: 'crypto.cipher', hook: 'javax.crypto.Cipher.getInstance', args: '"AES/ECB/PKCS5Padding"' },
  { ts: '00:01.502', group: 'crypto.cipher', hook: 'javax.crypto.Cipher.init', args: 'mode=ENCRYPT_MODE, key=AES[256]' },
  { ts: '00:01.711', group: 'crypto.cipher', hook: 'javax.crypto.Cipher.doFinal', args: 'input=64B → output=64B' },
  { ts: '00:02.080', group: 'crypto.md', hook: 'java.security.MessageDigest.getInstance', args: '"MD5"' },
  { ts: '00:02.314', group: 'crypto.md', hook: 'java.security.MessageDigest.digest', args: 'input=12B → 16B hash' },
  { ts: '00:03.018', group: 'tls.bypass', hook: 'okhttp3.CertificatePinner.check', args: 'host=api.meshfin.com → bypassed' },
  { ts: '00:03.215', group: 'tls.bypass', hook: 'javax.net.ssl.TrustManagerImpl.checkServerTrusted', args: 'cert=*.meshfin.com → bypassed' },
  { ts: '00:04.412', group: 'webview.bridge', hook: 'WebView.addJavascriptInterface', args: 'name="Android"' },
  { ts: '00:05.118', group: 'storage.prefs', hook: 'SharedPreferences$Editor.putString', args: 'key="auth_token", value="eyJhbGc..."' },
  { ts: '00:05.487', group: 'storage.prefs', hook: 'SharedPreferences$Editor.putString', args: 'key="refresh_token", value="rt_5f3..."' },
  { ts: '00:06.301', group: 'auth.biometric', hook: 'BiometricPrompt.authenticate', args: 'crypto=null' },
  { ts: '00:07.114', group: 'network.http', hook: 'OkHttpClient.newCall', args: 'url=https://api.meshfin.com/v1/balance' },
];
