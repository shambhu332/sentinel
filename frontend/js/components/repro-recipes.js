// Reproduction-step recipes — one canonical playbook per vuln class so
// every finding in the UI ships a junior-researcher-followable walkthrough
// even when the producing agent did not populate evidence.repro_steps.
//
// A recipe returns an ordered array of {text, command, label} steps.
// `text` is the human instruction (no jargon assumed).
// `command` is the exact shell/ADB/Frida snippet to paste.
// `label` is an optional category for matching screenshots later.
//
// Placeholders supported in text/command via tmpl():
//   {{package}}    — Android package id (com.example.app)
//   {{apk}}        — path to local APK on disk
//   {{component}}  — fully-qualified component (Activity/Service/Receiver)
//   {{class}}      — Java class FQN extracted from evidence.location
//   {{file}}       — file path from evidence.location

function tmpl(str, vars) {
  return String(str || '').replace(/\{\{(\w+)\}\}/g, (_, k) =>
    vars[k] != null && vars[k] !== '' ? String(vars[k]) : `<${k}>`);
}

function step(text, command, label) {
  return { text, command: command || '', label: label || '' };
}

function pkg(ctx) { return (ctx && ctx.package) || '<package>'; }

function locationParts(finding) {
  const loc = finding?.evidence?.location || finding?.location || '';
  // typical formats: "com/foo/Bar.java:42" or "com.foo.Bar#method"
  const file = loc.split(':')[0] || '';
  const cls = file.replace(/\.java$/, '').replace(/\//g, '.');
  return { file, class: cls, location: loc };
}

// ---- recipes ----

function reproDebuggable(ctx) {
  const p = pkg(ctx);
  return [
    step(
      'Pull the running APK from the device (skip if you already have the APK file).',
      `adb shell pm path ${p}\nadb pull $(adb shell pm path ${p} | sed 's/package://') ./target.apk`,
      'pull'),
    step(
      'Inspect the manifest for the android:debuggable attribute. The flag must be "true" on the <application> element.',
      'apktool d -f -o ./target_decoded ./target.apk\ngrep -n "android:debuggable" ./target_decoded/AndroidManifest.xml',
      'manifest'),
    step(
      'Install the APK on a non-rooted device and confirm jdwp exposes the process — only debuggable apps show up here.',
      `adb install -r ./target.apk\nadb shell am start -n ${p}/.MainActivity\nadb jdwp | xargs -I{} adb shell ps -p {} -o NAME= | grep ${p}`,
      'jdwp'),
    step(
      'Attach a debugger to confirm full runtime control. Successful attach = vulnerability proven.',
      `adb forward tcp:8700 jdwp:$(adb jdwp | head -1)\njdb -attach localhost:8700`,
      'attach'),
  ];
}

function reproBackup(ctx) {
  const p = pkg(ctx);
  return [
    step(
      'Install the target APK on a test device (Android 6+, USB debugging on).',
      `adb install -r ./target.apk`,
      'install'),
    step(
      'Launch the app and exercise a login/data-entry flow so private files exist under /data/data/.',
      `adb shell am start -n ${p}/.MainActivity`,
      'exercise'),
    step(
      'Request an ADB backup. The dialog appears only when allowBackup="true".',
      `adb backup -f ./out.ab -apk ${p}`,
      'backup-prompt'),
    step(
      'Confirm "Back up my data" on the device (no password).',
      '',
      'backup-confirm'),
    step(
      'Convert the Android backup blob to a tarball and inspect for sensitive data (DBs, shared_prefs, tokens).',
      `( printf "\\x1f\\x8b\\x08\\x00\\x00\\x00\\x00\\x00" ; tail -c +25 ./out.ab ) | gunzip > ./out.tar\ntar -tvf ./out.tar | head -50\ntar -xvf ./out.tar -C ./out\nfind ./out -name "*.xml" -o -name "*.db" | xargs grep -lE "token|password|email" 2>/dev/null`,
      'extract'),
  ];
}

function reproAuthTokenStorage(finding, ctx) {
  const p = pkg(ctx);
  const { file } = locationParts(finding);
  return [
    step(
      'Root the test device or use an emulator with a userdebug build so /data/data is readable.',
      'adb root && adb shell whoami',
      'root'),
    step(
      'Drive the app through a successful login so the credential gets persisted.',
      `adb shell am start -n ${p}/.LoginActivity`,
      'login'),
    step(
      `Locate the SharedPreferences / file the app writes the token to (source: ${file || 'see Affected Code'}).`,
      `adb shell run-as ${p} ls -la /data/data/${p}/shared_prefs/\nadb shell run-as ${p} cat /data/data/${p}/shared_prefs/*.xml`,
      'list-prefs'),
    step(
      'Grep the dump for high-signal keys (token, password, jwt, session). A plaintext hit confirms the finding.',
      `adb shell run-as ${p} cat /data/data/${p}/shared_prefs/*.xml | grep -iE "token|password|jwt|session|secret"`,
      'grep-secrets'),
    step(
      'Optional: confirm reachability without root via debuggable backup (covered separately in C_001).',
      `adb backup -f auth.ab -apk ${p}`,
      'backup-confirm'),
  ];
}

function reproInsecureLogging(finding, ctx) {
  const p = pkg(ctx);
  return [
    step(
      'Clear the logcat ring so only fresh entries appear.',
      'adb logcat -c',
      'clear'),
    step(
      'Start the app and reproduce the action that emits the sensitive log (typically login or token refresh).',
      `adb shell am start -n ${p}/.MainActivity`,
      'trigger'),
    step(
      'Tail logcat filtered to the target package and grep for sensitive keywords.',
      `adb logcat --pid=$(adb shell pidof ${p}) | grep -iE "password|token|email|jwt|secret|otp"`,
      'capture'),
    step(
      'Save proof: redirect output to a file as evidence for the report.',
      `adb logcat --pid=$(adb shell pidof ${p}) -d > logcat_evidence.txt`,
      'save'),
  ];
}

function reproSensitivePermission(finding, ctx) {
  const p = pkg(ctx);
  const perm = finding?.evidence?.permission
    || (finding?.vuln_class || '').split(':').pop()?.trim()
    || 'android.permission.X';
  return [
    step(
      'Decode the APK and read the manifest to confirm the dangerous permission is declared.',
      `apktool d -f -o ./decoded ./target.apk\ngrep -n "${perm}" ./decoded/AndroidManifest.xml`,
      'manifest'),
    step(
      'Install on a clean device. Android will grant install-time permissions automatically.',
      'adb install -r ./target.apk',
      'install'),
    step(
      `Confirm the runtime grant on first launch (Android 6+).`,
      `adb shell am start -n ${p}/.MainActivity\nadb shell dumpsys package ${p} | grep -A2 "runtime permissions"`,
      'grant'),
    step(
      `Justify with the dev team: locate every API call gated by ${perm} to decide whether the permission is genuinely needed.`,
      `grep -rn "${perm.split('.').pop()}" ./decoded/smali*/  2>/dev/null | head`,
      'usage-audit'),
  ];
}

function reproIntentRedirect(finding, ctx) {
  const p = pkg(ctx);
  const { class: cls } = locationParts(finding);
  return [
    step(
      'Identify the exported component that re-dispatches a caller-supplied Intent (see Affected Code).',
      `aapt dump xmltree ./target.apk AndroidManifest.xml | grep -A4 "${cls || 'name='}"`,
      'identify'),
    step(
      'Install the APK and ensure the device is awake.',
      `adb install -r ./target.apk && adb shell input keyevent 82`,
      'install'),
    step(
      'Fire a malicious Intent with a nested EXTRA Intent pointing at a protected component. A successful redirect proves the bug.',
      `adb shell am start -n ${p}/${cls || '<EXPORTED_COMPONENT>'} \\\n  --es target_uri "content://${p}.provider/private" \\\n  --ez forward true`,
      'exploit'),
    step(
      'Verify the target component was actually invoked by tailing logcat for the redirected start.',
      `adb logcat | grep -iE "ActivityManager|${p}"`,
      'verify'),
  ];
}

function reproExposedIPC(finding, ctx) {
  const p = pkg(ctx);
  return [
    step(
      'Enumerate every exported component on the installed APK.',
      `adb shell dumpsys package ${p} | grep -E "Activity|Service|Receiver" | grep -i "exported=true"`,
      'enumerate'),
    step(
      'Start each unguarded activity from a foreign UID to prove no permission check exists.',
      `adb shell am start -n ${p}/<EXPORTED_ACTIVITY>`,
      'start'),
    step(
      'For exported services, attempt a bind and observe AIDL/Messenger surface.',
      `adb shell am startservice -n ${p}/<EXPORTED_SERVICE>`,
      'bind'),
    step(
      'For exported receivers, broadcast crafted extras and watch for state changes.',
      `adb shell am broadcast -n ${p}/<EXPORTED_RECEIVER> --es key value`,
      'broadcast'),
    step(
      'Capture logcat during exploitation as evidence of cross-app invocation.',
      `adb logcat -d | grep ${p} > ipc_evidence.txt`,
      'evidence'),
  ];
}

function reproWeakCrypto(finding, ctx) {
  const p = pkg(ctx);
  return [
    step(
      'Confirm the algorithm in code (MD5/SHA1/DES/RC4 etc.) at the location shown in Affected Code.',
      'jadx -d ./jadx_out ./target.apk\ngrep -rnE "MessageDigest\\.getInstance\\((MD5|SHA-?1)\\)|Cipher\\.getInstance\\((DES|RC4|AES/ECB)" ./jadx_out',
      'static'),
    step(
      'Attach Frida at runtime and hook MessageDigest/Cipher to log the exact algorithm being used.',
      `frida -U -n ${p} -e "Java.perform(()=>{const M=Java.use('java.security.MessageDigest');M.getInstance.overload('java.lang.String').implementation=function(a){console.log('[MD]',a);return this.getInstance(a);};});"`,
      'frida'),
    step(
      'Drive the feature that invokes the crypto (e.g. password hash, signature). Frida output proves the weak algorithm is exercised at runtime.',
      `adb shell am start -n ${p}/.LoginActivity`,
      'trigger'),
  ];
}

function reproMutablePendingIntent(finding, ctx) {
  const p = pkg(ctx);
  const { file } = locationParts(finding);
  return [
    step(
      `Open the source at ${file || 'the location in Affected Code'} and confirm PendingIntent.FLAG_IMMUTABLE is NOT set.`,
      `jadx -d ./jadx_out ./target.apk && grep -rn "PendingIntent.get" ./jadx_out | grep -v IMMUTABLE`,
      'source'),
    step(
      'Run the app to the screen that builds the PendingIntent (notification, alarm, widget).',
      `adb shell am start -n ${p}/.MainActivity`,
      'trigger'),
    step(
      'Hook PendingIntent.getActivity/getBroadcast/getService with Frida and dump the flags integer. Missing 0x4000000 (FLAG_IMMUTABLE) = vulnerable.',
      `frida -U -n ${p} -e "Java.perform(()=>{const PI=Java.use('android.app.PendingIntent');['getActivity','getBroadcast','getService'].forEach(m=>{PI[m].overload('android.content.Context','int','android.content.Intent','int').implementation=function(c,r,i,f){console.log('[PI]',m,'flags=0x'+f.toString(16));return this[m](c,r,i,f);};});});"`,
      'frida'),
    step(
      'A malicious app can now hijack the empty base Intent. Demonstrate by holding the PendingIntent and overwriting its component before .send().',
      '// See evidence.poc for the malicious-companion app snippet',
      'poc'),
  ];
}

// ---- registry ----

const BY_AGENT = {
  META_002: reproDebuggable,
  C_001:    reproBackup,
  A_001:    reproAuthTokenStorage,
  A_007:    reproInsecureLogging,
  P_005:    reproSensitivePermission,
  P_010:    reproIntentRedirect,
  IPC_001:  reproExposedIPC,
  C_007:    reproWeakCrypto,
  P_012:    reproMutablePendingIntent,
};

const BY_VULN_CLASS = [
  [/debuggable/i,                reproDebuggable],
  [/backup/i,                    reproBackup],
  [/auth.*token|token.*storage|insecure auth/i, reproAuthTokenStorage],
  [/insecure logging|sensitive log/i, reproInsecureLogging],
  [/sensitive permission|dangerous permission/i, reproSensitivePermission],
  [/intent redirect/i,           reproIntentRedirect],
  [/exposed ipc|exported component/i, reproExposedIPC],
  [/weak crypto/i,               reproWeakCrypto],
  [/mutable pendingintent|pendingintent/i, reproMutablePendingIntent],
];

function genericFallback(finding, ctx) {
  const p = pkg(ctx);
  return [
    step(
      'Install the APK on a clean test device with USB debugging enabled.',
      'adb install -r ./target.apk',
      'install'),
    step(
      `Launch the app and navigate to the surface referenced in Affected Code (${finding?.evidence?.location || 'see code section'}).`,
      `adb shell am start -n ${p}/.MainActivity`,
      'navigate'),
    step(
      'Reproduce the trigger described in the finding description, then capture logcat + screenshots as evidence.',
      `adb logcat -c && adb logcat --pid=$(adb shell pidof ${p}) > evidence.log`,
      'capture'),
    step(
      'Compare the observed behaviour against the expected behaviour in the recommendation section. A divergence confirms the finding.',
      '',
      'verify'),
  ];
}

export function getReproRecipe(finding, ctx) {
  const recipe = BY_AGENT[finding?.agent_id];
  if (recipe) return recipe(finding, ctx).map(s => normaliseStep(s, ctx, finding));
  const vc = String(finding?.vuln_class || finding?.vulnClass || '');
  for (const [re, fn] of BY_VULN_CLASS) {
    if (re.test(vc)) return fn(finding, ctx).map(s => normaliseStep(s, ctx, finding));
  }
  return genericFallback(finding, ctx).map(s => normaliseStep(s, ctx, finding));
}

function normaliseStep(s, ctx, finding) {
  const vars = {
    package: pkg(ctx),
    apk: './target.apk',
    component: finding?.evidence?.component || '',
    ...locationParts(finding),
  };
  return {
    text: tmpl(s.text, vars),
    command: tmpl(s.command, vars),
    label: s.label || '',
  };
}
