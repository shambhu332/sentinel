# SENTINEL Frida agent

Bundled hook script used by `sentinel/tools/frida_runner.py`.

## When to rebuild

- After editing any file under `src/`
- After updating `frida-java-bridge` to a new major version
- Before each release tag

## Build

```bash
cd frida_agent
npm install          # one-time
npm run build        # produces dist/_agent.js
```

Commit `dist/_agent.js` — it's the artifact loaded by Python.
The Python side never invokes Node.js. Users without Node.js installed
can still run SENTINEL because the compiled agent is checked in.

## Verify the build

```bash
ls -lh dist/_agent.js
# Expected: ~150–250 KB (bundles frida-java-bridge ~ 100 KB + our hooks)

head -5 dist/_agent.js
# First lines should be the frida-compile preamble
```
