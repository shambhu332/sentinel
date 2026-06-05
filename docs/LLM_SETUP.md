
# SENTINEL — Self-hosted LLM Setup for College Server

This guide deploys an OpenAI-compatible LLM endpoint on a single Linux server that all SENTINEL student installations can call over the campus network. The recommended stack is **Ollama** — it has the easiest install, lowest operational overhead, and SENTINEL already supports it natively via the `--private` flag.

## What this gives you

- A local LLM endpoint at `http://<server-ip>:11434` reachable from every student laptop on campus
- Auto-restart on reboot via systemd
- Optional nginx + Basic Auth layer for access control
- Zero ongoing cost — no API keys, no rate limits, no data leaving the campus
- SENTINEL students set one environment variable and they're done

## 1. Choose a server tier

Pick the tier that matches your hardware. Ollama works on all three.

### Tier A — GPU server (recommended)

| Component | Minimum | Recommended |
|---|---|---|
| GPU VRAM | 16 GB (RTX 4060 Ti, A2000, V100) | 24 GB+ (RTX 4090, A5000, A6000) |
| RAM | 32 GB | 64 GB |
| Disk | 100 GB SSD | 200 GB NVMe |
| OS | Ubuntu 22.04 LTS or Ubuntu 24.04 LTS | same |

**Models that fit:** `qwen2.5-coder:14b` (≈9 GB), `llama3.1:8b` (≈5 GB), or `qwen2.5-coder:32b-instruct-q4_K_M` (≈19 GB on 24 GB cards).

### Tier B — CPU-only server

| Component | Minimum | Recommended |
|---|---|---|
| CPU | 8 cores, AVX2 | 16+ cores, AVX-512 |
| RAM | 32 GB | 64 GB |
| Disk | 100 GB SSD | 200 GB NVMe |
| OS | Ubuntu 22.04 LTS | same |

**Models that fit:** `llama3.2:3b` (fast), `qwen2.5:7b` (better answers, ~2–5 tokens/sec on CPU), `phi3:medium` (good code reasoning).

CPU-only is slow (think 30–90 seconds per finding triaged), but it works. Plan for batch scans, not interactive sessions.

### Tier C — Multi-GPU server (for many concurrent students)

If 10+ students will scan simultaneously, you want either:
- Multiple Ollama instances behind a load balancer, or
- vLLM with `tensor-parallel-size` — see Appendix B if you go this route

For typical lab use (1–5 concurrent scans), Tier A is enough.

## 2. Install Ollama

Run as a user with `sudo`. These steps assume Ubuntu 22.04/24.04.

```bash
# Install Ollama (official one-line installer)
curl -fsSL https://ollama.com/install.sh | sh

# Verify
ollama --version
# Expected: ollama version 0.X.X

# If you have a GPU, verify it sees the CUDA runtime
nvidia-smi
# You should see your GPU listed. If "command not found", install nvidia drivers first:
#   sudo apt update && sudo apt install -y nvidia-driver-535 && sudo reboot
```

On install, Ollama:
- Creates a systemd service named `ollama`
- Listens on `127.0.0.1:11434` by default
- Creates an `ollama` system user that owns `/usr/share/ollama`

## 3. Make Ollama reachable from the campus network

By default Ollama only listens on localhost. We need it on all interfaces.

```bash
# Edit the systemd unit override
sudo systemctl edit ollama.service
```

In the editor that opens, paste this and save:

```ini
[Service]
Environment="OLLAMA_HOST=0.0.0.0:11434"
Environment="OLLAMA_ORIGINS=*"
# Optional: tune concurrency
Environment="OLLAMA_NUM_PARALLEL=4"
Environment="OLLAMA_MAX_LOADED_MODELS=2"
```

Reload and restart:

```bash
sudo systemctl daemon-reload
sudo systemctl restart ollama
sudo systemctl status ollama
# Should show "active (running)"

# Verify it's bound to 0.0.0.0
sudo ss -tlnp | grep 11434
# Expected: LISTEN 0.0.0.0:11434
```

Open the firewall port:

```bash
# If using ufw
sudo ufw allow from 10.0.0.0/8 to any port 11434 comment "Ollama LAN access"
sudo ufw allow from 172.16.0.0/12 to any port 11434 comment "Ollama LAN access"
sudo ufw allow from 192.168.0.0/16 to any port 11434 comment "Ollama LAN access"
sudo ufw reload

# Replace the CIDR ranges with whatever covers the campus network.
# If you don't know, ask the network admin which subnet student laptops are on.
```

If your campus uses a firewall appliance instead of host firewall, ask the network admin to allow inbound TCP/11434 from the student subnet.

## 4. Download the model(s)

Pick one as primary and optionally a fallback. SENTINEL only needs one to be available.

**Recommended primary models (in order of preference):**

| Model tag | Size on disk | Best for | Hardware |
|---|---|---|---|
| `qwen2.5-coder:14b` | 9 GB | Code reasoning, our use case | GPU 16 GB+ |
| `llama3.1:8b` | 5 GB | General reasoning, fast | GPU 12 GB+ or CPU 32 GB |
| `qwen2.5:7b` | 4.7 GB | Good balance | GPU 8 GB+ or CPU 32 GB |
| `llama3.2:3b` | 2 GB | Fast on CPU, weaker reasoning | CPU only OK |

Pull the model(s):

```bash
# Primary model (pick one based on your hardware tier)
ollama pull qwen2.5-coder:14b

# Optional lightweight fallback for quick smoke tests
ollama pull llama3.2:3b

# Verify they're loaded
ollama list
```

First pull takes 5–20 minutes depending on the campus internet speed.

## 5. Test the endpoint locally on the server

```bash
# Health check
curl http://localhost:11434/api/tags
# Expected: JSON listing the models you pulled

# Functional check — ask the model a SENTINEL-shaped triage question
curl -s http://localhost:11434/api/chat -d '{
  "model": "qwen2.5-coder:14b",
  "messages": [
    {"role": "user", "content": "Is this a real security bug? An Android app calls MessageDigest.getInstance(\"MD5\") to hash passwords before storing them in SharedPreferences. Answer YES or NO and one sentence why."}
  ],
  "stream": false
}' | jq .message.content

# Expected output (something like):
# "YES. MD5 is cryptographically broken and unsuitable for password hashing;
#  use Argon2id or bcrypt with per-user salts instead."
```

If both commands work, the LLM is live.

## 6. Test from a student laptop on the same network

From any laptop on the campus WiFi:

```bash
# Replace <server-ip> with the actual IP of the college server
curl http://<server-ip>:11434/api/tags

# Expected: same JSON listing models
```

If the curl times out, the firewall is blocking the port. Re-check step 3.

If you get the model list — you're done with the server side. Move to step 7 to configure SENTINEL.

## 7. Configure SENTINEL on student laptops

Each student installs SENTINEL normally (see project README), then adds one environment variable. They can put it in their shell rc file once and forget about it.

```bash
# Add to ~/.bashrc or ~/.zshrc or ~/.config/fish/config.fish
export OLLAMA_HOST=http://<server-ip>:11434
```

For fish shell (CachyOS / Arch users):

```fish
echo 'set -gx OLLAMA_HOST http://<server-ip>:11434' >> ~/.config/fish/config.fish
```

Reload the shell, then run a scan with the `--private` flag, which forces SENTINEL's LLM router to use Ollama instead of cloud providers:

```bash
cd ~/sentinel
poetry run sentinel scan corpus/InsecureBankv2.apk --private
```

`--private` tells SENTINEL's `FreeProviderRouter` to skip Groq and Cerebras entirely and go straight to your college Ollama endpoint.

To verify SENTINEL is actually reaching the server, students can run:

```bash
poetry run sentinel status
# Look for "Ollama host: http://<server-ip>:11434" in the output
```

## 8. Pin the model name in SENTINEL config (one-time, per student or in the repo)

SENTINEL's Ollama client defaults to `llama3.2:3b` because that's the only model guaranteed available. Override it to match what you pulled in step 4.

In each student's environment (or commit to the repo's `.env.example`):

```bash
export SENTINEL_OLLAMA_MODEL=qwen2.5-coder:14b
```

Or directly edit `sentinel/llm/providers/ollama.py` if your teacher prefers a project-wide default — change the model constant near the top of the file.

## 9. (Optional) Add Basic Auth via nginx

If you want to require a username and password to access the LLM (recommended for a shared lab server), put nginx in front of Ollama.

```bash
# Install nginx and htpasswd tool
sudo apt update
sudo apt install -y nginx apache2-utils

# Create a password file with one user (you'll be prompted for a password)
sudo htpasswd -c /etc/nginx/sentinel.htpasswd students

# Create the nginx site
sudo tee /etc/nginx/sites-available/sentinel-llm <<'NGINX'
server {
    listen 8080 default_server;
    server_name _;

    auth_basic "SENTINEL College LLM";
    auth_basic_user_file /etc/nginx/sentinel.htpasswd;

    location / {
        proxy_pass http://127.0.0.1:11434;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_read_timeout 600s;
        proxy_send_timeout 600s;
        proxy_buffering off;
    }
}
NGINX

sudo ln -s /etc/nginx/sites-available/sentinel-llm /etc/nginx/sites-enabled/
sudo rm -f /etc/nginx/sites-enabled/default
sudo nginx -t
sudo systemctl reload nginx
```

Now close the direct Ollama port to the network — only nginx should be exposed:

```bash
# Make Ollama listen only on localhost again (revert step 3 partly)
sudo systemctl edit ollama.service
# Change OLLAMA_HOST=0.0.0.0:11434 to OLLAMA_HOST=127.0.0.1:11434
sudo systemctl restart ollama

# Open port 8080 in the firewall, close 11434
sudo ufw allow from 10.0.0.0/8 to any port 8080 comment "SENTINEL LLM (nginx)"
sudo ufw deny 11434
sudo ufw reload
```

Students now configure SENTINEL to use the auth-protected endpoint:

```bash
export OLLAMA_HOST=http://students:<password>@<server-ip>:8080
```

The `user:password@` syntax in the URL is handled by SENTINEL's HTTP client. If you want HTTPS too, add Certbot — but on a campus LAN that's usually overkill.

## 10. Operational checklist

Things to verify after setup:

- [ ] `systemctl is-enabled ollama` → `enabled` (auto-starts on reboot)
- [ ] `systemctl is-active ollama` → `active`
- [ ] `curl http://localhost:11434/api/tags` returns model list on the server
- [ ] `curl http://<server-ip>:11434/api/tags` returns model list from a student laptop (or `:8080` if nginx is configured)
- [ ] Pulled model name matches `SENTINEL_OLLAMA_MODEL` env var on student side
- [ ] A test scan with `--private` completes and produces triaged findings (look for "Triage: N verified" in the scan summary)

## 11. Day-to-day operations

### Restart the LLM

```bash
sudo systemctl restart ollama
```

### Pull a new model

```bash
ollama pull qwen2.5-coder:32b-instruct-q4_K_M
# Available models: https://ollama.com/library
```

### See what's running

```bash
ollama ps              # Currently loaded models in VRAM
ollama list            # All downloaded models
nvidia-smi             # GPU utilisation (if applicable)
journalctl -u ollama -f  # Live logs
```

### Disk usage

Models live in `/usr/share/ollama/.ollama/models/`. Quick check:

```bash
du -sh /usr/share/ollama/.ollama/models/
```

To remove a model:

```bash
ollama rm <model-tag>
```

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `curl` from student laptop times out | Firewall, or Ollama bound to localhost only | Check `ss -tlnp \| grep 11434` on server; should show `0.0.0.0:11434` not `127.0.0.1:11434` |
| `curl` returns 403 Forbidden | `OLLAMA_ORIGINS` not set | Add `Environment="OLLAMA_ORIGINS=*"` in systemd override and restart |
| Model loads slowly (60s+) | First request loads model into VRAM | Normal; subsequent requests are fast. Increase `OLLAMA_MAX_LOADED_MODELS` to keep more models hot |
| "out of memory" on GPU | Model too large for VRAM | Switch to a smaller variant: `qwen2.5-coder:14b` or use `:q4_K_M` quantization |
| SENTINEL scan shows "Ollama: connection refused" | `OLLAMA_HOST` env var not exported in student shell | Run `echo $OLLAMA_HOST` to verify; re-source the rc file |
| SENTINEL hangs on triage forever | CPU-only inference is just slow | Run scan with `--no-triage` to skip Phase 3 for quick smoke tests, or move to a GPU server |
| Concurrent scans fail intermittently | `OLLAMA_NUM_PARALLEL` too low | Increase it in systemd override (try 8), restart Ollama |

## Appendix A — Quick reference for students

Three commands to start scanning against the college LLM:

```bash
# 1. Set the LLM endpoint (one-time per shell, or in your rc file)
export OLLAMA_HOST=http://<server-ip>:11434
export SENTINEL_OLLAMA_MODEL=qwen2.5-coder:14b

# 2. Run a scan with --private (forces local LLM, skips cloud providers)
cd ~/sentinel
poetry run sentinel scan corpus/your-app.apk --private

# 3. To verify the connection without running a full scan
poetry run sentinel status
```

## Appendix B — Alternative: vLLM (advanced)

If you want maximum throughput for concurrent users and have a GPU with 24 GB+ VRAM, vLLM is faster than Ollama but more involved. Skip this unless you actually have a concurrency problem.

```bash
pip install vllm

# Run as a service (replace with your model and tuning)
python -m vllm.entrypoints.openai.api_server \
    --model Qwen/Qwen2.5-Coder-14B-Instruct \
    --host 0.0.0.0 \
    --port 8000 \
    --max-model-len 8192 \
    --gpu-memory-utilization 0.9
```

vLLM exposes an OpenAI-compatible API at `http://<server-ip>:8000/v1/chat/completions`. To wire SENTINEL into this, you'd need to add a new provider class to `sentinel/llm/providers/` — beyond the scope of this guide. Stick with Ollama unless you have a real reason to switch.

## Appendix C — Hardware sizing cheat sheet for the bursar's office

| If you tell the budget owner: | They should buy: | Rough cost (2026) |
|---|---|---|
| "We need a CPU server for a final-year project" | Refurbished server with 16 cores, 64 GB RAM | $400–800 |
| "We want one student at a time with okay latency" | New tower with RTX 4060 Ti 16 GB, 32 GB RAM | $1,200–1,500 |
| "We want a class of 30 students to scan simultaneously" | Workstation with RTX 4090 24 GB or A5000, 64 GB RAM | $3,500–5,000 |
| "We want a teaching lab that runs the latest big models" | Server with dual RTX A6000 48 GB, 128 GB RAM | $10,000+ |

For a typical capstone/lab setting, the second tier ($1,200–1,500) is the sweet spot and runs `qwen2.5-coder:14b` comfortably with sub-3-second response times per finding.

---

**Questions for your teacher to answer before starting:**

1. What's the IP/hostname of the college server they're using?
2. Does it have a GPU? If yes, which one (`nvidia-smi` output)?
3. How much RAM? (`free -h`)
4. Which Linux distro and version? (`lsb_release -a`)
5. What's the campus network subnet so we can scope the firewall rule correctly?

Once your teacher answers these five questions, the exact commands to run can be customised — but the structure above stays the same.