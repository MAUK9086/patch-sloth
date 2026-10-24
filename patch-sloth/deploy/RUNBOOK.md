# GPU window (Option A): one Droplet session, at most 2.5 hours

One NVIDIA **L40S** GPU Droplet (48 GB; $1.57/hour on demand, billed per second, **still billed when powered off**
until destroyed; DigitalOcean pricing page, checked 2026-10-24). Worst case 2.5 h ≈ $3.93.

Order: start-time log → firewall → vLLM with the LoRA → parity → rebuild the M4 stack predictions (TabPFN) →
error analysis on the served model → latency → copy results to the laptop, commit, push → destroy → stop-time log.

vLLM is capped at half the GPU (`GPU_MEM_UTIL=0.5`, ~24 GB), so TabPFN can run in the same session without stopping
it. Everything runs **on the Droplet against localhost**. Port 8000 is open only to your laptop's IP, never to the
internet.

Conventions:
- **[laptop]** blocks run in Git Bash in `~/Downloads/TECH_PROJECTS/hacktoberFestweek3/patch-sloth`.
- **[droplet]** blocks run in the SSH session.
- Secrets are typed at hidden `read -s` prompts, so they never land in shell history or files.

**Hard stop.** At **T+2:15**, skip whatever is left and go straight to steps 9–10. The budget column is a guide.

| Step | What | Budget |
|---|---|---|
| 0 | Create the Droplet, log the start time | 0:00–0:10 |
| 1 | Firewall, clone, frozen data, secrets | 0:10–0:20 |
| 2 | vLLM + LoRA export (`deploy/vllm-droplet.sh`) | 0:20–0:45 |
| 3 | Parity, 300 CVEs (`12_vllm_parity.py compare`) | 0:45–0:55 |
| 4 | Rebuild the M4 stack predictions (TabPFN, seed 0) | 0:55–1:35 |
| 5 | Error analysis on the served model | 1:35–1:40 |
| 6 | Latency, 100 single-CVE requests | 1:40–1:50 |
| 7 | Copy results to the laptop | 1:50–2:00 |
| 8 | Commit and push (laptop) | 2:00–2:05 |
| 9 | Destroy the Droplet, log the stop time | 2:05–2:15 |

## Before the window (laptop)

- Have ready: `TINKER_API_KEY`, `TABPFN_TOKEN` (Prior Labs), and an SSH key added in DigitalOcean (**Settings →
  Security → SSH keys**). If TabPFN asks for Hugging Face access to the gated `Prior-Labs/tabpfn_3_5` weights, you
  will also need `HF_TOKEN` from the account that accepted those terms.
- The frozen evaluation data must be on the laptop: `patch-sloth/data/cves.parquet` (45 MB, data as of
  2026-10-21T14:41Z).

## 0. Create the Droplet and log the start (console + laptop)

Console: **Create → Droplets**. Choose **GPU Droplets**, a region with L40S capacity, then **NVIDIA L40S** (1 GPU).
For the image, pick the **AI/ML Ready** Ubuntu image (NVIDIA drivers preinstalled). Select your SSH key, name it
`patchsloth-gpu`, and click **Create GPU Droplet**. Copy its public IPv4.

```bash
# [laptop]
IP=203.0.113.10          # <- paste the Droplet's IPv4
echo "{\"event\": \"droplet_created\", \"utc\": \"$(date -u +%FT%TZ)\", \"plan\": \"gpu-l40s-1x\", \"usd_per_hour\": 1.57}" >> patch-sloth/results/do_gpu_session.jsonl
ssh -o StrictHostKeyChecking=accept-new root@$IP 'nvidia-smi --query-gpu=name,memory.total --format=csv'
```

## 1. Firewall, code, frozen data, secrets

```bash
# [droplet]  ssh root@<IP>
MY_IP=${SSH_CLIENT%% *}; echo "your laptop IP: $MY_IP"
ufw allow OpenSSH
ufw allow from "$MY_IP" to any port 8000 proto tcp
ufw --force enable && ufw status
git clone https://github.com/MAUK9086/patch-sloth /opt/patch-sloth
mkdir -p /opt/patch-sloth/patch-sloth/data
```

```bash
# [laptop]  frozen evaluation snapshot (the same rows final_table.md uses)
scp patch-sloth/data/cves.parquet root@$IP:/opt/patch-sloth/patch-sloth/data/cves.parquet
```

```bash
# [droplet]  secrets: typed at hidden prompts, exported for this shell only
cd /opt/patch-sloth/patch-sloth
read -rsp "TINKER_API_KEY: " TINKER_API_KEY; echo; export TINKER_API_KEY
read -rsp "TABPFN_TOKEN: " TABPFN_TOKEN; echo; export TABPFN_TOKEN
export VLLM_API_KEY=$(openssl rand -hex 24)
export VLLM_BASE_URL=http://127.0.0.1:8000/v1
ls -la data/cves.parquet
```

Optionally, if TabPFN later says it needs Hugging Face access:
`read -rsp "HF_TOKEN: " HF_TOKEN; echo; export HF_TOKEN`

## 2. vLLM with the LoRA (~20 min: installs, Qwen3-8B download, adapter export, start-up)

```bash
# [droplet]
cd /opt/patch-sloth/patch-sloth
GPU_MEM_UTIL=0.5 bash deploy/vllm-droplet.sh
# expected at the end: "vllm serve flags verified", "LoRA rank 32", "ready: ... (model patchsloth)"
source .venv/bin/activate
curl -s -H "Authorization: Bearer $VLLM_API_KEY" http://127.0.0.1:8000/v1/models | head -c 300; echo
```

If it fails, read `tail -50 vllm.log`. "max_lora_rank" errors mean the adapter rank is above `--max-lora-rank`; the
script reads it from `adapter_config.json`.

## 3. Parity: 300 test CVEs, vLLM vs Tinker (~5 min)

```bash
# [droplet]  (.venv active)
cd /opt/patch-sloth/patch-sloth
python scripts/12_vllm_parity.py compare --base_url "$VLLM_BASE_URL"
cat results/vllm_parity.json | head -40
```

The script writes `results/vllm_parity.json` with two modes: `tokens` (exact Tinker prompt tokens) and `chat` (what
the app sends). Each mode reports exact-text, vector and severity match, plus json_valid.

## 4. Rebuild the M4 per-row stack predictions (TabPFN-3.5 + LLM features, seed 0) (~30–40 min)

This uses a separate venv, so TabPFN's torch never touches vLLM's.

```bash
# [droplet]
cd /opt/patch-sloth/patch-sloth
export PATH="$HOME/.local/bin:$PATH"
uv venv --python 3.11 .venv-tabpfn
uv pip install --python .venv-tabpfn -r requirements.txt "tabpfn==9.2.0"
.venv-tabpfn/bin/python -c "import torch; print(torch.__version__, torch.cuda.is_available(), torch.cuda.mem_get_info())"
nohup .venv-tabpfn/bin/python scripts/12_m4_experiments.py --only tabpfn_llm_stack --seeds 0 > m4_rebuild.log 2>&1 &
tail -f m4_rebuild.log      # Ctrl-C to stop watching; done when it prints "done"
ls -la data/m4/tabpfn_llm_stack_s0.parquet
```

If the TabPFN licence check fails, check `echo ${TABPFN_TOKEN:+set}` prints `set`. On a CUDA out-of-memory error,
stop vLLM (`pkill -f "vllm serve"`), rerun the `nohup` line, and do step 6 after restarting vLLM with
`GPU_MEM_UTIL=0.5 bash deploy/vllm-droplet.sh` (that skips the install and export).

## 5. Error analysis on the served model (~2 min)

```bash
# [droplet]
cd /opt/patch-sloth/patch-sloth
.venv-tabpfn/bin/python scripts/10_error_analysis.py --model served
```

It compares the rebuilt predictions with the served model: band counts vs `serving_stack.json` (376/746/6,878)
and PR-AUC vs M4 seed 0 (0.6204), stopping if PR-AUC differs by ≥ 0.01. It then rewrites
`results/error_sample.md`. **Any tags already written in that file are overwritten.** Copy your tags out first, or
tag after this step.

## 6. Latency: 100 single-CVE requests (~3 min)

```bash
# [droplet]  (.venv active)
cd /opt/patch-sloth/patch-sloth && source .venv/bin/activate
python scripts/12_vllm_parity.py latency --base_url "$VLLM_BASE_URL" --n 100
```

This writes `results/vllm_latency.json`: p50/p95 seconds for one request at a time, through the app's
`VLLMBackend`, measured on the Droplet (server plus client, no internet hop).

## 7. Copy results to the laptop

```bash
# [laptop]
scp root@$IP:/opt/patch-sloth/patch-sloth/results/{vllm_parity.json,vllm_latency.json,error_sample.md,error_sample.json} patch-sloth/results/
mkdir -p patch-sloth/data/m4
scp root@$IP:/opt/patch-sloth/patch-sloth/data/m4/tabpfn_llm_stack_s0.parquet patch-sloth/data/m4/
scp root@$IP:/opt/patch-sloth/patch-sloth/{vllm.log,m4_rebuild.log} patch-sloth/results/ 2>/dev/null || true
```

## 8. Commit and push (laptop)

```bash
# [laptop]
cd patch-sloth
git add results/vllm_parity.json results/vllm_latency.json results/error_sample.md results/error_sample.json results/do_gpu_session.jsonl
git commit -m "GPU window: vLLM parity, latency, served-model error sample"
git push
cd ..
```

`data/m4/` is gitignored on purpose. The logs are only for you; don't commit `vllm.log` unless you have read it
(it is public once pushed).

## 9. Destroy the Droplet and log the stop time

Console: **Droplets → patchsloth-gpu → Destroy** (at the bottom of the left menu). Choose **Destroy this Droplet**,
type the name, and confirm. Powering off does **not** stop billing.

```bash
# [laptop]
echo "{\"event\": \"droplet_destroyed\", \"utc\": \"$(date -u +%FT%TZ)\"}" >> patch-sloth/results/do_gpu_session.jsonl
python - <<'EOF'
import json, datetime as dt
ev = [json.loads(l) for l in open("patch-sloth/results/do_gpu_session.jsonl")]
t = {e["event"]: dt.datetime.fromisoformat(e["utc"].replace("Z", "+00:00")) for e in ev}
h = (t["droplet_destroyed"] - t["droplet_created"]).total_seconds() / 3600
rate = next(e["usd_per_hour"] for e in ev if "usd_per_hour" in e)
print(f"GPU Droplet: {h:.2f} h x ${rate}/h = ${h * rate:.2f}")
EOF
git -C patch-sloth add results/do_gpu_session.jsonl && git -C patch-sloth commit -m "GPU window: Droplet start/stop times" && git -C patch-sloth push
```

Then check the console's **Billing** page later that day. The console figure is the one to quote in the post; the
computed number is an estimate.

## If the window can't happen

The draft keeps the fallback sentence (post/draft.md §7):
> "LoRA weights downloaded from Tinker in PEFT format; vLLM's chat template matches the training prompt (200/200
> checked). The vLLM conversion and end-to-end parity were not run, for lack of time."

The download step was done on the laptop (`results/peft_export.json`). The conversion for vLLM was not: it needs
Qwen3-8B's 16 GB of safetensors, and the laptop ran out of memory.

The error sample stays the HGB + LLM stack version.
