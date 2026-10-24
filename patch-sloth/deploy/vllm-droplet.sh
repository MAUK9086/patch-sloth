#!/usr/bin/env bash
# Serve the fine-tuned Qwen3-8B LoRA with vLLM on a DigitalOcean GPU Droplet (SPEC §12, Option A). [HUMAN] creates
# the Droplet (single GPU with >= 48 GB, e.g. L40S or RTX 6000; Ubuntu AI/ML-ready image with NVIDIA drivers), then:
#   scp -r <repo>/patch-sloth root@<ip>:/opt/patch-sloth      (or git clone the public repo)
#   ssh root@<ip>
#   cd /opt/patch-sloth && TINKER_API_KEY=... VLLM_API_KEY=... bash deploy/vllm-droplet.sh
# Steps: venv -> vLLM -> export the LoRA from Tinker to PEFT (scripts/12 export) -> vllm serve on :8000 behind
# VLLM_API_KEY. Then, from the Droplet or a laptop: python scripts/12_vllm_parity.py compare --base_url ...
# Billing runs while the Droplet exists, even powered off: DESTROY it after the demo window.
# Traffic to :8000 is plain HTTP with a bearer key; restrict it with a DO Cloud Firewall if the app's egress IP is
# known, and rotate VLLM_API_KEY after the demo.
set -euo pipefail

VLLM_VERSION="${VLLM_VERSION:-0.31.0}"      # released 2026-10-05; tinker-cookbook verified Qwen3-8B LoRA on 0.18
BASE_MODEL="Qwen/Qwen3-8B"
ADAPTER_DIR="${ADAPTER_DIR:-$PWD/peft_adapter}"
PORT="${PORT:-8000}"
# 0.5 of a 48 GB GPU = 24 GB: Qwen3-8B bf16 (~16.4 GB) + KV cache, leaving ~24 GB for TabPFN in the same session
GPU_MEM_UTIL="${GPU_MEM_UTIL:-0.5}"
: "${VLLM_API_KEY:?set VLLM_API_KEY (any long random string; the app uses the same value)}"

nvidia-smi --query-gpu=name,memory.total --format=csv

if [ ! -d .venv ]; then
  curl -LsSf https://astral.sh/uv/install.sh | sh
  export PATH="$HOME/.local/bin:$PATH"
  uv venv --python 3.11 .venv
fi
# shellcheck disable=SC1091
source .venv/bin/activate
export PATH="$HOME/.local/bin:$PATH"
uv pip install "vllm==${VLLM_VERSION}" tinker tinker-cookbook pandas pyarrow python-dotenv openai

# VERIFY the serve flags on the installed version before relying on them
HELP=$(vllm serve --help=all 2>/dev/null || true)
for flag in --enable-lora --lora-modules --max-lora-rank --max-model-len --api-key --gpu-memory-utilization; do
  grep -q -- "$flag" <<<"$HELP" || { echo "vllm serve has no $flag in this version: check 'vllm serve --help=all'"; exit 1; }
done
echo "vllm serve flags verified"

if [ ! -f "$ADAPTER_DIR/adapter_config.json" ]; then
  : "${TINKER_API_KEY:?set TINKER_API_KEY to download the LoRA (or copy peft_adapter/ here)}"
  python scripts/12_vllm_parity.py export --out "$ADAPTER_DIR"
fi
RANK=$(python -c "import json,sys; print(json.load(open(sys.argv[1]))['r'])" "$ADAPTER_DIR/adapter_config.json")
echo "LoRA rank $RANK"

# --max-lora-rank must be >= the adapter's rank (32 for the M3 run); 2048 tokens covers prompt (<= ~600) + 48 out
nohup vllm serve "$BASE_MODEL" \
  --enable-lora \
  --lora-modules "patchsloth=$ADAPTER_DIR" \
  --max-lora-rank "$RANK" \
  --max-model-len 2048 \
  --dtype bfloat16 \
  --gpu-memory-utilization "$GPU_MEM_UTIL" \
  --host 0.0.0.0 --port "$PORT" \
  --api-key "$VLLM_API_KEY" > vllm.log 2>&1 &
echo "vLLM starting (pid $!); log: $PWD/vllm.log"

for _ in $(seq 1 120); do
  if curl -fsS -H "Authorization: Bearer $VLLM_API_KEY" "http://127.0.0.1:$PORT/v1/models" 2>/dev/null | grep -q patchsloth; then
    echo "ready: http://<droplet-ip>:$PORT/v1 (model patchsloth)"
    exit 0
  fi
  sleep 10
done
echo "vLLM did not become ready in 20 min; see vllm.log"
exit 1
