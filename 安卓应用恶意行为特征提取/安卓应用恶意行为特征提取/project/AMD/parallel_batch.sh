#!/bin/bash
# Parallel batch processing for malradar-1/2/3 using multiple agents.
# Each agent runs run_pipeline.py on the SAME directory; per-APK file locks
# prevent duplicate work (first-come-first-served). Agents advance through
# the remaining directories together.
#
# Usage: parallel_batch.sh [N_AGENTS]
#   N_AGENTS: how many parallel agents (default 2, max safe 3 on 16GB)

set -u

N_AGENTS=${1:-2}
PYTHON=/Library/Frameworks/Python.framework/Versions/3.12/bin/python3
PROJECT_DIR=/Users/yqh/knowledge_graph/安卓应用恶意行为特征提取/project/AMD
INPUT_BASE=/Users/yqh/Downloads
OUTPUT_BASE=/Users/yqh/knowledge_graph/output

export LLM_SYNTHESIS_TIMEOUT=600
export PYTHONUNBUFFERED=1

# Limit per-JVVM heap so concurrent agents don't OOM. jadx-gui default is
# MaxRAMPercentage=70 (→ ~11GB heap on this 16GB Mac). With N agents we cap
# each Java process (jadx-gui + jadx CLI) to ~12% of RAM (~1.9GB heap each).
# NOTE: JAVA_OPTS is appended AFTER the jadx-gui script's defaults, so this
# overrides -XX:MaxRAMPercentage=70.0.
export JAVA_OPTS="${JADX_JAVA_OPTS:--XX:MaxRAMPercentage=12.0}"

cd "$PROJECT_DIR"

for dir in malradar-3; do
    INPUT_DIR="$INPUT_BASE/$dir"
    OUTPUT_DIR="$OUTPUT_BASE/$dir"
    if [ ! -d "$INPUT_DIR" ]; then
        echo "[!] Input directory not found: $INPUT_DIR"
        continue
    fi

    mkdir -p "$OUTPUT_DIR"
    HAVE=$(ls "$OUTPUT_DIR"/*.json 2>/dev/null | wc -l | tr -d ' ')
    TOTAL=$(find "$INPUT_DIR" -name "*.apk" 2>/dev/null | wc -l | tr -d ' ')
    echo "=================================================="
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] Starting PARALLEL: $dir ($HAVE/$TOTAL JSONs, $N_AGENTS agents)"
    echo "=================================================="

    PIDS=()
    for i in $(seq 0 $((N_AGENTS - 1))); do
        LOG="/tmp/parallel_${dir}_agent${i}.log"
        echo "[$(date '+%Y-%m-%d %H:%M:%S')] Agent $i -> $LOG"
        AGENT_ID=$i $PYTHON run_pipeline.py "$INPUT_DIR" "$OUTPUT_DIR" > "$LOG" 2>&1 &
        PIDS+=($!)
    done

    FAIL=0
    for pid in "${PIDS[@]}"; do
        wait "$pid" || FAIL=1
    done

    JSON_COUNT=$(ls "$OUTPUT_DIR"/*.json 2>/dev/null | wc -l | tr -d ' ')
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] Finished PARALLEL: $dir (fail=$FAIL, JSONs=$JSON_COUNT)"
done

echo "=================================================="
echo "[$(date '+%Y-%m-%d %H:%M:%S')] All directories processed in parallel!"
echo "=================================================="