#!/bin/bash
# monitor_progress.sh - Snapshot batch progress every run. Scheduled via cron every 2h.
# Usage: monitor_progress.sh  (no args)

export PATH="$HOME/Library/Android/sdk/platform-tools:$PATH"

OUTPUT_DIR="/Users/yqh/knowledge_graph/output/malradar-0"
BATCH_LOG="/var/folders/nd/9pmplbnd40b4tzgy53f_8vyw0000gn/T/opencode/malradar_batch3.log"
PROGRESS_LOG="/var/folders/nd/9pmplbnd40b4tzgy53f_8vyw0000gn/T/opencode/malradar_progress.log"

TS="$(date '+%Y-%m-%d %H:%M:%S')"
JSONS=$(ls "$OUTPUT_DIR"/*.json 2>/dev/null | wc -l | tr -d ' ')
PIDS=$(pgrep -f "run_pipeline.py /Users/yqh/Downloads/malradar-0" | tr '\n' ' ' | sed 's/ $//')
SKIPS=$(grep -c 'SKIP' "$BATCH_LOG" 2>/dev/null); SKIPS=${SKIPS:-0}
DONE=$(grep -c 'APK processing complete' "$BATCH_LOG" 2>/dev/null); DONE=${DONE:-0}
PACKED=$(grep -c 'Starting dynamic unpack: packer=' "$BATCH_LOG" 2>/dev/null); PACKED=${PACKED:-0}
DYN_OK=$(grep -c '\[F-E-full\] Success' "$BATCH_LOG" 2>/dev/null); DYN_OK=${DYN_OK:-0}
STATIC_OK=$(grep -c '\[F-E-lite\] Success' "$BATCH_LOG" 2>/dev/null); STATIC_OK=${STATIC_OK:-0}

EMU=0
if command -v adb >/dev/null 2>&1; then
    EMU=$(adb devices 2>/dev/null | grep -c '^emulator-.*device' || echo 0)
fi

CUR=""
CUR=$(grep -E '^\[[0-9]+/1000\] (Processing|SKIP)' "$BATCH_LOG" 2>/dev/null | tail -1 | sed 's/^/      /')

cat >> "$PROGRESS_LOG" <<EOF
----- $TS -----
  JSONs:       $JSONS / 1000
  Batch PID:   ${PIDS:-NONE}
  Skips:       $SKIPS   Done: $DONE (this batch)
  Packed dyn:  $PACKED   F-E-full OK: $DYN_OK   F-E-lite OK: $STATIC_OK
  Emulator:    ${EMU:-0} device(s)
$CUR
EOF