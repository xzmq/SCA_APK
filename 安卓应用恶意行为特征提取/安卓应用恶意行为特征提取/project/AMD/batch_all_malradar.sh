#!/bin/bash
# Sequential batch processing for malradar-0 (finish remaining), then 1, 2, 3
# Each directory is processed in order; skips existing JSONs automatically

PYTHON=/Library/Frameworks/Python.framework/Versions/3.12/bin/python3
PROJECT_DIR=/Users/yqh/knowledge_graph/安卓应用恶意行为特征提取/project/AMD
INPUT_BASE=/Users/yqh/Downloads
OUTPUT_BASE=/Users/yqh/knowledge_graph/output

export LLM_SYNTHESIS_TIMEOUT=600

cd "$PROJECT_DIR"

for dir in malradar-0 malradar-1 malradar-2 malradar-3; do
    echo "=================================================="
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] Starting: $dir"
    echo "=================================================="
    
    INPUT_DIR="$INPUT_BASE/$dir"
    OUTPUT_DIR="$OUTPUT_BASE/$dir"
    LOG_FILE="/tmp/batch_${dir}.log"
    
    if [ ! -d "$INPUT_DIR" ]; then
        echo "[!] Input directory not found: $INPUT_DIR"
        continue
    fi
    
    mkdir -p "$OUTPUT_DIR"
    
    $PYTHON run_pipeline.py "$INPUT_DIR" "$OUTPUT_DIR" > "$LOG_FILE" 2>&1
    EXIT_CODE=$?
    
    JSON_COUNT=$(ls "$OUTPUT_DIR"/*.json 2>/dev/null | wc -l)
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] Finished: $dir (exit=$EXIT_CODE, JSONs=$JSON_COUNT)"
done

echo "=================================================="
echo "[$(date '+%Y-%m-%d %H:%M:%S')] All directories processed!"
echo "=================================================="
