#!/bin/bash
# watchdog_opencode.sh - Kill stuck `opencode run --agent sub04_synthesis` processes.
# The Python-side LLM_SYNTHESIS_TIMEOUT (600s) does not always fire (opencode may
# remain alive as an orphan holding pipe FDs). This watchdog kills any opencode
# sub04 process alive for more than LLM_SYNTHESIS_TIMEOUT + margin.
# Safe: a healthy run completes well under 600s; only stuck ones reach the kill age.
#
# Use: watchdog_opencode.sh   (typically run by launchd every 3 min)

export PATH="/usr/bin:/bin:/usr/sbin:/sbin:/usr/local/bin:/opt/homebrew/bin"

BATCH_LOG="/var/folders/nd/9pmplbnd40b4tzgy53f_8vyw0000gn/T/opencode/malradar_batch3.log"
WATCHDOG_LOG="/var/folders/nd/9pmplbnd40b4tzgy53f_8vyw0000gn/T/opencode/malradar_watchdog.log"
KILL_AGE=660   # LLM_SYNTHESIS_TIMEOUT(600) + 10% margin

now="$(date '+%Y-%m-%d %H:%M:%S')"

# Parse elapsed time "HH:MM[:SS]" or "MM:SS" or "D-HH:MM:SS" into seconds.
elapsed_sec() {
    local et="$1" d=0 h=0 m=0 s=0 rest parts
    if [[ "$et" == *-* ]]; then
        d="${et%%-*}"; rest="${et#*-}"
    else
        rest="$et"
    fi
    parts=(${rest//:/ })
    if [ "${#parts[@]}" -eq 3 ]; then
        h="${parts[0]}"; m="${parts[1]}"; s="${parts[2]}"
    elif [ "${#parts[@]}" -eq 2 ]; then
        m="${parts[0]}"; s="${parts[1]}"
    else
        s="${parts[0]}"
    fi
    echo $(( (d*86400) + (h*3600) + (m*60) + s ))
}

# Ensure the batch is actually running before killing anything
BATCH_PIDS=$(pgrep -f "run_pipeline.py /Users/yqh/Downloads/malradar-0" 2>/dev/null)
if [ -z "$BATCH_PIDS" ]; then exit 0; fi

# Find stuck opencode sub04 processes (one per APK normally)
for PID in $(pgrep -f "opencode run --agent sub04_synthesis" 2>/dev/null); do
    [ -z "$PID" ] && continue
    ET=$(ps -o etime= -p "$PID" 2>/dev/null | tr -d ' ')
    [ -z "$ET" ] && continue   # process already gone
    AGE=$(elapsed_sec "$ET")

    if [ "$AGE" -gt "$KILL_AGE" ]; then
        echo "$now — STUCK sub04 opencode PID=$PID age=${AGE}s (etime=$ET), kill -9" >> "$WATCHDOG_LOG"
        kill -9 "$PID" 2>>"$WATCHDOG_LOG"
        # Kill any descendant opencode processes too (child model servers)
        pkill -9 -P "$PID" 2>>"$WATCHDOG_LOG"
        echo "$now — killed PID=$PID (extract_risk_profile will fall back to Python synthesis)" >> "$WATCHDOG_LOG"
    fi
done

# Log a heartbeat every run for debugging (append only when something was done)
if [ -n "$(pgrep -f 'opencode run --agent sub04_synthesis' 2>/dev/null)" ]; then
    :
fi
exit 0