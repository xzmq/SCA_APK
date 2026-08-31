#!/usr/bin/env python3
"""
OOM / agent-liveness monitor for the parallel batch pipeline.
Checks every N seconds:
  1. Agent process count (run_pipeline.py) stays at the expected N_AGENTS.
  2. Total RSS of pipeline processes (run_pipeline / jadx / opencode).
  3. macOS memory_pressure level.
  4. Recent jetsam / memorystatus kills in the unified log.
Alerts via osascript notification + `say` voice + /tmp/oom_alerts.log.
Usage: python3 oom_monitor.py [N_AGENTS]
"""
import os
import sys
import time
import subprocess
import datetime

N_AGENTS = int(sys.argv[1]) if len(sys.argv) > 1 else 3
CHECK_INTERVAL = int(os.environ.get("OOM_CHECK_INTERVAL", "20"))
ALERT_LOG = "/tmp/oom_alerts.log"
MASTER_LOG = "/tmp/parallel_batch_master.log"
RSS_WARN_MB = int(os.environ.get("OOM_RSS_WARN_MB", "12500"))
RSS_CRITICAL_MB = int(os.environ.get("OOM_RSS_CRITICAL_MB", "14000"))
INPUT_BASE = "/Users/yqh/Downloads"
OUTPUT_BASE = "/Users/yqh/knowledge_graph/output"
AGENT_PATTERN = "run_pipeline.py.*malradar"


def now():
    return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def log(msg):
    try:
        with open(ALERT_LOG, "a") as f:
            f.write(f"[{now()}] {msg}\n")
    except Exception:
        pass
    print(f"[OOM-MONITOR] {msg}", flush=True)


def alert(msg):
    log(f"!!! ALERT !!! {msg}")
    safe = msg.replace('"', "'")[:120]
    for _ in range(2):
        try:
            subprocess.run(
                ["osascript", "-e",
                 f'display notification "{safe}" with title "OOM / 进程告警"'],
                timeout=5, capture_output=True)
            break
        except Exception:
            time.sleep(1)
    try:
        subprocess.run(["say", "告警，检测到内存不足或进程异常退出"],
                       timeout=5, capture_output=True)
    except Exception:
        pass


def agent_count():
    try:
        out = subprocess.run(
            ["pgrep", "-f", AGENT_PATTERN],
            capture_output=True, text=True, timeout=10).stdout.strip()
        return len(out.split()) if out else 0
    except Exception:
        return 0


def pipeline_rss_mb():
    total = 0
    try:
        out = subprocess.run(
            ["ps", "axo", "rss,command"], capture_output=True, text=True,
            timeout=10).stdout
    except Exception:
        return 0
    for line in out.splitlines():
        parts = line.split(None, 1)
        if len(parts) < 2:
            continue
        try:
            rss = int(parts[0])
        except ValueError:
            continue
        if any(p in parts[1] for p in
               ("run_pipeline.py", "jadx-1.5.6-all.jar", "opencode run",
                "jadx_mcp_server.py")):
            total += rss
    return total // 1024


def memory_pressure_level():
    try:
        out = subprocess.run(
            ["memory_pressure"], capture_output=True, text=True, timeout=10).stdout
        if "critical" in out.lower():
            return "CRITICAL"
        if "warn" in out.lower():
            return "WARN"
        if out.strip():
            return "NORMAL"
    except Exception:
        pass
    return "UNKNOWN"


def batch_finished():
    try:
        with open(MASTER_LOG) as f:
            return "All directories processed" in f.read()
    except Exception:
        return False


def dir_done():
    for d in ("malradar-1", "malradar-2", "malradar-3"):
        out_dir = os.path.join(OUTPUT_BASE, d)
        in_dir = os.path.join(INPUT_BASE, d)
        if not os.path.isdir(out_dir) or not os.path.isdir(in_dir):
            continue
        try:
            done = len([f for f in os.listdir(out_dir) if f.endswith(".json")])
            total = len([f for f in os.listdir(in_dir) if f.endswith(".apk")])
        except Exception:
            continue
        if total and done >= total:
            return d
    return None


def recent_jetsam():
    try:
        out = subprocess.run(
            ["log", "show", "--style", "compact", "--last", "3m",
             "--predicate", 'eventMessage CONTAINS "jetsam" OR eventMessage CONTAINS "memorystatus" OR eventMessage CONTAINS "memory pressure"'],
            capture_output=True, text=True, timeout=60).stdout
        return out
    except Exception:
        return ""


def main():
    log(f"OOM monitor started: expecting {N_AGENTS} agents, "
        f"interval={CHECK_INTERVAL}s, warn>{RSS_WARN_MB}MB, crit>{RSS_CRITICAL_MB}MB")
    low_cycles = 0
    last_status = 0

    while True:
        time.sleep(CHECK_INTERVAL)
        t = time.time()

        if batch_finished():
            log("Batch finished normally — stopping monitor")
            break
        ddone = dir_done()
        if ddone:
            log(f"Directory {ddone} complete (agents may be moving on)")

        n = agent_count()
        rss = pipeline_rss_mb()
        mp = memory_pressure_level()

        # 1) Agent count below expected
        if n < N_AGENTS:
            low_cycles += 1
            if low_cycles >= 3:
                js = recent_jetsam()
                alert(f"Agent 进程异常：期望 {N_AGENTS} 个，实际 {n} 个"
                      + ("，近期存在 jetsam 事件！" if js.strip() else "（未发现 jetsam 日志）"))
                if js.strip():
                    log(f"Jetsam 日志(前1500字符):\n{js.strip()[:1500]}")
        else:
            low_cycles = 0

        # 2) Total RSS thresholds
        if rss >= RSS_CRITICAL_MB:
            alert(f"总 RSS {rss}MB 超过临界值 {RSS_CRITICAL_MB}MB！")
        elif rss >= RSS_WARN_MB:
            log(f"[WARN] 总 RSS {rss}MB 超过预警值 {RSS_WARN_MB}MB")

        # 3) macOS memory pressure
        if mp == "CRITICAL":
            alert(f"macOS memory_pressure = CRITICAL！")
        elif mp == "WARN":
            log(f"[WARN] macOS memory_pressure = WARN")

        # 4) Periodic status (~5 min)
        if t - last_status >= 300:
            last_status = t
            log(f"STATUS: agents={n}/{N_AGENTS}, total_rss={rss}MB, "
                f"mem_pressure={mp}")
        if mp == "CRITICAL":
            time.sleep(2)


if __name__ == "__main__":
    main()