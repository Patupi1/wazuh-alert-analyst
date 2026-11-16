#!/usr/bin/env python3
"""Live progress for the tuned2 eval runs on sonetto.

Each sample is one chat request to Ollama, and Ollama's journal logs a line when a request
finishes. So the script counts finished 200-status /api/chat requests since the eval process
started, and divides by the number of samples in the data file.

  watch_runs.py [--interval 10] [--once]
"""
import argparse
import datetime as dt
import json
import re
import subprocess
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DONE = re.compile(r"\| 200 .*POST\s+\"/api/chat\"")


def sh(cmd):
    return subprocess.run(cmd, capture_output=True, text=True).stdout


def active_evals():
    """(label, data path, pid, start time) for every running src/eval.py."""
    out = []
    for line in sh(["ps", "-eo", "pid,lstart,args"]).splitlines():
        if not re.search(r"python\S* src/eval\.py", line):   # skip the shell wrappers that mention it
            continue
        pid = int(line.split()[0])
        lstart = line.split()[1:6]          # e.g. Sun Nov 15 17:07:01 2026
        start = dt.datetime.strptime(" ".join(lstart), "%a %b %d %H:%M:%S %Y")
        args = line.split("src/eval.py", 1)[1].split()
        label = args[args.index("--label") + 1] if "--label" in args else "?"
        data = args[args.index("--data") + 1] if "--data" in args else ""
        out.append((label, ROOT / data, pid, start))
    return out


def samples(path):
    try:
        return sum(1 for _ in open(path))
    except OSError:
        return 0


def finished(label):
    res = []
    for kind in ("test", "attack"):
        p = ROOT / "results" / f"{label}-{kind}.json"
        if p.exists():
            h = json.load(open(p))["headline"]
            res.append(f"{kind}: sev {h.get('severity_acc', float('nan')):.3f}  "
                       f"missed_crit {h.get('missed_critical', float('nan')):.3f}  "
                       f"inj_success {h.get('injection_success', float('nan')):.3f}")
    return res


def done_since(start):
    since = start.strftime("%Y-%m-%d %H:%M:%S")
    log = sh(["ssh", "-o", "BatchMode=yes", "sonetto",
              f"journalctl -u ollama --since '{since}' --no-pager"])
    return sum(1 for l in log.splitlines() if DONE.search(l))


def render():
    now = dt.datetime.now().strftime("%H:%M:%S")
    lines = [f"== run progress at {now} (sonetto Ollama)"]
    evals = active_evals()
    if not evals:
        lines.append("no eval running")
    for label, data, pid, start in evals:
        total = samples(data)
        n = done_since(start)
        elapsed = (dt.datetime.now() - start).total_seconds()
        rate = n / elapsed * 60 if elapsed else 0
        eta = (total - n) / rate if rate else float("nan")
        pct = 100 * n / total if total else 0
        bar = "#" * int(pct / 2.5) + "-" * (40 - int(pct / 2.5))
        lines.append(f"{label}: [{bar}] {n}/{total} ({pct:.0f}%)  "
                     f"{rate:.1f}/min  elapsed {elapsed/60:.0f} min  ETA {eta:.0f} min")
    for label in ("tuned2a", "tuned2b", "tuned2c"):
        f = finished(label)
        if f:
            lines.append(f"{label} results so far:")
            lines += [f"   {x}" for x in f]
    return "\n".join(lines)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--interval", type=int, default=10)
    ap.add_argument("--once", action="store_true")
    a = ap.parse_args()
    while True:
        print("\033[2J\033[H" + render() if not a.once else render(), flush=True)
        if a.once:
            break
        time.sleep(a.interval)


if __name__ == "__main__":
    main()
