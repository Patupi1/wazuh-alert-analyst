#!/usr/bin/env python3
"""Progress of the Q8_0 evaluation (TODO #28): which phase, samples done, latency, ETA, and the
curated headline next to v1 Q4_K_M once a phase is scored.

  watch_q8.py [--interval 15] [--once]
"""
import argparse
import datetime as dt
import json
import re
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from watch_runs import ROOT, active_evals, sh  # noqa: E402

PHASES = [("tuned-q8-test", 300), ("tuned-q8-attack", 150)]
REQ = re.compile(r"\| 200 \|\s*([\d.]+)(m?s) \|.*POST\s+\"/api/chat\"")
SHOW = [("missed_critical", "missed critical ↓"), ("severity_acc", "severity acc"), ("json_schema_valid", "schema valid"),
        ("invented_entities", "invented ↓"), ("injection_success", "injection success ↓")]


def latencies(start):
    log = sh(["ssh", "-o", "BatchMode=yes", "sonetto",
              f"journalctl -u ollama --since '{start:%Y-%m-%d %H:%M:%S}' --no-pager"])
    return [float(v) / (1000 if unit == "ms" else 1) for v, unit in REQ.findall(log)]


def headline(label):
    p = ROOT / "results" / f"{label}.json"
    return json.load(open(p))["headline"] if p.exists() else None


def render():
    L = [f"== Q8_0 eval at {dt.datetime.now():%H:%M:%S}"]
    running = {lab: start for lab, _, _, start in active_evals()}
    for label, total in PHASES:
        if label in running:
            lat = latencies(running[label])
            n = len(lat)
            mean = sum(lat) / n if n else float("nan")
            eta = (total - n) * mean / 60 if n else float("nan")
            pct = 100 * n / total
            bar = "#" * int(pct / 2.5) + "-" * (40 - int(pct / 2.5))
            L.append(f"{label:18s} [{bar}] {n}/{total} ({pct:.0f}%)  {mean:.1f} s/batch (Q4_K_M: 6.0)  ETA {eta:.0f} min")
        elif headline(label):
            L.append(f"{label:18s} done")
        else:
            L.append(f"{label:18s} waiting")
    for kind in ("test", "attack"):
        q8, q4 = headline(f"tuned-q8-{kind}-curated"), headline(f"tuned-{kind}-curated")
        if q8 and q4:
            L.append(f"\n{kind} (curated)        Q4_K_M    Q8_0")
            L += [f"  {name:20s} {q4.get(k, float('nan')):7.3f}  {q8.get(k, float('nan')):7.3f}" for k, name in SHOW if k in q8]
    if not running and all(headline(f"tuned-q8-{k}-curated") for k in ("test", "attack")):
        L.append("\nall phases finished")
    elif not running:
        L.append("\nno eval.py running (between phases, or stopped: see results/tuned-q8-eval.log)")
    return "\n".join(L)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--interval", type=int, default=15)
    ap.add_argument("--once", action="store_true")
    a = ap.parse_args()
    while True:
        out = render()
        print(out if a.once else "\033[2J\033[H" + out, flush=True)
        if a.once:
            break
        time.sleep(a.interval)


if __name__ == "__main__":
    main()
