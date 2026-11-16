#!/usr/bin/env python3
"""Fresh held-out set for scoring any v3 (vault §15.5). Its only use is final scoring: never look at
a model's errors on it while designing training data, and do not publish it until it has been used
for a v3 decision. Output goes to data/holdout/ and data/curated_holdout/ (both git-ignored).

  make_holdout.py [--seed-v1 2027] [--seed-v2 2028]

Seeds 1, 2, 11 and 99 are taken by earlier sets. Writes ~300 v1-profile and ~150 v2-profile batches
(15 % injected), gives them distinct ids (ho1-*, ho2-*), drops any batch whose input matches an
input in an existing raw file, then curates the result with the same CuratorKIT settings as the test set.
"""
import argparse
import json
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))
from build_dataset import curate, to_alpaca  # noqa: E402
from prompt import batch_json  # noqa: E402

TAKEN = {1, 2, 11, 99}


def squash(s):
    return re.sub(r"\s+", "", s)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--seed-v1", type=int, default=2027)
    ap.add_argument("--seed-v2", type=int, default=2028)
    ap.add_argument("--n-v1", type=int, default=300)
    ap.add_argument("--n-v2", type=int, default=150)
    a = ap.parse_args()
    assert not {a.seed_v1, a.seed_v2} & TAKEN, "seed already used by an earlier set"
    raw_dir, cur_dir = ROOT / "data/holdout", ROOT / "data/curated_holdout"
    raw_dir.mkdir(parents=True, exist_ok=True)
    parts = [("ho1", "v1", a.seed_v1, a.n_v1), ("ho2", "v2", a.seed_v2, a.n_v2)]
    rows = []
    for prefix, profile, seed, n in parts:
        out = raw_dir / f"{prefix}_{profile}_seed{seed}.jsonl"
        subprocess.run([sys.executable, str(ROOT / "src/gen_alerts.py"), "--n", str(n), "--seed", str(seed),
                        "--inject-rate", "0.15", "--profile", profile, "--out", str(out)], check=True)
        for line in open(out):
            r = json.loads(line)
            r["id"] = f"{prefix}-{r['id'].split('-')[-1]}"
            r["meta"]["holdout_profile"] = profile
            rows.append(r)
    seen = set()
    for f in sorted((ROOT / "data/synthetic").glob("*.jsonl")):
        for line in open(f):
            seen.add(squash(batch_json(json.loads(line)["input"])))
    kept, clash, dup = [], 0, 0
    mine = set()
    for r in rows:
        k = squash(batch_json(r["input"]))
        if k in seen:
            clash += 1
        elif k in mine:
            dup += 1
        else:
            mine.add(k)
            kept.append(r)
    path = raw_dir / "holdout_raw.jsonl"
    with open(path, "w") as g:
        for r in kept:
            g.write(json.dumps(r, ensure_ascii=False) + "\n")
    print(f"{len(rows)} generated, {clash} match an existing input, {dup} duplicates -> {len(kept)} in {path}")
    cur_dir.mkdir(parents=True, exist_ok=True)
    n = to_alpaca(path, cur_dir / "holdout_in.jsonl", cur_dir / "holdout_meta.jsonl")
    res = curate(cur_dir / "holdout_in.jsonl", cur_dir / "holdout", None, "wazuh-alert-analyst-holdout")
    print(f"holdout: {n} rows in -> {len(getattr(res, 'passed', []) or [])} passed; {cur_dir / 'holdout'}")


if __name__ == "__main__":
    main()
