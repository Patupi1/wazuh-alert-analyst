#!/usr/bin/env python3
"""Turn generator output into trainer-ready datasets through CuratorKIT.

Step 1: raw.jsonl -> alpaca rows (instruction = fixed system prompt, input = alert
        batch JSON, output = target JSON). A sidecar keeps the ground-truth metadata.
Step 2: CuratorKIT cleans, schema-gates, scans for secrets, deduplicates near-identical
        batches (MinHash) and writes train/val/test with provenance files.

Usage: build_dataset.py data/synthetic/raw.jsonl data/curated [--attack data/synthetic/attack.jsonl]
"""
import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from prompt import INSTRUCTION, batch_json  # noqa: E402


def to_alpaca(src: Path, dst: Path, meta_out: Path):
    n = 0
    with open(src) as f, open(dst, "w") as g, open(meta_out, "w") as m:
        for line in f:
            r = json.loads(line)
            # The long system prompt is NOT stored per row (it would dominate MinHash dedup and
            # bloat the dataset); trainer and evaluator add prompt.SYSTEM as the system turn.
            g.write(json.dumps({"id": r["id"], "instruction": INSTRUCTION, "input": batch_json(r["input"]),
                                "output": json.dumps(r["target"], ensure_ascii=False)}, ensure_ascii=False) + "\n")
            m.write(json.dumps({"id": r["id"], **r["meta"], "target": r["target"]}, ensure_ascii=False) + "\n")
            n += 1
    return n


def curate(alpaca_path: Path, out_dir: Path, split: dict | None, name: str):
    from curatorkit import Curator, CuratorConfig
    cfg = CuratorConfig(
        name=name,
        dataset=str(alpaca_path),
        format="alpaca",
        max_tokens=6000,                       # a batch plus its answer is ~1.5k tokens; default cap is 2048
        schema_required_fields=["instruction", "input", "output"],
        dedup="minhash", minhash_threshold=0.9,
        clean=True,
        clean_transforms={"strip_html": False},  # keeps tag-shaped injection strings intact
        secrets_gate=True,
        output_split=split,
        output_split_near_dup_threshold=0.8,
        export_formats=["alpaca", "sharegpt"],
        output_dir=str(out_dir),
        write_hf_readme=True,
    )
    return Curator(cfg).run()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("out")
    ap.add_argument("--train", required=True, help="generator output; CuratorKIT splits it into train/val")
    ap.add_argument("--test", help="held-out generator output (different seed), curated whole")
    ap.add_argument("--attack", help="injection-only generator output, curated whole")
    a = ap.parse_args()
    out = Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    sets = [("train", a.train, {"train": 0.95, "val": 0.05}), ("test", a.test, None), ("attack", a.attack, None)]
    for name, src, split in sets:
        if not src:
            continue
        n = to_alpaca(Path(src), out / f"{name}_in.jsonl", out / f"{name}_meta.jsonl")
        res = curate(out / f"{name}_in.jsonl", out / name, split, f"wazuh-alert-analyst-{name}")
        passed = len(getattr(res, "passed", []) or [])
        print(f"{name}: {n} rows in -> {passed} passed; see {out / name / 'dataset_card.md'}")


if __name__ == "__main__":
    main()
