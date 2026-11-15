#!/usr/bin/env python3
"""Curated alpaca rows -> chat `messages` rows with the exact system/user text the evaluator uses.

Writes messages.jsonl next to every sft_alpaca.jsonl under data/curated (or the folder given as argument).
Training on these rows (AlignTune task_type="chat_completion") means the fine-tuned model is
trained and evaluated on byte-identical prompts.
"""
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from prompt import INSTRUCTION, SYSTEM  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent

# optional argument: another curated folder (v2 training sets live outside the frozen data/curated)
BASE = Path(sys.argv[1]).resolve() if len(sys.argv) > 1 else ROOT / "data/curated"

for src in sorted(BASE.rglob("sft_alpaca.jsonl")):
    dst = src.with_name("messages.jsonl")
    n = 0
    with open(src) as f, open(dst, "w") as g:
        for line in f:
            r = json.loads(line)
            user = (r.get("instruction") or INSTRUCTION) + "\n" + r["input"]
            g.write(json.dumps({"messages": [{"role": "system", "content": SYSTEM},
                                             {"role": "user", "content": user},
                                             {"role": "assistant", "content": r["output"]}]}, ensure_ascii=False) + "\n")
            n += 1
    print(f"{dst.relative_to(ROOT)}: {n} rows")
