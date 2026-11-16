#!/usr/bin/env python3
"""Apply the deterministic brute-force-login escalation (src/postprocess.py) to saved model outputs,
so a model can be rescored offline with `src/eval.py --from-results` (no new generations).

  apply_rule.py results/tuned-test.json data/synthetic/test_raw.jsonl results/tuned-rule-test-in.json

Only outputs the rule changes are rewritten (re-serialised as strict JSON); everything else is kept
byte for byte. Unparseable outputs are left alone. Prints how many outputs changed and how many of
those were not strict JSON before, since re-serialising can lift the is_json / schema metrics.
"""
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))
from eval import lenient_json  # noqa: E402
from postprocess import escalate  # noqa: E402

src, data, dst = sys.argv[1:4]
batches = {}
for line in open(data):
    r = json.loads(line)
    batches[r["id"]] = r["input"]
res = json.load(open(src))
changed = nonstrict = sev_changed = 0
for p in res["predictions"]:
    raw = p["raw_output"]
    ans = lenient_json(raw)
    if ans is None:
        continue
    ans, notes = escalate(batches[p["sample_id"]], ans)
    if notes:
        changed += 1
        sev_changed += any(n.startswith("severity") for n in notes)
        try:
            json.loads(raw)
        except Exception:
            nonstrict += 1
        p["raw_output"] = json.dumps(ans, ensure_ascii=False)
json.dump(res, open(dst, "w"), indent=1, default=str)
print(f"{src}: {changed} outputs changed ({sev_changed} severity raised, {nonstrict} were not strict JSON before) -> {dst}")
