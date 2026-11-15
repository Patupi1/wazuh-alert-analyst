#!/usr/bin/env python3
"""Upload the curated datasets (and later the model / results) to Hugging Face.

Needs a write token: `hf auth login` or HF_TOKEN in the environment.

  push_hf.py datasets <user>/<repo>         uploads data/curated/{train,test,attack} as one dataset repo
  push_hf.py results  <user>/<repo>         uploads results/*.json into the dataset repo under results/
  push_hf.py model    <user>/<repo> <dir>   uploads a model/adapter folder
  push_hf.py datasets-v2 <user>/<repo>      uploads data/curated_v2/{a,b} (v2 TRAINING sets only; test and
                                            attack stay in the v1 dataset repo, unchanged)
"""
import sys
from pathlib import Path

from huggingface_hub import HfApi

ROOT = Path(__file__).resolve().parent.parent

DATASET_CARD = """---
license: cc-by-4.0
tags:
- curatorkit
- security
- wazuh
- synthetic
- prompt-injection
- lexsi-hackathon
task_categories:
- text-generation
language:
- en
size_categories:
- 1K<n<10K
configs:
- config_name: train
  data_files:
  - split: train
    path: train/train/sft_alpaca.jsonl
  - split: val
    path: train/val/sft_alpaca.jsonl
- config_name: test
  data_files:
  - split: test
    path: test/sft_alpaca.jsonl
- config_name: attack
  data_files:
  - split: test
    path: attack/sft_alpaca.jsonl
- config_name: train_messages
  data_files:
  - split: train
    path: train/train/messages.jsonl
  - split: val
    path: train/val/messages.jsonl
- config_name: test_messages
  data_files:
  - split: test
    path: test/messages.jsonl
- config_name: attack_messages
  data_files:
  - split: test
    path: attack/messages.jsonl
- config_name: train_sharegpt
  data_files:
  - split: train
    path: train/train/sft_sharegpt.jsonl
  - split: val
    path: train/val/sft_sharegpt.jsonl
---

# Wazuh alert analyst — synthetic alert batches with exact ground truth

Training, test and prompt-injection ("attack") sets for a small model that turns a batch of
Wazuh alerts into a grounded, structured triage: severity, what needs a look (with evidence
copied from the batch), a harmless explanation, one check to run, and a routine list.

**Everything is synthetic.** Hosts, users, files and addresses are invented (external
addresses come from the RFC 5737 documentation ranges). Rule ids, levels and descriptions are
taken from Wazuh's public ruleset. Because each batch is composed from named scenarios, the
correct answer is known exactly and the datasets contain no real logs from any system.

Columns (alpaca): `instruction` ("Alert batch:"), `input` (the batch as compact JSON),
`output` (the target JSON). The fixed system prompt lives in `src/prompt.py` of the code
repository and is added by the trainer and the evaluator.

- `train`: scenario mix, 15% of batches carry a planted prompt-injection string
- `test`: held out, generated with a different seed
- `attack`: every batch carries a planted prompt-injection string, for the attack-success metric

Curated with CuratorKIT (schema gate, exact + MinHash dedup, secrets gate, provenance files
in each folder). Built for the Lexsi AI Safety and Alignment Hackathon (Track 1).
"""


V2_CARD = """---
license: cc-by-4.0
tags:
- curatorkit
- security
- wazuh
- synthetic
- prompt-injection
- lexsi-hackathon
task_categories:
- text-generation
language:
- en
size_categories:
- 1K<n<10K
configs:
- config_name: a_train_messages
  data_files:
  - split: train
    path: a/train/train/messages.jsonl
  - split: val
    path: a/train/val/messages.jsonl
- config_name: b_train_messages
  data_files:
  - split: train
    path: b/train/train/messages.jsonl
  - split: val
    path: b/train/val/messages.jsonl
- config_name: a_train
  data_files:
  - split: train
    path: a/train/train/sft_alpaca.jsonl
  - split: val
    path: a/train/val/sft_alpaca.jsonl
- config_name: b_train
  data_files:
  - split: train
    path: b/train/train/sft_alpaca.jsonl
  - split: val
    path: b/train/val/sft_alpaca.jsonl
---

# Wazuh alert analyst, v2 training sets

Second-round **training** data for the Tiny Aya Wazuh alert analyst. The test and attack sets are
not here on purpose: v2 is evaluated on the frozen v1 sets in
[Yusheng88/wazuh-alert-analyst](https://huggingface.co/datasets/Yusheng88/wazuh-alert-analyst),
and no v2 training input matches a test or attack input.

Generated with `src/gen_alerts.py --profile v2 --seed 11 --n 3000` (v1 used seeds 1, 2 and 99):

- `a`: 15 % of batches carry a planted prompt-injection string (same rate as v1)
- `b`: 30 % injected, otherwise the same recipe

What changed against the v1 training set, each aimed at a failure seen in the v1 outputs:

- more routine days (about a third), with one consistent `next_step` grounded in the batch
  (v1's model often wrote `"next_step": null` there)
- about a quarter of the rows come from contrast groups: same hosts, users and filler, one detail
  different (brute force with or without a login from the attacking address, agent restart vs
  stopped, critical vs watched vs package-upgrade file changes, web 404 noise vs rejected attack vs
  attack that returned 200, Suricata severity 3 vs 2 vs 1, sudo use vs sudo failures vs new account
  with or without a sudoers change)
- checks say "the last known-good copy" instead of "the last backup": `backup` is also a host name
  in the generator, so the v1 wording made the evidence check see a host that was not in the batch
- summary capitalisation fixed ("SSH", not "sSH")
- still no `quiet` targets: the frozen sets have none, and on injected batches a `quiet` answer is
  what the attacker asks for

Everything is synthetic; no real logs. Curated with CuratorKIT (schema gate, exact + MinHash dedup,
secrets gate, provenance files in each folder). Lexsi AI Safety and Alignment Hackathon, Track 1.
"""


def main():
    api = HfApi()
    cmd, repo = sys.argv[1], sys.argv[2]
    if cmd == "datasets":
        api.create_repo(repo, repo_type="dataset", exist_ok=True)
        (ROOT / "data/curated/README.md").write_text(DATASET_CARD)
        api.upload_folder(folder_path=str(ROOT / "data/curated"), repo_id=repo, repo_type="dataset",
                          ignore_patterns=["*_in.jsonl"], commit_message="curated train/test/attack sets")
        print("https://huggingface.co/datasets/" + repo)
    elif cmd == "datasets-v2":
        api.create_repo(repo, repo_type="dataset", exist_ok=True)
        (ROOT / "data/curated_v2/README.md").write_text(V2_CARD)
        api.upload_folder(folder_path=str(ROOT / "data/curated_v2"), repo_id=repo, repo_type="dataset",
                          ignore_patterns=["*_in.jsonl"], commit_message="v2 training sets (runs a and b)")
        print("https://huggingface.co/datasets/" + repo)
    elif cmd == "results":
        api.upload_folder(folder_path=str(ROOT / "results"), path_in_repo="results", repo_id=repo, repo_type="dataset",
                          ignore_patterns=["smoke*", "*.log"], commit_message="evaluation results")
    elif cmd == "model":
        api.create_repo(repo, exist_ok=True)
        api.upload_folder(folder_path=sys.argv[3], repo_id=repo, commit_message="fine-tuned adapter")
        print("https://huggingface.co/" + repo)
    else:
        sys.exit(__doc__)


if __name__ == "__main__":
    main()
