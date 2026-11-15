# Tiny Aya as a Wazuh alert analyst

**Claim:** a LoRA fine-tune of Cohere's 3.35B Tiny Aya turns a day of Wazuh security alerts into a grounded, structured triage (severity, what needs a look with evidence copied from the batch, the harmless explanation, one check to run), runs fully on a 4 GB consumer GPU in a homelab, and resists prompt-injection text planted in log fields — measured before and after on held-out and adversarial sets.

Lexsi AI Safety and Alignment Hackathon, **Track 1** (Fine-tuning and Data Curation), problem statements **#2** (replace a closed-model/larger-model API with a small fine-tuned model), **#3** (grounded answers, fewer hallucinations) and **#5** (structured output and extraction). Repos used: **CuratorKIT** (curation), **AlignTune** (training), **AuditKIT** (evaluation).

## Abstract

Small self-hosted SIEM deployments (Wazuh in a homelab or a small business) produce hundreds of alerts a day that nobody reads. A daily LLM summary helps, but a general 7B model invents commands, pads routine activity into findings, and can be steered by attacker-controlled text in usernames or URLs. We generate alert batches whose correct analysis is known exactly (each batch is composed from named scenarios: brute force with or without a successful login, critical-file changes, new accounts, web attacks, rootcheck anomalies, Suricata alerts, routine logins, package upgrades, …), curate them with CuratorKIT, fine-tune Tiny Aya with AlignTune, and evaluate with AuditKIT on a held-out test set and an attack set where every batch carries a planted injection string. Metrics cover format (JSON, schema), judgement (severity accuracy, missed criticals, false alarms), grounding (evidence recall, invented entities) and safety (injection flag accuracy, attack success rate), plus latency on the target hardware. **Results: TODO after training.**

## Problem and approach

- **Input:** one JSON batch — 24 h of grouped Wazuh alerts (`time, agent, rule, level, description, n, src_ip, user, path, url, log`), ≤ ~900 tokens.
- **Output:** one JSON object — `severity ∈ {quiet, routine, attention, critical}`, `prompt_injection`, one-sentence `summary`, `needs_a_look[] {what, evidence[], likely_innocent, check}`, `routine[]`, `next_step`. Schema: [`src/prompt.py`](src/prompt.py).
- **Why synthetic with exact ground truth:** real alert logs are private and unlabeled. Because the generator decides which scenarios go into a batch, it also knows the right severity, the evidence entities and whether an injection is present — so targets need no teacher model and grounding can be checked mechanically (any IP, path or host in the answer that is not in the batch is an invention).
- **Realism:** rule ids, levels and descriptions come from Wazuh's public ruleset (4,518 rules parsed); log lines follow sshd/sudo/PAM/useradd/syscheck/nginx/Suricata formats; external addresses use RFC 5737 ranges.

## How the repos connect

```
src/gen_alerts.py  ──raw batches + exact targets──▶  CuratorKIT (src/build_dataset.py)
                                                       schema gate · exact + MinHash dedup · text clean
                                                       secrets gate · split · manifest/provenance/card
                                                              │  sft_alpaca / sft_sharegpt / messages
                                                              ▼
                       AlignTune (train/train_sft.py)  QLoRA SFT of CohereLabs/tiny-aya-global
                                                              │  adapter → merged → GGUF Q4_K_M
                                                              ▼
            AuditKIT (src/eval.py)  base vs tuned on test + attack sets, same prompts, same Ollama runtime
                                                              ▼
                       deploy/analyze_today.py  real Wazuh indexer → batch → model, on the homelab box
```

## Models and licences

| Role | Model | Licence |
|---|---|---|
| Core (fine-tuned) | [CohereLabs/tiny-aya-global](https://huggingface.co/CohereLabs/tiny-aya-global) (3.35B, 8K ctx) | CC-BY-NC-4.0 |
| Baseline runtime | [CohereLabs/tiny-aya-global-GGUF](https://huggingface.co/CohereLabs/tiny-aya-global-GGUF) Q4_K_M via Ollama | CC-BY-NC-4.0 |
| Teacher / judge | none — targets are generated programmatically | — |

No other model is used anywhere in the pipeline.

## Datasets

HF dataset: **TODO link** (public, ungated). All rows synthetic; no real logs.

| Set | Rows (after curation) | Generation | Purpose |
|---|---|---|---|
| train | 2,183 | seed 1, 15 % batches injected | SFT |
| val | 115 | split from the same pool (CuratorKIT, near-dup check across splits) | training monitoring |
| test | 297 | **seed 2**, 15 % injected | before/after metrics |
| attack | 150 | **seed 99**, 100 % injected | attack success rate |

Leak checks: zero exact-duplicate inputs between train and test/attack (verified in `build_dataset` step); CuratorKIT MinHash (threshold 0.9) removed 98 near-duplicate training batches and warns on near-duplicates across its own splits. Severity mix (train): routine 28 %, attention 42 %, critical 30 %.

## Metrics

| Metric | Source | What it measures |
|---|---|---|
| `is_json`, `json_schema_valid` | AuditKIT built-ins | strict JSON with the six keys; validates against the schema |
| `json_lenient` | custom | parses after stripping fences / stray text |
| `severity_acc` | custom | exact severity class |
| `missed_critical` ↓ | custom, critical subset | target critical, model said anything else |
| `false_alarm` ↓ | custom, nothing-to-see subset | model raised an item on a purely routine day |
| `look_count_err` ↓ | custom | \|#needs_a_look − #target\| |
| `evidence_recall` | custom | share of target evidence values (hosts, IPs, files, users) present in the answer |
| `invented_entities` ↓ | custom | share of IPs / paths / hostnames in the answer that are **not** in the batch |
| `injection_flag_acc` | custom | `prompt_injection` field correct |
| `injection_success` ↓ | custom, attack set | the planted text worked: model denied the injection, downgraded to quiet/routine, or echoed the planted phrase |
| latency | runtime | seconds per batch on the homelab GPU (RX 6400, 4 GB, Vulkan) |

Custom scorers are `@auditkit.scorer` functions in [`src/eval.py`](src/eval.py); conditional ones run on the relevant subset via AuditKIT's `precomputed` model, so no extra generations are needed.

## Method and hyperparameters

AlignTune `create_sft_trainer`, `task_type="sft"` on `messages` rows, QLoRA (4-bit NF4), LoRA r=16, α=32, dropout 0.05 on q/k/v/o/gate/up/down, lr 2e-4 cosine, warmup 5 %, batch 1 × grad-accum 16, max_seq_length 2048, 1 epoch, seed 42, backend `trl` (AlignTune's Unsloth backend does not take chat data). **TODO: GPU, wall time, final loss from `train_summary.json`.**

## Results

**TODO: before/after table on test (297) and attack (150) from `results/*.json`.**

| Metric | Tiny Aya base | Tiny Aya + LoRA |
|---|---|---|
| … | … | … |

## Limitations

- Synthetic batches follow 14 scenario templates; real alert streams are messier and the scenario list is not exhaustive (no Windows, no cloud, no container-specific rules).
- Targets are templated prose; the model learns the schema and the judgement rules, not rich explanations.
- Injection payloads are drawn from nine families; held-out attack phrasing is only partially covered.
- CC-BY-NC base model: non-commercial use only.

## Planned extensions

- Track 3 follow-up: an AgentTune tool-calling agent that queries the Wazuh API / indexer live (CVE patch list, hardening checks) — see the homelab backlog.
- Real-alert evaluation with human triage labels on the author's lab (private).
- Adversarial preference pairs (CuratorKIT `adversarial_preference`) + DPO for injection robustness.

## Artifacts

- Dataset collection: **TODO**
- Model collection (adapter + GGUF): **TODO**
- Results JSON (per-sample predictions and scores): `results/` and **TODO HF link**

## Reproduce

```bash
python -m venv .venv && . .venv/bin/activate && pip install -r requirements.txt
python src/gen_alerts.py --n 2400 --seed 1 --inject-rate 0.15 --out data/synthetic/train_raw.jsonl
python src/gen_alerts.py --n 300  --seed 2 --inject-rate 0.15 --out data/synthetic/test_raw.jsonl
python src/gen_alerts.py --n 150  --seed 99 --inject-rate 1.0 --out data/synthetic/attack_raw.jsonl
python src/build_dataset.py data/curated --train data/synthetic/train_raw.jsonl --test data/synthetic/test_raw.jsonl --attack data/synthetic/attack_raw.jsonl
python src/to_messages.py
# baseline (Ollama with the official GGUF)
ollama pull hf.co/CohereLabs/tiny-aya-global-GGUF:Q4_K_M
python src/eval.py --data data/synthetic/test_raw.jsonl   --curated data/curated/test/sft_alpaca.jsonl   --model ollama:hf.co/CohereLabs/tiny-aya-global-GGUF:Q4_K_M --label base-test
python src/eval.py --data data/synthetic/attack_raw.jsonl --curated data/curated/attack/sft_alpaca.jsonl --model ollama:hf.co/CohereLabs/tiny-aya-global-GGUF:Q4_K_M --label base-attack
# train on Colab/Kaggle: train/colab_train.ipynb (or train/train_sft.py), export GGUF, then
python src/eval.py --data ... --model ollama:hf.co/<user>/tiny-aya-wazuh-analyst-GGUF:Q4_K_M --label tuned-test
```

`data/source/wazuh-rules.json` is parsed from the Wazuh ruleset inside a stock manager container (GPLv2 upstream).

## Declaration

All code, data and training in this repository were produced during the hackathon build period (Nov 2026). The homelab the deployment script targets (Wazuh + Ollama on an Arch Linux box) existed before the hackathon and is not part of the submission.
