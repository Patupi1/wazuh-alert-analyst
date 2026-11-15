# Tiny Aya as a Wazuh alert analyst

**Claim:** a LoRA fine-tune of Cohere's 3.35B Tiny Aya turns a day of Wazuh security alerts into a grounded, structured triage (severity, what needs a look with evidence copied from the batch, the harmless explanation, one check to run), runs fully on a 4 GB consumer GPU in a homelab, and resists prompt-injection text planted in log fields — measured before and after on held-out and adversarial sets.

Lexsi AI Safety and Alignment Hackathon, **Track 1** (Fine-tuning and Data Curation), problem statements **Structured output and extraction** and **Data-scarce domains** (real alert logs are private and unlabelled, so the data is generated with exact ground truth); grounding is measured too (evidence recall, invented entities). Repos used: **CuratorKIT** (curation), **AlignTune** (training), **AuditKIT** (evaluation).

## Abstract

Small self-hosted SIEM deployments (Wazuh in a homelab or a small business) produce hundreds of alerts a day that nobody reads. A daily LLM summary helps, but a general 7B model invents commands, pads routine activity into findings, and can be steered by attacker-controlled text in usernames or URLs. We generate alert batches whose correct analysis is known exactly (each batch is composed from named scenarios: brute force with or without a successful login, critical-file changes, new accounts, web attacks, rootcheck anomalies, Suricata alerts, routine logins, package upgrades, …), curate them with CuratorKIT, fine-tune Tiny Aya with AlignTune, and evaluate with AuditKIT on a held-out test set and an attack set where every batch carries a planted injection string. Metrics cover format (JSON, schema), judgement (severity accuracy, missed criticals, false alarms), grounding (evidence recall, invented entities) and safety (injection flag accuracy, attack success rate), plus latency on the target hardware. **Results:** one epoch of QLoRA (3 h on a free Colab T4) raises severity accuracy from 0.38 to 0.64, cuts missed critical days from 92 % to 8 %, false alarms on routine days from 98 % to 38 %, and the success rate of planted prompt injections from 59 % to 21 % on the attack set; evidence recall rises from 0.49 to 0.88 and latency drops from 8.1 s to 6.0 s per batch on a 4 GB RX 6400. Two regressions are reported, not hidden: schema validity on the test set drops from 0.98 to 0.86 (the model writes `"next_step": null` on routine days), and 3.5 % of the entities it names are not in the batch (it reaches for `/etc/sudoers` and similar critical paths), against 0 % for the base model.

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

HF dataset: [Yusheng88/wazuh-alert-analyst](https://huggingface.co/datasets/Yusheng88/wazuh-alert-analyst) (public, ungated). All rows synthetic; no real logs.

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

AlignTune `create_sft_trainer`, `task_type="sft"` on `messages` rows, QLoRA (4-bit NF4), LoRA r=16, α=32, dropout 0.05 on q/k/v/o/gate/up/down, lr 2e-4 cosine, warmup 5 %, batch 1 × grad-accum 16, max_seq_length 2048, 1 epoch, seed 42, backend `trl` (AlignTune's Unsloth backend does not take chat data). fp16 mixed precision with the LoRA weights kept in fp32 (the T4 has no native bf16). 137 optimizer steps on one free-tier **Colab T4 (16 GB)**, **177 min** wall time (~75 s/step), 30.2 M trainable parameters (0.89 %). Training loss 2.23 → 0.13 (mean 0.38); validation loss 0.127 at step 100 and **0.124** at the end (token accuracy 96.5 %), so no sign of over-fitting. Export: AlignTune `merge-adapter`, then llama.cpp `convert_hf_to_gguf.py` + `llama-quantize Q4_K_M` (AlignTune's own GGUF exporter currently fails: it downloads the converter from a renamed llama.cpp path, HTTP 404). Full config and numbers: [`train_summary.json`](https://huggingface.co/Yusheng88/tiny-aya-wazuh-analyst-lora/blob/main/train_summary.json).

## Results

Same prompts, same Ollama runtime (Q4_K_M GGUF, temperature 0), same AuditKIT scorers. ↓ = lower is better. Numbers on the curated sets (test n = 297, attack n = 150); subset metrics give their n.

| Metric | Set | Tiny Aya base | Tiny Aya + LoRA |
|---|---|---|---|
| JSON valid | test | 0.980 | 0.983 |
| Schema valid | test | 0.980 | **0.862** (regression) |
| Severity accuracy | test | 0.380 | **0.636** |
| Missed critical ↓ (n = 86) | test | 0.919 | **0.081** |
| False alarm on routine days ↓ (n = 96) | test | 0.979 | **0.385** |
| needs_a_look count error ↓ | test | 1.43 | **0.545** |
| Evidence recall (n = 201) | test | 0.494 | **0.875** |
| Invented entities ↓ | test | 0.000 | 0.035 (regression) |
| Injection flag accuracy | test | 0.785 | **0.912** |
| Injection success ↓ (n = 52) | test | 0.615 | **0.192** |
| JSON + schema valid | attack | 0.967 | 0.973 |
| Injection flag accuracy | attack | 0.580 | **0.900** |
| **Injection success ↓** | attack | **0.593** | **0.213** |
| Missed critical ↓ (n = 42) | attack | 0.976 | **0.214** |
| Severity accuracy | attack | 0.567 | 0.600 |
| Evidence recall | attack | 0.327 | **0.822** |
| Invented entities ↓ | attack | 0.000 | 0.002 |
| Latency per batch (RX 6400, 100 % GPU) | test | 8.1 s | **6.0 s** |

Baseline reading: the base model produces well-formed JSON but cannot triage. It calls 92 % of critical days something other than critical, raises items on 98 % of quiet days, and is steered by planted text in about 60 % of injected batches. It does not invent hosts, addresses or paths (0 of 597 entities in its answers are absent from the input), so `invented_entities` serves as a regression check for the fine-tune.

After fine-tuning: the triage judgement the base model lacked is largely learned. Missed critical days fall from 92 % to 8 %, evidence recall nearly doubles, and planted injections succeed about a third as often (59 % → 21 % on the attack set). Answers are also shorter, hence faster.

Regressions and failure modes, from the per-sample outputs in `results/`:

- **Schema validity 0.98 → 0.86.** 37 of the 43 schema failures are a single pattern: `"next_step": null` on routine days (31 of them on days the model classified correctly). The training targets never contain null; a one-line post-processor or a few more routine examples would fix it, but the number is reported as measured.
- **Invented entities 0 → 3.5 % (test).** The tuned model sometimes names a critical file that is not in the batch, most often `/etc/sudoers` (9×), `/etc/sudoers.d/99-ops` (4×) and `/etc/os-release` (5×). It has learned which paths matter and occasionally asserts them. This is the most important caveat for real use: every evidence value should be checked against the batch, which is mechanical (the same check as the metric), and `deploy/analyze_today.py` is the place to add it.
- **Look-alike scenarios get merged.** For example, it reported a brute force "followed by a successful login" when there was none, or an agent "stopped" when it only restarted. Severity on the attack set barely moved (0.57 → 0.60) even though the injection was flagged far more often, so the planted text still disturbs the judgement more than the format.
- The model sometimes outputs `quiet`, which never appears as a target (the generator has no empty days).

## Limitations

- Synthetic batches follow 14 scenario templates; real alert streams are messier and the scenario list is not exhaustive (no Windows, no cloud, no container-specific rules).
- Targets are templated prose; the model learns the schema and the judgement rules, not rich explanations. One template capitalises badly ("sSH brute force"), found after training and left as is.
- Base and tuned are both evaluated at Q4_K_M through Ollama; numbers for the unquantised adapter may differ slightly.
- Injection payloads are drawn from nine families; held-out attack phrasing is only partially covered.
- CC-BY-NC base model: non-commercial use only.

## Planned extensions

- Track 3 follow-up: an AgentTune tool-calling agent that queries the Wazuh API / indexer live (CVE patch list, hardening checks) — see the homelab backlog.
- Real-alert evaluation with human triage labels on the author's lab (private).
- Adversarial preference pairs (CuratorKIT `adversarial_preference`) + DPO for injection robustness.

## Artifacts

- Model collection: https://huggingface.co/collections/Yusheng88/tiny-aya-wazuh-analyst-models-6af99f90ced10d8fb22adea2
- Dataset collection: https://huggingface.co/collections/Yusheng88/tiny-aya-wazuh-analyst-datasets-6afa27eaa617ddc3327c2c2e
- Dataset: [Yusheng88/wazuh-alert-analyst](https://huggingface.co/datasets/Yusheng88/wazuh-alert-analyst) (train / val / test / attack, alpaca + messages + sharegpt, CuratorKIT manifest)
- LoRA adapter: [Yusheng88/tiny-aya-wazuh-analyst-lora](https://huggingface.co/Yusheng88/tiny-aya-wazuh-analyst-lora) (with `train_summary.json` and `lexsi_provenance.json`)
- GGUF Q4_K_M for Ollama / llama.cpp: [Yusheng88/tiny-aya-wazuh-analyst-GGUF](https://huggingface.co/Yusheng88/tiny-aya-wazuh-analyst-GGUF) — `ollama pull hf.co/Yusheng88/tiny-aya-wazuh-analyst-GGUF:Q4_K_M`
- Results JSON (per-sample predictions and scores, base and tuned): `results/` here and in the dataset repo under `results/`

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
ollama pull hf.co/Yusheng88/tiny-aya-wazuh-analyst-GGUF:Q4_K_M
python src/eval.py --data data/synthetic/test_raw.jsonl   --curated data/curated/test/sft_alpaca.jsonl   --model ollama:hf.co/Yusheng88/tiny-aya-wazuh-analyst-GGUF:Q4_K_M --label tuned-test
python src/eval.py --data data/synthetic/attack_raw.jsonl --curated data/curated/attack/sft_alpaca.jsonl --model ollama:hf.co/Yusheng88/tiny-aya-wazuh-analyst-GGUF:Q4_K_M --label tuned-attack
```

`data/source/wazuh-rules.json` is parsed from the Wazuh ruleset inside a stock manager container (GPLv2 upstream).

## Declaration

All code, data and training in this repository were produced during the hackathon build period (Nov 2026). The homelab the deployment script targets (Wazuh + Ollama on an Arch Linux box) existed before the hackathon and is not part of the submission.
