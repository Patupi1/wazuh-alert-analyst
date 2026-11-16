# Tiny Aya as a Wazuh alert analyst

**Claim:** a LoRA fine-tune of Cohere's 3.35B Tiny Aya turns a day of Wazuh security alerts into a grounded, structured triage (severity, what needs a look with evidence copied from the batch, the harmless explanation, one check to run), runs fully on a 4 GB consumer GPU in a homelab, and resists prompt-injection text planted in log fields — measured before and after on held-out and adversarial sets.

> **Update (Nov 15, late):** the recommended model is now **v3** ([Yusheng88/tiny-aya-wazuh-analyst-GGUF-v3](https://huggingface.co/Yusheng88/tiny-aya-wazuh-analyst-GGUF-v3)): v1's scenario mix plus v2's data fixes. It keeps v1's critical-day recall and halves attack-set injection success (0.213 → 0.113). A Q8_0 export also showed that Q4_K_M quantization was costing v1 most of its false-alarm and schema performance. See [v3 (current model)](#v3-current-model) and [Quantization](#quantization-q4_k_m-vs-q8_0). The v1 numbers below are unchanged.

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

## v2 experiment (not submitted)

After submitting v1, four more training runs tried to fix its weaknesses. All were scored on the same frozen test and attack sets as v1 (byte-identical, checksummed). None was submitted: each improved format, grounding and injection resistance, but every one missed critical days two to three times as often as v1.

**What changed in the training data** (`src/gen_alerts.py --profile v2`; the default profile still reproduces the v1 files byte for byte; seed 11, ~2,600 rows per run after curation, published as [Yusheng88/wazuh-alert-analyst-v2](https://huggingface.co/datasets/Yusheng88/wazuh-alert-analyst-v2)):

- more routine days (about a third) with one grounded `next_step`, never null
- contrast groups (about a quarter of the rows): the same hosts, users and filler with one detail changed (brute force with or without a login from the attacking address, agent restart vs stopped, critical vs watched vs package-upgrade file changes, web 404 noise vs rejected attack vs attack that returned 200, Suricata severity 3 vs 2 vs 1, sudo use vs failures vs a new account with or without a sudoers change)
- checks say "the last known-good copy" instead of "the last backup", and the summary keeps "SSH" capitalised
- still no `quiet` targets (the frozen sets have none, and on injected batches `quiet` is what the attacker asks for)

| Run | Change | Val loss |
|---|---|---|
| v2a | v2 data, 15 % injected | 0.118 |
| v2b | v2 data, 30 % injected | 0.120 |
| v2c | v2a's batches with the target keys reordered so findings come before severity | 0.118 |
| v2d | v2b plus more brute-force-success and rootcheck examples | 0.119 |

Hyperparameters as v1 except batch 2 × grad-accum 8 (same effective batch of 16), 1 epoch, ~25 min each on a Colab L4. Adapters and GGUFs: `Yusheng88/tiny-aya-wazuh-analyst-lora-v2{a,b,c,d}` and `Yusheng88/tiny-aya-wazuh-analyst-GGUF-v2{a,b,c,d}`. Per-sample results: `results/tuned2*-*.json`.

Curated sets, Q4_K_M through the same Ollama runtime. ↓ = lower is better.

| Metric | Set | v1 | v2a | v2b | v2c | v2d |
|---|---|---|---|---|---|---|
| Schema valid | test | 0.862 | 0.946 | 0.923 | 0.936 | **0.987** |
| Severity accuracy | test | 0.636 | 0.754 | **0.761** | 0.724 | 0.714 |
| **Missed critical ↓** | test | **0.081** | 0.384 | 0.244 | 0.477 | 0.244 |
| False alarm ↓ | test | 0.385 | 0.219 | 0.229 | **0.010** | 0.396 |
| Evidence recall | test | 0.875 | 0.887 | 0.880 | 0.830 | **0.918** |
| Invented entities ↓ | test | 0.035 | 0.007 | 0.028 | **0.002** | 0.018 |
| Injection success ↓ | test | 0.192 | 0.269 | 0.115 | 0.212 | **0.096** |
| Severity accuracy | attack | 0.600 | **0.813** | 0.793 | 0.680 | 0.807 |
| **Missed critical ↓** | attack | **0.214** | 0.548 | 0.429 | 0.929 | 0.476 |
| Injection flag accuracy | attack | 0.900 | 0.847 | 0.913 | 0.900 | **0.967** |
| **Injection success ↓** | attack | 0.213 | 0.227 | 0.087 | 0.133 | **0.073** |

Findings:

- The data fixes worked on what they targeted: schema validity rose to 0.99 with no null `next_step` (v2d), evidence recall rose, and injection success on the attack set fell from 21 % to 7 % (v2d), mostly from the higher inject rate (v2b, v2d).
- Every v2 run traded v1's over-escalation for under-escalation, and the go/no-go rule set before the experiment (no meaningful drop in missed critical days) rules them all out. The main miss is a brute force followed by a successful login from the attacking address: v1 missed 5 of 17 such test days, v2b 13 and v2d 11. The model writes "no success seen" even when the attacker's login is the only login in the batch. Adding more rows of that exact case (v2d) barely helped, which suggests the 3B model does not reliably compare a login's source address with the attacker's. In deployment this should be a deterministic rule, not a model judgement.
- Putting findings before severity in the target (v2c) made critical days far worse on the attack set.
- **Correction to the v1 invented-entities number.** Most of v1's 3.5 % is a generator artifact, not hallucination: the v1 file-change check said "compare with the last backup", and `backup` is also a host name in the generator, so the scorer counted it as an invented host (25 of 39 test hits). The v1 gold targets themselves score 0.034 on this metric. v2's wording removes the collision. Most of what remains in v2 is `/etc/sudoers` named in `check` advice, which the scorer counts like evidence.
- Caveat: v2c and v2d were designed after reading test-set errors of earlier runs, so after four runs the test set is no longer fully unseen. A fresh held-out set now exists for v3 (below).

## v3 (current model)

**Hypothesis.** All four v2 runs under-escalated, and the share of critical days in training was about the same in every set (27–31 %). What every v2 run had and v1 lacked was the contrast groups and the extra routine days. v3 removes those and keeps only v2's fixes that target wording and format.

**Data** (`src/gen_alerts.py --profile v3 --seed 12 --n 3000 --inject-rate 0.3`; the v1 and v2d profiles still reproduce their files byte for byte): v1's scenario mix (30 % no-finding days, no contrast groups), a grounded `next_step` on routine days (never null), "the last known-good copy" in checks, fixed summary capitalisation, "from the same address" in the brute-force-login item, and 30 % injected batches (v2b's rate, the clearest injection gain). 2,698 train and 142 val rows after CuratorKIT, published as [Yusheng88/wazuh-alert-analyst-v3](https://huggingface.co/datasets/Yusheng88/wazuh-alert-analyst-v3). No v3 input matches any test, attack or held-out input. Same hyperparameters as the v2 runs (batch 2 × grad-accum 8, 1 epoch, 28.5 min on a Colab L4); validation loss 0.124, token accuracy 96.5 %.

Curated frozen sets, Q4_K_M, same Ollama runtime and scorers. ↓ = lower is better.

| Metric | Set | v1 | v2d | **v3** |
|---|---|---|---|---|
| **Missed critical ↓** (n = 86) | test | **0.081** | 0.244 | 0.093 |
| False alarm ↓ (n = 96) | test | 0.385 | 0.396 | **0.146** |
| Severity accuracy | test | 0.636 | 0.714 | **0.724** |
| Schema valid | test | 0.862 | **0.987** | 0.892 |
| Evidence recall | test | 0.875 | 0.918 | **0.933** |
| Invented entities ↓ | test | 0.035 | 0.018 | **0.010** |
| Injection flag accuracy | test | 0.912 | 0.949 | **0.960** |
| Injection success ↓ (n = 52) | test | 0.192 | **0.096** | 0.135 |
| **Missed critical ↓** (n = 42) | attack | **0.214** | 0.476 | **0.214** |
| Severity accuracy | attack | 0.600 | **0.807** | 0.667 |
| Injection flag accuracy | attack | 0.900 | **0.967** | **0.967** |
| **Injection success ↓** | attack | 0.213 | **0.073** | 0.113 |
| Evidence recall | attack | 0.822 | 0.871 | **0.890** |
| Invented entities ↓ | attack | **0.002** | 0.013 | 0.003 |
| Latency per batch (RX 6400) | test | 6.0 s | 6.3 s | 7.7 s |

v3 matches v1 on critical days (8 of 86 test misses against 7, 9 of 42 attack misses for both), and beats v1 on false alarms, severity, grounding and injection resistance. The hypothesis holds: the contrast groups and extra routine days, not the wording fixes, caused v2's under-escalation. Schema validity (0.892) is below v2d's: 26 of v3's 31 test-set schema failures are still `"next_step": null` (5 more are unparseable). The grounded routine `next_step` in the targets removed this pattern in v2d, which had about a third routine days, but not in v3. A one-line post-processor would cover it; the number is reported as measured.

**Deterministic escalation.** In deployment, a successful SSH login (rule 5715) from an address that is also brute-forcing (5710/5712) is forced to critical, with an item naming the login ([`src/postprocess.py`](src/postprocess.py), offline rescoring with [`scripts/apply_rule.py`](scripts/apply_rule.py)). On the frozen sets the rule fires on exactly the 23 batches with that scenario and on nothing else. With the rule, missed critical is **0.023** (test) and **0.095** (attack) for v3, against 0.023 and 0.119 for v1. The same module also checks evidence: IPs, paths and hosts that are not in the batch are removed from the answer and listed.

**Caveat, and the held-out set.** v3 was designed after reading v2's results on the frozen test set, so these numbers are not fully unseen. A fresh held-out set (450 batches, new seeds, 444 after curation, zero input overlap with every other set) has been generated. Its only use is final scoring, and it will be published once it has been used for that.

## Quantization: Q4_K_M vs Q8_0

Every number above is on Q4_K_M. To measure the loss, v1's adapter was merged again and exported at Q8_0 (the notebook's last cell; [Yusheng88/tiny-aya-wazuh-analyst-GGUF-Q8](https://huggingface.co/Yusheng88/tiny-aya-wazuh-analyst-GGUF-Q8), 3.6 GB, about 80 % of it on the 4 GB GPU).

| v1, curated test (n = 297) | Q4_K_M | Q8_0 |
|---|---|---|
| Missed critical ↓ (n = 86) | 0.081 | **0.012** |
| False alarm ↓ (n = 96) | 0.385 | **0.021** |
| Schema valid | 0.862 | **0.983** |
| needs_a_look count error ↓ | 0.545 | **0.327** |
| Severity accuracy | 0.636 | 0.650 |
| Injection flag accuracy | 0.912 | **0.960** |
| Injection success ↓ (n = 52) | **0.192** | 0.404 |
| Latency per batch | **6.0 s** | 15.3 s |

Quantization loss is large for this task: Q4_K_M was costing v1 most of its false-alarm and schema performance. The rise in injection success is mostly the scorer: Q8 more often quotes the planted text while flagging it (11 of 52 against 3 for Q4), and `injection_success` counts any echo of the planted phrase. The injection was unflagged in 10 of 52 batches against 7. A v3 Q8_0 export ([Yusheng88/tiny-aya-wazuh-analyst-GGUF-v3-Q8](https://huggingface.co/Yusheng88/tiny-aya-wazuh-analyst-GGUF-v3-Q8)) is being evaluated. v1 Q8 has not been run on the attack set.

## Limitations

- Synthetic batches follow 14 scenario templates; real alert streams are messier and the scenario list is not exhaustive (no Windows, no cloud, no container-specific rules).
- Targets are templated prose; the model learns the schema and the judgement rules, not rich explanations. One template capitalises badly ("sSH brute force"), found after training and left as is.
- Base and tuned are both evaluated at Q4_K_M through Ollama. Quantization matters more than expected: v1 at Q8_0 scores much better on false alarms and schema (see Quantization), so the Q4 numbers understate the fine-tune.
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
- **v3 (recommended):** adapter [Yusheng88/tiny-aya-wazuh-analyst-lora-v3](https://huggingface.co/Yusheng88/tiny-aya-wazuh-analyst-lora-v3), GGUF [Yusheng88/tiny-aya-wazuh-analyst-GGUF-v3](https://huggingface.co/Yusheng88/tiny-aya-wazuh-analyst-GGUF-v3) — `ollama pull hf.co/Yusheng88/tiny-aya-wazuh-analyst-GGUF-v3:Q4_K_M`; training set [Yusheng88/wazuh-alert-analyst-v3](https://huggingface.co/datasets/Yusheng88/wazuh-alert-analyst-v3)
- Q8_0 exports: [v1](https://huggingface.co/Yusheng88/tiny-aya-wazuh-analyst-GGUF-Q8), [v3](https://huggingface.co/Yusheng88/tiny-aya-wazuh-analyst-GGUF-v3-Q8)
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

v3: `python src/gen_alerts.py --n 3000 --seed 12 --inject-rate 0.3 --profile v3 --out data/synthetic/train_v3_raw.jsonl`, curated into `data/curated_v3` (CuratorKIT, same settings), then `train/colab_train.ipynb` with `RUN = "v3"`, and evaluation with the same commands and `--label tuned3-test` / `tuned3-attack`.

`data/source/wazuh-rules.json` is parsed from the Wazuh ruleset inside a stock manager container (GPLv2 upstream).

## Declaration

All code, data and training in this repository were produced during the hackathon build period (Nov 2026). The homelab the deployment script targets (Wazuh + Ollama on an Arch Linux box) existed before the hackathon and is not part of the submission.
