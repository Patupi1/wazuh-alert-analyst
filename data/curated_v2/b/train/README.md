---
tags:
- curatorkit
configs:
- config_name: sft_alpaca
  default: true
  description: curatorkit sft_alpaca export, sha256 013c89725d2080a79c0618393476ef43533a59df120f1e3e68817cfd77ed5d0e
  data_files:
  - split: train
    path: train/sft_alpaca.jsonl
  - split: val
    path: val/sft_alpaca.jsonl
- config_name: sft_sharegpt
  description: curatorkit sft_sharegpt export, sha256 435d59a661d07d333a9a1b547875c66ccb383f45aefc605c13dcdccba874ccba
  data_files:
  - split: train
    path: train/sft_sharegpt.jsonl
  - split: val
    path: val/sft_sharegpt.jsonl
---

# Dataset Card: wazuh-alert-analyst-train

## Summary

- **Run timestamp**: 2026-11-15T22:13:58.864110Z
- **Wall clock time**: 110.5s
- **Pipeline config hash**: `c86677b2d8ba47b7`

## Source Documents

  - Unknown

## Pipeline Stages

| Step | Input | Passed | Recovered | Rejected | Forward |
|------|-------|--------|-----------|----------|---------|
| JSONLReader | 3000 | 3000 | — | 0 | 3000 |
| SchemaGate | 3000 | 3000 | 0 | 0 | 3000 |
| ExactDeduplicator | 3000 | 2973 | — | — | 2973 |
| MinHashDeduplicator | 2973 | 2747 | — | — | 2747 |
| TextCleaner | 2747 | 2747 | — | — | 2747 |
| SecretsGate | 2747 | 2747 | 0 | 0 | 2747 |

## Gate Pass Rates and Rejection Breakdown

- **JSONLReader**: 3000/0 passed (N/A), 0 rejected
- **SchemaGate**: 3000/3000 passed (100.0%), 0 rejected
- **SecretsGate**: 2747/2747 passed (100.0%), 0 rejected


**Rejection reasons:**
  - None

## Deduplication

  - near_duplicates_removed: 226
  - surviving_count: 2747

## Known Limitations

- MinHash threshold used: **0.9** — this is a starting point, not a universal answer. Adjust per domain (legal, medical, and other domain-specific corpora may need a lower threshold to avoid losing structurally similar but semantically valid examples).
- Table extraction requires `extract_tables: true` on the PDF reader and MinerU with GPU support. Disabled by default.
- Token counting uses a whitespace tokenizer by default. For exact LLM context window
  enforcement, enable `use_tiktoken: true` in the SchemaGate config.
- Both within-run (MinHash/Diversity) and cross-run (EmbeddingDeduplicator) deduplication
  are available. Cross-run dedup persists an embedding index across runs; use
  `embedding_reset_index: true` to start fresh.

## Reproduction

```bash
pip install curatorkit
curatorkit run pipeline.yaml --output-dir ./out/
```

## Tool Versions

- **curatorkit**: 0.1.28
- **python**: 3.14.10

## Configs

Load one with `datasets.load_dataset("<this folder or Hub repo>", "<config>")`.

| Config | Splits (rows) | Columns |
|--------|---------------|---------|
| `sft_alpaca` | train (2609), val (138) | `instruction`: string<br>`input`: string (empty when there is no input)<br>`output`: string |
| `sft_sharegpt` | train (2609), val (138) | `conversations`: list of {from, value}; from is system, human or gpt |
