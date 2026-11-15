---
tags:
- curatorkit
configs:
- config_name: sft_alpaca
  default: true
  description: curatorkit sft_alpaca export, sha256 47b7cc18812dcd584c089b6f6c14bfd5477e0d57dcb1b070640d1f0dbf2d90ab
  data_files:
  - split: train
    path: train/sft_alpaca.jsonl
  - split: val
    path: val/sft_alpaca.jsonl
- config_name: sft_sharegpt
  description: curatorkit sft_sharegpt export, sha256 8d20875cdfd32f34e6836d7ee37420cddd200427d748e3025d45369f00808e6b
  data_files:
  - split: train
    path: train/sft_sharegpt.jsonl
  - split: val
    path: val/sft_sharegpt.jsonl
---

# Dataset Card: wazuh-alert-analyst-train

## Summary

- **Run timestamp**: 2026-11-15T22:12:07.091986Z
- **Wall clock time**: 105.9s
- **Pipeline config hash**: `5f52e9281cba16fe`

## Source Documents

  - Unknown

## Pipeline Stages

| Step | Input | Passed | Recovered | Rejected | Forward |
|------|-------|--------|-----------|----------|---------|
| JSONLReader | 3000 | 3000 | — | 0 | 3000 |
| SchemaGate | 3000 | 3000 | 0 | 0 | 3000 |
| ExactDeduplicator | 3000 | 2967 | — | — | 2967 |
| MinHashDeduplicator | 2967 | 2714 | — | — | 2714 |
| TextCleaner | 2714 | 2714 | — | — | 2714 |
| SecretsGate | 2714 | 2714 | 0 | 0 | 2714 |

## Gate Pass Rates and Rejection Breakdown

- **JSONLReader**: 3000/0 passed (N/A), 0 rejected
- **SchemaGate**: 3000/3000 passed (100.0%), 0 rejected
- **SecretsGate**: 2714/2714 passed (100.0%), 0 rejected


**Rejection reasons:**
  - None

## Deduplication

  - near_duplicates_removed: 253
  - surviving_count: 2714

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
| `sft_alpaca` | train (2578), val (136) | `instruction`: string<br>`input`: string (empty when there is no input)<br>`output`: string |
| `sft_sharegpt` | train (2578), val (136) | `conversations`: list of {from, value}; from is system, human or gpt |
