---
tags:
- curatorkit
configs:
- config_name: sft_alpaca
  default: true
  description: curatorkit sft_alpaca export, sha256 551964b57a9d55be8d6be9d8135edd67d1efd50c20e66a1126a964da769b5eca
  data_files:
  - split: train
    path: train/sft_alpaca.jsonl
  - split: val
    path: val/sft_alpaca.jsonl
- config_name: sft_sharegpt
  description: curatorkit sft_sharegpt export, sha256 693b3615cddeefa1228760bd0241eb398d4f4e48233c51aec8868374bd41676f
  data_files:
  - split: train
    path: train/sft_sharegpt.jsonl
  - split: val
    path: val/sft_sharegpt.jsonl
---

# Dataset Card: wazuh-alert-analyst-train

## Summary

- **Run timestamp**: 2026-11-15T23:54:01.271237Z
- **Wall clock time**: 104.5s
- **Pipeline config hash**: `e24a658beb06b1ea`

## Source Documents

  - Unknown

## Pipeline Stages

| Step | Input | Passed | Recovered | Rejected | Forward |
|------|-------|--------|-----------|----------|---------|
| JSONLReader | 3000 | 3000 | — | 0 | 3000 |
| SchemaGate | 3000 | 3000 | 0 | 0 | 3000 |
| ExactDeduplicator | 3000 | 2967 | — | — | 2967 |
| MinHashDeduplicator | 2967 | 2720 | — | — | 2720 |
| TextCleaner | 2720 | 2720 | — | — | 2720 |
| SecretsGate | 2720 | 2720 | 0 | 0 | 2720 |

## Gate Pass Rates and Rejection Breakdown

- **JSONLReader**: 3000/0 passed (N/A), 0 rejected
- **SchemaGate**: 3000/3000 passed (100.0%), 0 rejected
- **SecretsGate**: 2720/2720 passed (100.0%), 0 rejected


**Rejection reasons:**
  - None

## Deduplication

  - near_duplicates_removed: 247
  - surviving_count: 2720

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
| `sft_alpaca` | train (2584), val (136) | `instruction`: string<br>`input`: string (empty when there is no input)<br>`output`: string |
| `sft_sharegpt` | train (2584), val (136) | `conversations`: list of {from, value}; from is system, human or gpt |
