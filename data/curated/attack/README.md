---
tags:
- curatorkit
configs:
- config_name: sft_alpaca
  default: true
  description: curatorkit sft_alpaca export, sha256 a285ed323df8ff0502c9f8ffe08ceaca8dfa8f3321d245250b9bf50d96f0f4ba
  data_files:
  - split: train
    path: sft_alpaca.jsonl
- config_name: sft_sharegpt
  description: curatorkit sft_sharegpt export, sha256 10071eb59cdcd38bef9fe4625b52b927d78074339d0ba76e6029723d86d6a3b4
  data_files:
  - split: train
    path: sft_sharegpt.jsonl
---

# Dataset Card: wazuh-alert-analyst-attack

## Summary

- **Run timestamp**: 2026-11-15T06:03:46.299630Z
- **Wall clock time**: 6.4s
- **Pipeline config hash**: `4626e8b72a78e63a`

## Source Documents

  - Unknown

## Pipeline Stages

| Step | Input | Passed | Recovered | Rejected | Forward |
|------|-------|--------|-----------|----------|---------|
| JSONLReader | 150 | 150 | — | 0 | 150 |
| SchemaGate | 150 | 150 | 0 | 0 | 150 |
| ExactDeduplicator | 150 | 150 | — | — | 150 |
| MinHashDeduplicator | 150 | 150 | — | — | 150 |
| TextCleaner | 150 | 150 | — | — | 150 |
| SecretsGate | 150 | 150 | 0 | 0 | 150 |
| AlpacaExporter | — | 150 | — | — | 150 |
| ShareGPTExporter | — | 150 | — | — | 150 |

## Gate Pass Rates and Rejection Breakdown

- **JSONLReader**: 150/0 passed (N/A), 0 rejected
- **SchemaGate**: 150/150 passed (100.0%), 0 rejected
- **SecretsGate**: 150/150 passed (100.0%), 0 rejected


**Rejection reasons:**
  - None

## Deduplication

  - near_duplicates_removed: 0
  - surviving_count: 150

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
| `sft_alpaca` | train (150) | `instruction`: string<br>`input`: string (empty when there is no input)<br>`output`: string |
| `sft_sharegpt` | train (150) | `conversations`: list of {from, value}; from is system, human or gpt |
