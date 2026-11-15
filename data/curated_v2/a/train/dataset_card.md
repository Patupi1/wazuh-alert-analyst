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
