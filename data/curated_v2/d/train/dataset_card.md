# Dataset Card: wazuh-alert-analyst-train

## Summary

- **Run timestamp**: 2026-11-16T02:02:04.042917Z
- **Wall clock time**: 111.6s
- **Pipeline config hash**: `d7fc472264b5b14f`

## Source Documents

  - Unknown

## Pipeline Stages

| Step | Input | Passed | Recovered | Rejected | Forward |
|------|-------|--------|-----------|----------|---------|
| JSONLReader | 3000 | 3000 | — | 0 | 3000 |
| SchemaGate | 3000 | 3000 | 0 | 0 | 3000 |
| ExactDeduplicator | 3000 | 2969 | — | — | 2969 |
| MinHashDeduplicator | 2969 | 2750 | — | — | 2750 |
| TextCleaner | 2750 | 2750 | — | — | 2750 |
| SecretsGate | 2750 | 2750 | 0 | 0 | 2750 |

## Gate Pass Rates and Rejection Breakdown

- **JSONLReader**: 3000/0 passed (N/A), 0 rejected
- **SchemaGate**: 3000/3000 passed (100.0%), 0 rejected
- **SecretsGate**: 2750/2750 passed (100.0%), 0 rejected


**Rejection reasons:**
  - None

## Deduplication

  - near_duplicates_removed: 219
  - surviving_count: 2750

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
