# Dataset Card: wazuh-alert-analyst-train

## Summary

- **Run timestamp**: 2026-11-15T06:03:29.201334Z
- **Wall clock time**: 88.4s
- **Pipeline config hash**: `e3c51faab18e8a50`

## Source Documents

  - Unknown

## Pipeline Stages

| Step | Input | Passed | Recovered | Rejected | Forward |
|------|-------|--------|-----------|----------|---------|
| JSONLReader | 2400 | 2400 | — | 0 | 2400 |
| SchemaGate | 2400 | 2400 | 0 | 0 | 2400 |
| ExactDeduplicator | 2400 | 2396 | — | — | 2396 |
| MinHashDeduplicator | 2396 | 2298 | — | — | 2298 |
| TextCleaner | 2298 | 2298 | — | — | 2298 |
| SecretsGate | 2298 | 2298 | 0 | 0 | 2298 |

## Gate Pass Rates and Rejection Breakdown

- **JSONLReader**: 2400/0 passed (N/A), 0 rejected
- **SchemaGate**: 2400/2400 passed (100.0%), 0 rejected
- **SecretsGate**: 2298/2298 passed (100.0%), 0 rejected


**Rejection reasons:**
  - None

## Deduplication

  - near_duplicates_removed: 98
  - surviving_count: 2298

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
