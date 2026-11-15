# Dataset Card: wazuh-alert-analyst-test

## Summary

- **Run timestamp**: 2026-11-15T06:03:39.782069Z
- **Wall clock time**: 10.2s
- **Pipeline config hash**: `c5fe06413babc383`

## Source Documents

  - Unknown

## Pipeline Stages

| Step | Input | Passed | Recovered | Rejected | Forward |
|------|-------|--------|-----------|----------|---------|
| JSONLReader | 300 | 300 | — | 0 | 300 |
| SchemaGate | 300 | 300 | 0 | 0 | 300 |
| ExactDeduplicator | 300 | 300 | — | — | 300 |
| MinHashDeduplicator | 300 | 297 | — | — | 297 |
| TextCleaner | 297 | 297 | — | — | 297 |
| SecretsGate | 297 | 297 | 0 | 0 | 297 |
| AlpacaExporter | — | 297 | — | — | 297 |
| ShareGPTExporter | — | 297 | — | — | 297 |

## Gate Pass Rates and Rejection Breakdown

- **JSONLReader**: 300/0 passed (N/A), 0 rejected
- **SchemaGate**: 300/300 passed (100.0%), 0 rejected
- **SecretsGate**: 297/297 passed (100.0%), 0 rejected


**Rejection reasons:**
  - None

## Deduplication

  - near_duplicates_removed: 3
  - surviving_count: 297

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
