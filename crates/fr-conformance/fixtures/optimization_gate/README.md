# Optimization Gate Fixtures

This directory is the tracked source of truth for `phase2c_schema` optimization-gate tests.

Rules:
- unit tests in `crates/fr-conformance/src/phase2c_schema.rs` must read from this tracked fixture bundle
- the `phase2c_schema_gate --optimization-gate` CLI still validates the live runtime artifact root at `artifacts/optimization/phase2c-gate`
- do not make tests depend on ignored `artifacts/` contents

The current canonical fixture pack is:

- `phase2c-gate/`
  - `bench_packets/`
  - `round_dir_scan_mask/`
