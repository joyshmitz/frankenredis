# FrankenRedis

<div align="center">
  <img src="frankenredis_illustration.webp" alt="FrankenRedis - memory-safe clean-room Redis reimplementation in Rust">
</div>

FrankenRedis is a clean-room Rust reimplementation targeting grand-scope excellence: semantic fidelity, operational safety, and performance-focused design.

Absolute project goal: full drop-in replacement parity with legacy Redis behavior for the complete intended Redis surface, not a permanently reduced feature subset.

## What Makes This Project Special

Deterministic Latency Replication Core (DLRC): strict command semantics with tail-aware scheduling and recoverable persistence pipelines.

This is treated as a core identity constraint, not a best-effort nice-to-have.

## Methodological DNA

This project applies frankenlibc/frankenfs compatibility-security thinking: strict vs hardened mode separation, fail-closed compatibility gates, and explicit drift ledgers. This is implemented and enforced throughout the codebase via `fr-config::Mode` and the runtime policy system.

## Roadmap

The following disciplines are planned but not yet integrated:

1. **alien-artifact-coding** for decision theory, confidence calibration, and explainability. Status: not started.
2. **extreme-software-optimization** for profile-first, proof-backed performance work. Status: optimization proof artifacts exist (`ISOMORPHISM_PROOF_ROUND{1,2}.md`), the live-server benchmark harness/baselines/regression gate now exist (`crates/fr-bench`, `baselines/`, `scripts/benchmark_gate.sh`), and the active blocker is the severe throughput gap versus legacy Redis rather than lack of measurement.
3. **RaptorQ-everywhere** for self-healing durability of long-lived artifacts and state. Status: not started, no crate dependency added.

## Current State

- project charter and porting docs established
- legacy oracle cloned at `/data/projects/frankenredis/legacy_redis_code/redis`
- first executable vertical slice landed:
  - standalone `fr-server` binary (`frankenredis`) using `mio` for single-threaded TCP serving on top of `fr-runtime`
  - RESP parser/encoder
  - broad command surface across strings, hashes, lists, sets, sorted sets, streams, geo, pub/sub, and server control paths
  - in-memory store + TTL semantics
  - replication sync baseline: `PSYNC`/`SYNC` negotiation, full-resync snapshot apply, partial backlog replay, replica reconnect flow, and live replication offset reporting
  - strict/hardened compatibility gate + runtime evidence/structured-log baseline
  - fixture-driven conformance harness (`core_*` families + phase2c packet suites)
- live performance instrumentation landed:
  - `crates/fr-bench` TCP benchmark harness with HdrHistogram latency reporting
  - checked-in FrankenRedis vs Redis baseline artifacts under `baselines/`
  - `scripts/record_baselines.sh` for baseline capture and `scripts/benchmark_gate.sh` for regression checks
- checked-in optimization and proof artifacts currently include:
  - `artifacts/optimization/phase2c-gate/baseline_hyperfine.json`
  - `artifacts/optimization/phase2c-gate/baseline_strace.txt`
  - `artifacts/optimization/phase2c-gate/after_hyperfine_multi.json`
  - `artifacts/optimization/phase2c-gate/after_multi_strace.txt`
  - `artifacts/optimization/ISOMORPHISM_PROOF_ROUND1.md`
  - `artifacts/optimization/ISOMORPHISM_PROOF_ROUND2.md`
  - `artifacts/phase2c/schema/topology_lock_v1.json`

## Current Benchmark Evidence

Initial live-server baselines were captured on April 7, 2026 against FrankenRedis `v0.1.0` and Redis `7.2.4`.

- `SET`: FrankenRedis `1240.93 ops/sec` vs Redis `94402.47 ops/sec`; p99 `58,847us` vs `1,022us`
- `GET`: FrankenRedis `1204.65 ops/sec` vs Redis `91142.35 ops/sec`; p99 `51,647us` vs `1,038us`
- `MIXED`: FrankenRedis `1159.23 ops/sec` vs Redis `96834.08 ops/sec`; p99 `65,791us` vs `1,002us`
- `INCR`: FrankenRedis `1176.59 ops/sec` vs Redis `95183.76 ops/sec`; p99 `66,559us` vs `996us`
- `PIPELINE16`: FrankenRedis `1221.37 ops/sec` vs Redis `860900.42 ops/sec`; p50/p99 `693,759us / 857,087us` vs `759us / 1,817us`

### Throughput-gap recovery (April 9, 2026)

Profile-driven optimization (`frankenredis-zjii`) closed most of the gap. Two
fixes — lazy threat-event digests and an ACL category short-circuit — moved
FrankenRedis from ~1.3% of Redis throughput to **79–99% on per-command
workloads** and **31% on `pipeline=16`**:

- `SET` p1: **75,054 ops/sec** (79% of Redis)
- `GET` p1: **90,567 ops/sec** (99% of Redis)
- `INCR` p1: **81,383 ops/sec** (86% of Redis)
- `MIXED` p1: **80,372 ops/sec** (83% of Redis)
- `SET` p16: **268,414 ops/sec** (31% of Redis)
- `GET` p16: **433,970 ops/sec**
- `MIXED` p16: **310,564 ops/sec**

See `artifacts/optimization/throughput-gap/ISOMORPHISM_PROOF_LAZY_DIGEST.md`
for the full investigation, before/after flamegraphs, and the semantic-drift
note for the threat-event ledger.

## Full Drop-In Parity Contract

- 100% feature/functionality overlap with legacy Redis target surface is mandatory.
- Any staged rollout is sequencing only, never a permanent exclusion.
- Every deferred surface must be represented as an explicit blocking backlog item with closure criteria.
- Strict mode must preserve Redis-observable replies, side effects, and ordering across the full parity program.

## Architecture Direction

tcp client -> fr-server -> fr-runtime -> RESP parser -> command router -> data engine -> persistence -> replication

## Concrete Execution Path (Current Code)

1. Network ingress starts in the standalone `frankenredis` binary at `crates/fr-server/src/main.rs`, which runs a single-threaded `mio` event loop, owns TCP connection state, and delegates per-command execution to `fr-runtime`.
2. Runtime ingress inside that server path reaches `Runtime::execute_bytes` (`crates/fr-runtime/src/lib.rs`), which parses wire bytes and emits fail-closed evidence on protocol errors.
3. `Runtime::execute_frame` performs preflight policy checks, handles special runtime commands (auth, acl, config, cluster, transaction, persistence controls), enforces auth/maxmemory gates, and runs active-expire before general dispatch.
4. General command dispatch flows through `fr_command::dispatch_argv` (`crates/fr-command/src/lib.rs`) into command handlers that mutate/read `Store` with deterministic `now_ms` semantics.
5. Expiration semantics are centralized in store + `fr-expire` (`evaluate_expiry`), preserving Redis-visible `TTL/PTTL` return contracts (`-2`, `-1`, positive remaining lifetime).
6. Successful write dispatch captures persistence/replication signals in runtime (`capture_aof_record`), appending `fr-persist::AofRecord` entries and advancing replication offsets.
7. Replication state-machine logic lives in `fr-repl`, while the live server path in `fr-server` handles replica sockets, backlog delivery, and reconnect flow on top of runtime state.
8. Conformance execution is driven by `fr-conformance::run_fixture`, which instantiates strict or hardened runtime modes and validates both reply parity and threat/evidence expectations.

## Compatibility and Security Stance

Preserve Redis-observable replies, side effects, and ordering guarantees for full parity scope.

Defend against malformed protocol frames, replay/order attacks, and persistence tampering.

## Performance and Correctness Bar

Track throughput and p95/p99 latency under mixed workloads; gate persistence overhead and replication-lag regressions.

Maintain deterministic command semantics, expiration behavior, and AOF/RDB recovery ordering invariants.

## Key Documents

- AGENTS.md
- COMPREHENSIVE_SPEC_FOR_FRANKENREDIS_V1.md
- COMPREHENSIVE_SPEC_FOR_FRANKENSQLITE_V1_REFERENCE.md (copied exemplar from `frankensqlite`)
- TEST_LOG_SCHEMA_V1.md

## Next Steps

1. Root-cause and reduce the severe throughput/latency gap versus legacy Redis while preserving strict parity.
2. Expand conformance fixtures until all command families and compatibility-critical behaviors are covered.
3. Expand persistence and replication invariants from the implemented sync baseline to broader legacy-oracle parity coverage.
4. Add Asupersync-backed runtime adapter and FrankenTUI operator dashboard adapter.
5. Implement RaptorQ sidecar pipeline for all durability-critical artifacts.
6. Run optimization loop with one lever per commit and isomorphism proofs while preserving strict parity.

## Porting Artifact Set

- PLAN_TO_PORT_REDIS_TO_RUST.md
- EXISTING_REDIS_STRUCTURE.md
- PROPOSED_ARCHITECTURE.md
- FEATURE_PARITY.md

These four docs are now the canonical porting-to-rust workflow for this repo.

## Validation Commands

```bash
# Offloaded (recommended in multi-agent sessions)
rch exec -- cargo fmt --check
rch exec -- cargo check --workspace --all-targets
rch exec -- cargo clippy --workspace --all-targets -- -D warnings
rch exec -- cargo test --workspace
rch exec -- cargo test -p fr-conformance -- --nocapture
rch exec -- cargo run -p fr-conformance --bin phase2c_schema_gate -- --optimization-gate
rch exec -- cargo bench

# Baseline capture (build step uses rch when available)
./scripts/record_baselines.sh

# The benchmark gate runs locally and offloads only its release build step via rch.
./scripts/benchmark_gate.sh

# If rch is unavailable, run the same commands with plain cargo.
```

## License

MIT License (with OpenAI/Anthropic Rider). See `LICENSE`.

## Round 1 Benchmark Script

```bash
./scripts/benchmark_round1.sh
```

## Round 2 Benchmark Script

```bash
./scripts/benchmark_round2.sh
```

## Benchmark Regression Gate

```bash
./scripts/benchmark_gate.sh
```

Use `FR_BENCH_THROUGHPUT_DROP_PCT` and `FR_BENCH_P99_REGRESSION_PCT` to tune
the failure thresholds. Each run writes raw benchmark reports, per-workload
comparisons, and an aggregate gate report under `artifacts/benchmark/<run-id>/`.
