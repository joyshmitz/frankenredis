#![forbid(unsafe_code)]

use std::fs;
use std::path::PathBuf;

use serde_json::Value;

#[derive(Debug, Clone, Copy)]
struct WrapperSpec {
    script_rel: &'static str,
    expected_cmd_line: &'static str,
}

const WRAPPER_SPECS: [WrapperSpec; 6] = [
    WrapperSpec {
        script_rel: "scripts/run_live_oracle_diff.sh",
        expected_cmd_line: "cmd=(cargo run -p fr-conformance --bin live_oracle_orchestrator -- \"$@\")",
    },
    WrapperSpec {
        script_rel: "scripts/run_adversarial_triage.sh",
        expected_cmd_line: "cmd=(cargo run -p fr-conformance --bin adversarial_triage_orchestrator -- \"$@\")",
    },
    WrapperSpec {
        script_rel: "scripts/run_raptorq_artifact_gate.sh",
        expected_cmd_line: "cmd=(cargo run -p fr-conformance --bin raptorq_artifact_orchestrator -- \"$@\")",
    },
    WrapperSpec {
        script_rel: "scripts/check_coverage_flake_budget.sh",
        expected_cmd_line: "cmd=(cargo run -p fr-conformance --bin live_oracle_budget_orchestrator -- \"$1\")",
    },
    WrapperSpec {
        script_rel: "scripts/benchmark_round1.sh",
        expected_cmd_line: "cmd=(cargo run -p fr-conformance --bin conformance_benchmark_runner -- --round round1 \"$@\")",
    },
    WrapperSpec {
        script_rel: "scripts/benchmark_round2.sh",
        expected_cmd_line: "cmd=(cargo run -p fr-conformance --bin conformance_benchmark_runner -- --round round2 \"$@\")",
    },
];

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("crate dir has parent")
        .parent()
        .expect("workspace dir has parent")
        .to_path_buf()
}

fn script_contents(script_rel: &str) -> String {
    let path = repo_root().join(script_rel);
    fs::read_to_string(&path).expect("failed to read script wrapper")
}

fn load_json(path: PathBuf) -> Value {
    serde_json::from_str(&fs::read_to_string(&path).expect("failed to read json fixture"))
        .expect("failed to parse json fixture")
}

fn find_baseline(server: &str, workload: &str) -> PathBuf {
    let baseline_dir = repo_root().join("baselines");
    let suffix = format!("_{workload}.json");
    let mut matches = fs::read_dir(&baseline_dir)
        .expect("failed to read baselines directory")
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| {
                    name.starts_with(&format!("{server}_")) && name.ends_with(&suffix)
                })
        })
        .collect::<Vec<_>>();
    matches.sort();
    assert_eq!(
        matches.len(),
        1,
        "expected exactly one baseline for server={server} workload={workload}, found {:?}",
        matches
    );
    matches.pop().expect("baseline match present")
}

fn json_f64(value: &Value, key: &str) -> Option<f64> {
    value[key].as_f64()
}

fn json_u64(value: &Value, key: &str) -> Option<u64> {
    value[key].as_u64()
}

#[test]
fn wrappers_delegate_to_expected_binaries() {
    for spec in WRAPPER_SPECS {
        let contents = script_contents(spec.script_rel);
        assert!(
            contents.contains(spec.expected_cmd_line),
            "wrapper {} missing expected command line {}",
            spec.script_rel,
            spec.expected_cmd_line
        );
        assert!(
            contents.contains("\"${cmd[@]}\""),
            "wrapper {} must execute delegated command array",
            spec.script_rel
        );
    }
}

#[test]
fn wrappers_do_not_embed_legacy_orchestration_logic() {
    let banned_snippets = [
        "~/.local/bin/rch exec --",
        "hyperfine \\",
        "strace -c -o",
        "while (($# > 0)); do",
    ];

    for spec in WRAPPER_SPECS {
        let contents = script_contents(spec.script_rel);
        for banned in banned_snippets {
            assert!(
                !contents.contains(banned),
                "wrapper {} should stay thin; found banned snippet: {}",
                spec.script_rel,
                banned
            );
        }
    }
}

#[test]
fn benchmark_scripts_and_checked_in_baselines_stay_in_sync() {
    let record_script = script_contents("scripts/record_baselines.sh");
    assert!(
        record_script.contains("rch exec -- env CARGO_TARGET_DIR=\"$repo_root/target\""),
        "record_baselines.sh must keep using rch-aware release builds"
    );
    for workload in ["set", "get", "mixed", "pipeline16", "incr"] {
        assert!(
            record_script.contains(&format!(
                "run_benchmark \"frankenredis\" \"$fr_version\" \"{workload}\""
            )) || workload == "pipeline16"
                && record_script.contains(
                    "run_benchmark \"frankenredis\" \"$fr_version\" \"pipeline16\" \"set\" 16 0"
                ),
            "record_baselines.sh must capture FrankenRedis workload {workload}"
        );
        assert!(
            record_script.contains(&format!(
                "run_benchmark \"redis\" \"$legacy_version\" \"{workload}\""
            )) || workload == "pipeline16"
                && record_script.contains(
                    "run_benchmark \"redis\" \"$legacy_version\" \"pipeline16\" \"set\" 16 0"
                ),
            "record_baselines.sh must capture Redis workload {workload}"
        );
    }

    let gate_script = script_contents("scripts/benchmark_gate.sh");
    assert!(
        gate_script.contains("schema_version\": \"frankenredis_benchmark_gate/v1\""),
        "benchmark_gate.sh must emit the normalized gate report schema"
    );
    assert!(
        gate_script.contains("frankenredis_*_{workload}.json"),
        "benchmark_gate.sh must auto-discover checked-in FrankenRedis baselines"
    );

    for server in ["frankenredis", "redis"] {
        for workload in ["set", "get", "mixed", "pipeline16", "incr"] {
            let path = find_baseline(server, workload);
            let report = load_json(path);
            let raw = &report["raw_report"];

            assert_eq!(report["schema_version"], "frankenredis_baseline/v1");
            assert_eq!(report["server"], server);
            assert_eq!(report["workload"], workload);
            assert!(
                report["server_version"]
                    .as_str()
                    .is_some_and(|text| !text.is_empty()),
                "server_version must be non-empty for {server}/{workload}"
            );

            let pipeline = json_u64(&report, "pipeline");
            let ops_sec = json_f64(&report, "ops_sec");
            let p50 = json_u64(&report, "p50_us");
            let p95 = json_u64(&report, "p95_us");
            let p99 = json_u64(&report, "p99_us");
            let p999 = json_u64(&report, "p999_us");

            assert!(
                ops_sec.is_some_and(|value| value > 0.0),
                "ops/sec must be positive for {server}/{workload}"
            );
            assert!(matches!(
                (p50, p95, p99, p999),
                (Some(p50), Some(p95), Some(p99), Some(p999)) if p50 <= p95 && p95 <= p99 && p99 <= p999
            ));
            assert_eq!(report["total_requests"], raw["requests"]);
            assert_eq!(report["read_percent"], raw["read_percent"]);
            assert_eq!(report["datasize"], raw["datasize"]);
            assert_eq!(report["keyspace"], raw["keyspace"]);
            assert_eq!(report["bytes_sent"], raw["bytes_sent"]);
            assert_eq!(report["bytes_received"], raw["bytes_received"]);
            assert_eq!(raw["schema_version"], "fr_bench_report/v1");

            if workload == "pipeline16" {
                assert_eq!(
                    pipeline,
                    Some(16),
                    "pipeline16 baseline must use pipeline depth 16"
                );
                assert_eq!(raw["workload"], "set");
            } else {
                assert_eq!(
                    pipeline,
                    Some(1),
                    "{workload} baseline must remain non-pipelined"
                );
                assert_eq!(raw["workload"], workload);
            }
        }
    }
}
