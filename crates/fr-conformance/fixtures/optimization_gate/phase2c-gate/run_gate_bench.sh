#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "$script_dir/../../../../.." && pwd)"
bin="$repo_root/target-local/debug/phase2c_schema_gate"

mapfile -t args < <(find "$script_dir/bench_packets" -mindepth 1 -maxdepth 1 -type d | sort)
"$bin" "${args[@]}"
