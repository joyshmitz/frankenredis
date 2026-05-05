//! Replay every file in `fuzz/corpus/fuzz_aof_decoder/` through
//! `decode_aof_stream` and lock in the invariant that none of the
//! seeded inputs panics. Mirrors the fr-protocol fuzz_corpus_smoke
//! test added in cwx6 — exercises the same handcrafted samples that
//! libfuzzer consumes, so corner-case coverage stays deterministic
//! between cargo-fuzz runs.
//!
//! (frankenredis-ohm5)

use fr_persist::decode_aof_stream;
use std::fs;
use std::path::PathBuf;

fn corpus_dir() -> PathBuf {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest_dir.join("../../fuzz/corpus/fuzz_aof_decoder")
}

#[test]
fn fuzz_aof_decoder_corpus_never_panics() {
    let dir = corpus_dir();
    assert!(
        dir.is_dir(),
        "corpus dir missing: {} — did the workspace move?",
        dir.display()
    );

    let mut count = 0_usize;
    for entry in fs::read_dir(&dir).expect("read corpus dir") {
        let entry = entry.expect("dir entry");
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        let bytes = fs::read(&path)
            .unwrap_or_else(|err| panic!("failed to read {}: {err}", path.display()));

        // Decoder must surface every malformed input as Err, never
        // unwind. We don't care whether it returns Ok or Err — only
        // that it returns at all.
        let _ = decode_aof_stream(&bytes);

        count += 1;
    }

    // 14 original happy-path seeds + 8 hostile-input seeds added in
    // ohm5; bail loudly if the corpus is silently emptied.
    assert!(
        count >= 14,
        "fuzz_aof_decoder corpus shrank to {count} files — regressed seed coverage?"
    );
}

/// Confirm the hostile-input seeds added in ohm5 actually surface as
/// Err rather than tripping a never-panic-but-silently-Ok path.
/// Catches a future refactor that loosens the array/bulk-length caps
/// or drops the recursion guard without explicit thought.
#[test]
fn fuzz_aof_decoder_rejects_hostile_seeds() {
    let dir = corpus_dir();
    for name in [
        "malformed_array_len_overflow",
        "malformed_bulk_len_overflow",
        "truncated_array_header",
        "truncated_bulk_header",
        "truncated_bulk_body",
        "missing_crlf_after_bulk_len",
        "non_resp_prefix",
        "deeply_nested_arrays",
    ] {
        let bytes = fs::read(dir.join(name))
            .unwrap_or_else(|err| panic!("missing seed {name}: {err}"));
        let result = decode_aof_stream(&bytes);
        assert!(
            result.is_err(),
            "hostile seed {name} should fail decoding, got Ok: {result:?}"
        );
    }
}
