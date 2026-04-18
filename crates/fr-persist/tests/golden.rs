use fr_persist::parse_aof_manifest;
use std::fs;
use std::path::Path;

fn assert_golden(test_name: &str, actual: &str) {
    let golden_path = Path::new("tests/golden").join(format!("{}.golden", test_name));

    if std::env::var("UPDATE_GOLDENS").is_ok() {
        fs::create_dir_all(golden_path.parent().unwrap()).unwrap();
        fs::write(&golden_path, actual).unwrap();
        eprintln!("[GOLDEN] Updated: {}", golden_path.display());
        return;
    }

    let expected = fs::read_to_string(&golden_path).unwrap_or_else(|_| {
        panic!(
            "Golden file missing: {}\n\
             Run with UPDATE_GOLDENS=1 to create it",
            golden_path.display()
        )
    });

    if actual != expected {
        let actual_path = golden_path.with_extension("actual");
        fs::write(&actual_path, actual).unwrap();

        panic!(
            "GOLDEN MISMATCH: {}\n\
             To update: UPDATE_GOLDENS=1 cargo test --test golden\n\
             To review: diff {} {}",
            test_name,
            golden_path.display(),
            actual_path.display(),
        );
    }
}

fn parse_and_snapshot(test_name: &str, manifest_data: &str) {
    match parse_aof_manifest(manifest_data) {
        Ok(result) => {
            let actual = format!("{:#?}", result);
            assert_golden(test_name, &actual);
        }
        Err(e) => {
            let actual = format!("Error: {:#?}", e);
            assert_golden(test_name, &actual);
        }
    }
}

#[test]
fn golden_manifest_empty() {
    parse_and_snapshot("manifest_empty", "");
}

#[test]
fn golden_manifest_single_base() {
    parse_and_snapshot(
        "manifest_single_base",
        "file appendonly.aof.1.base.rdb seq 1 type b\n",
    );
}

#[test]
fn golden_manifest_base_and_incremental() {
    parse_and_snapshot(
        "manifest_base_and_incremental",
        "file appendonly.aof.1.base.rdb seq 1 type b\nfile appendonly.aof.1.incr.aof seq 1 type i\n",
    );
}

#[test]
fn golden_manifest_history_entries() {
    parse_and_snapshot(
        "manifest_history_entries",
        "file appendonly.aof.1.base.rdb seq 1 type h\nfile appendonly.aof.1.incr.aof seq 1 type h\nfile appendonly.aof.2.base.rdb seq 2 type b\nfile appendonly.aof.2.incr.aof seq 2 type i\n",
    );
}

#[test]
fn golden_manifest_invalid_type() {
    parse_and_snapshot(
        "manifest_invalid_type",
        "file appendonly.aof.1.base.rdb seq 1 type x\n",
    );
}

#[test]
fn golden_manifest_missing_seq() {
    parse_and_snapshot(
        "manifest_missing_seq",
        "file appendonly.aof.1.base.rdb type b\n",
    );
}

#[test]
fn golden_manifest_missing_file() {
    parse_and_snapshot("manifest_missing_file", "seq 1 type b\n");
}

#[test]
fn golden_manifest_invalid_seq_number() {
    parse_and_snapshot(
        "manifest_invalid_seq_number",
        "file appendonly.aof.1.base.rdb seq 01 type b\n",
    );
}
