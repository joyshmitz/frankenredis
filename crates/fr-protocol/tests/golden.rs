use fr_protocol::parse_frame;
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

fn parse_and_snapshot(test_name: &str, input: &[u8]) {
    match parse_frame(input) {
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
fn golden_simple_string() {
    parse_and_snapshot("simple_string", b"+OK\r\n");
}

#[test]
fn golden_error_string() {
    parse_and_snapshot("error_string", b"-ERR unknown command 'foobar'\r\n");
}

#[test]
fn golden_integer() {
    parse_and_snapshot("integer", b":1000\r\n");
}

#[test]
fn golden_bulk_string() {
    parse_and_snapshot("bulk_string", b"$6\r\nfoobar\r\n");
}

#[test]
fn golden_null_bulk_string() {
    parse_and_snapshot("null_bulk_string", b"$-1\r\n");
}

#[test]
fn golden_array() {
    parse_and_snapshot("array", b"*2\r\n$3\r\nfoo\r\n$3\r\nbar\r\n");
}

#[test]
fn golden_null_array() {
    parse_and_snapshot("null_array", b"*-1\r\n");
}

#[test]
fn golden_nested_array() {
    parse_and_snapshot(
        "nested_array",
        b"*2\r\n*3\r\n:1\r\n:2\r\n:3\r\n*2\r\n+Foo\r\n-Bar\r\n",
    );
}

#[test]
fn golden_invalid_prefix() {
    parse_and_snapshot("invalid_prefix", b"x1000\r\n");
}

#[test]
fn golden_invalid_bulk_length() {
    parse_and_snapshot("invalid_bulk_length", b"$abc\r\n");
}
