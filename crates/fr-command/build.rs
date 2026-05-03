use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use serde_json::Value;

fn main() -> Result<(), Box<dyn Error>> {
    let manifest_dir = PathBuf::from(std::env::var_os("CARGO_MANIFEST_DIR").ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::NotFound,
            "CARGO_MANIFEST_DIR is not set for build.rs",
        )
    })?);
    let commands_dir = manifest_dir
        .join("../..")
        .join("legacy_redis_code/redis/src/commands");

    println!("cargo:rerun-if-changed={}", commands_dir.display());

    let mut entries = BTreeMap::<String, BTreeSet<String>>::new();
    for path in command_json_paths(&commands_dir)? {
        println!("cargo:rerun-if-changed={}", path.display());
        let raw = fs::read_to_string(&path).map_err(|err| {
            io::Error::new(
                err.kind(),
                format!(
                    "failed to read Redis command metadata {}: {err}",
                    path.display()
                ),
            )
        })?;
        let value: Value = serde_json::from_str(&raw).map_err(|err| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "failed to parse Redis command metadata {}: {err}",
                    path.display()
                ),
            )
        })?;
        let object = value.as_object().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "top-level command metadata is not an object: {}",
                    path.display()
                ),
            )
        })?;

        for (name, metadata) in object {
            let flags = string_array(metadata.get("command_flags"));
            if flags.contains(&"ONLY_SENTINEL") {
                continue;
            }

            let command_name = metadata
                .get("container")
                .and_then(Value::as_str)
                .map(|container| format!("{container}|{name}"))
                .unwrap_or_else(|| name.clone())
                .to_ascii_lowercase();

            let categories = entries.entry(command_name).or_default();
            for category in string_array(metadata.get("acl_categories")) {
                categories.insert(category.to_ascii_lowercase());
            }

            if flags.contains(&"WRITE") {
                categories.insert("write".to_string());
            }
            if flags.contains(&"READONLY") && !categories.contains("scripting") {
                categories.insert("read".to_string());
            }
            if flags.contains(&"ADMIN") {
                categories.insert("admin".to_string());
                categories.insert("dangerous".to_string());
            }
            if flags.contains(&"PUBSUB") {
                categories.insert("pubsub".to_string());
            }
            if flags.contains(&"FAST") {
                categories.insert("fast".to_string());
            }
            if flags.contains(&"BLOCKING") {
                categories.insert("blocking".to_string());
            }
            if !categories.contains("fast") {
                categories.insert("slow".to_string());
            }
        }
    }

    let mut out = String::from("const UPSTREAM_ACL_CATEGORY_ENTRIES: &[(&str, &[&str])] = &[\n");
    for (command, categories) in entries {
        out.push_str("    (\"");
        out.push_str(&escape_rust_string(&command));
        out.push_str("\", &[");
        for category in categories {
            out.push('"');
            out.push_str(&escape_rust_string(&category));
            out.push_str("\", ");
        }
        out.push_str("]),\n");
    }
    out.push_str("];\n");

    let out_dir = PathBuf::from(std::env::var_os("OUT_DIR").ok_or_else(|| {
        io::Error::new(io::ErrorKind::NotFound, "OUT_DIR is not set for build.rs")
    })?);
    fs::write(out_dir.join("acl_categories.rs"), out)?;
    Ok(())
}

fn command_json_paths(commands_dir: &Path) -> io::Result<Vec<PathBuf>> {
    let mut paths: Vec<PathBuf> = fs::read_dir(commands_dir)
        .map_err(|err| {
            io::Error::new(
                err.kind(),
                format!(
                    "failed to read Redis commands dir {}: {err}",
                    commands_dir.display()
                ),
            )
        })?
        .map(|entry| entry.map(|entry| entry.path()))
        .collect::<io::Result<Vec<_>>>()?
        .into_iter()
        .filter(|path| path.extension().is_some_and(|ext| ext == "json"))
        .collect();
    paths.sort();
    Ok(paths)
}

fn string_array(value: Option<&Value>) -> Vec<&str> {
    value
        .and_then(Value::as_array)
        .map(|array| array.iter().filter_map(Value::as_str).collect())
        .unwrap_or_default()
}

fn escape_rust_string(value: &str) -> String {
    value.replace('\\', "\\\\").replace('"', "\\\"")
}
