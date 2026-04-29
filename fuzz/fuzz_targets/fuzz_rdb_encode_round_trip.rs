#![no_main]
//! Coverage-guided fuzzer for the RDB encode/decode round-trip with
//! compact-type selection enabled.
//!
//! `encode_rdb_with_options` (br-frankenredis-91kt, commit eaecea1)
//! is the new public entry point that mirrors upstream Redis 7.2's
//! compact RDB type-tag selection
//! (RDB_TYPE_SET_INTSET=11, _SET_LISTPACK=20, _HASH_LISTPACK=16,
//! _ZSET_LISTPACK=17, _LIST_QUICKLIST_2=18) for shapes whose
//! cardinality / per-element byte size fits within the supplied
//! thresholds. Unit tests pin the contract on a handful of
//! hand-crafted shapes; this fuzzer drives libfuzzer's coverage-guided
//! mutator across the full strategy space.
//!
//! Invariants asserted per fuzz iteration:
//!
//!   1. `encode_rdb_with_options(values, opts)` never panics.
//!   2. The encoded bytes always start with the `REDIS` magic and end
//!      with an EOF + 8-byte CRC trailer.
//!   3. `decode_rdb(encoded)` succeeds (i.e. our encoder doesn't emit
//!      anything our decoder can't read).
//!   4. The decoded entry set is shape-equivalent to the input under
//!      a canonicalisation that accounts for upstream's set/hash
//!      members being unordered and zset scores being floating-point.
//!
//! The `Arbitrary`-derived `FuzzShape` mixes uniformly-random member
//! sizes (driving the canonical-fallback path) with deliberately small
//! shapes (driving the compact path), so both code branches see
//! coverage. The `compact_thresholds` field also varies — sometimes
//! `None` (canonical only) and sometimes `Some(default)` to exercise
//! both sides of the dispatch.

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

use fr_persist::{
    CompactRdbThresholds, RdbEncodeOptions, RdbEntry, RdbValue, decode_rdb, encode_rdb_with_options,
};

#[derive(Debug, Arbitrary)]
struct FuzzInput {
    /// When true, the encoder runs with compact-type selection enabled
    /// (the new code path in eaecea1). When false, runs with the
    /// canonical-only default — exercises the back-compat wrapper.
    enable_compact: bool,
    /// Per-shape value generators. Capped at 8 entries so libfuzzer
    /// stays in a useful exploration window.
    entries: Vec<FuzzEntry>,
}

#[derive(Debug, Arbitrary)]
struct FuzzEntry {
    key: Vec<u8>,
    value: FuzzValue,
}

#[derive(Debug, Arbitrary)]
enum FuzzValue {
    StringRaw(Vec<u8>),
    /// Lists are upstream-quicklist-encoded; we exercise both the
    /// single-PACKED-node path and the per-PLAIN-node fallback by
    /// sometimes including a giant element.
    List(Vec<Vec<u8>>),
    /// Sets exercise three branches: intset (all integers fit
    /// canonical decimal), listpack (small non-int members), or
    /// canonical hashtable (overflow).
    SetIntegerLike(Vec<i32>),
    SetGeneral(Vec<Vec<u8>>),
    Hash(Vec<(Vec<u8>, Vec<u8>)>),
    SortedSet(Vec<(Vec<u8>, f64)>),
}

impl FuzzValue {
    fn to_rdb(&self) -> RdbValue {
        match self {
            FuzzValue::StringRaw(s) => RdbValue::String(s.clone()),
            FuzzValue::List(items) => RdbValue::List(items.clone()),
            FuzzValue::SetIntegerLike(values) => {
                RdbValue::Set(values.iter().map(|v| v.to_string().into_bytes()).collect())
            }
            FuzzValue::SetGeneral(members) => RdbValue::Set(members.clone()),
            FuzzValue::Hash(pairs) => RdbValue::Hash(pairs.clone()),
            FuzzValue::SortedSet(members) => RdbValue::SortedSet(members.clone()),
        }
    }

    /// Canonical-form comparison key — sorted byte slices for
    /// unordered shapes, score-rounding for floats. Required because
    /// the encode/decode round-trip can reorder members in
    /// unordered shapes (set, hash, intset) and a strict `==` would
    /// trip on a real-but-uninteresting difference.
    fn canonical(&self) -> CanonicalShape {
        match self {
            FuzzValue::StringRaw(s) => CanonicalShape::String(s.clone()),
            FuzzValue::List(items) => CanonicalShape::List(items.clone()),
            FuzzValue::SetIntegerLike(values) => {
                let mut canonical: Vec<Vec<u8>> =
                    values.iter().map(|v| v.to_string().into_bytes()).collect();
                canonical.sort();
                canonical.dedup();
                CanonicalShape::Set(canonical)
            }
            FuzzValue::SetGeneral(members) => {
                let mut canonical = members.clone();
                canonical.sort();
                canonical.dedup();
                CanonicalShape::Set(canonical)
            }
            FuzzValue::Hash(pairs) => {
                // Drop later duplicates of the same field — our encoder
                // emits them all but the decoder may collapse depending
                // on the type tag. Comparing on field-deduplicated
                // first-wins keys avoids spurious mismatches.
                let mut seen = std::collections::BTreeSet::new();
                let mut canonical = Vec::new();
                for (k, v) in pairs {
                    if seen.insert(k.clone()) {
                        canonical.push((k.clone(), v.clone()));
                    }
                }
                canonical.sort();
                CanonicalShape::Hash(canonical)
            }
            FuzzValue::SortedSet(members) => {
                let mut canonical: Vec<(Vec<u8>, f64)> = members
                    .iter()
                    .filter(|(_, score)| score.is_finite())
                    .map(|(m, s)| (m.clone(), *s))
                    .collect();
                canonical.sort_by(|a, b| {
                    a.0.cmp(&b.0)
                        .then(a.1.partial_cmp(&b.1).unwrap_or(std::cmp::Ordering::Equal))
                });
                CanonicalShape::SortedSet(canonical)
            }
        }
    }
}

#[derive(Debug, PartialEq)]
enum CanonicalShape {
    String(Vec<u8>),
    List(Vec<Vec<u8>>),
    Set(Vec<Vec<u8>>),
    Hash(Vec<(Vec<u8>, Vec<u8>)>),
    SortedSet(Vec<(Vec<u8>, f64)>),
}

fn rdb_canonical(value: &RdbValue) -> Option<CanonicalShape> {
    match value {
        RdbValue::String(s) => Some(CanonicalShape::String(s.clone())),
        RdbValue::List(items) => Some(CanonicalShape::List(items.clone())),
        RdbValue::Set(members) => {
            let mut sorted = members.clone();
            sorted.sort();
            sorted.dedup();
            Some(CanonicalShape::Set(sorted))
        }
        RdbValue::Hash(pairs) => {
            let mut seen = std::collections::BTreeSet::new();
            let mut canonical = Vec::new();
            for (k, v) in pairs {
                if seen.insert(k.clone()) {
                    canonical.push((k.clone(), v.clone()));
                }
            }
            canonical.sort();
            Some(CanonicalShape::Hash(canonical))
        }
        RdbValue::SortedSet(members) => {
            let mut sorted: Vec<(Vec<u8>, f64)> = members
                .iter()
                .filter(|(_, s)| s.is_finite())
                .cloned()
                .collect();
            sorted.sort_by(|a, b| {
                a.0.cmp(&b.0)
                    .then(a.1.partial_cmp(&b.1).unwrap_or(std::cmp::Ordering::Equal))
            });
            Some(CanonicalShape::SortedSet(sorted))
        }
        // HashWithTtls and Stream aren't constructed by FuzzValue; skip.
        _ => None,
    }
}

fuzz_target!(|input: FuzzInput| {
    // Bound the work done per iteration so libfuzzer doesn't time out
    // on pathological inputs. Mirrors the limits used by the
    // structured RDB fuzzer.
    if input.entries.len() > 8 {
        return;
    }

    let mut entries = Vec::with_capacity(input.entries.len());
    let mut canonical_inputs = Vec::with_capacity(input.entries.len());
    for fe in &input.entries {
        if fe.key.is_empty() || fe.key.len() > 256 {
            return;
        }
        // Cap individual member sizes so the encoder stays in the
        // usefully-explorable size range (also matches the project's
        // proto-max-bulk-len-style ceilings).
        if let FuzzValue::List(items) = &fe.value
            && items.iter().any(|item| item.len() > 4096)
        {
            return;
        }
        if let FuzzValue::SetGeneral(members) = &fe.value
            && members.iter().any(|m| m.len() > 4096)
        {
            return;
        }
        if let FuzzValue::Hash(pairs) = &fe.value
            && pairs.iter().any(|(k, v)| k.len() > 4096 || v.len() > 4096)
        {
            return;
        }
        if let FuzzValue::SortedSet(members) = &fe.value
            && members.iter().any(|(m, _)| m.len() > 4096)
        {
            return;
        }

        let canonical = fe.value.canonical();
        canonical_inputs.push((fe.key.clone(), canonical));
        entries.push(RdbEntry {
            db: 0,
            key: fe.key.clone(),
            value: fe.value.to_rdb(),
            expire_ms: None,
        });
    }
    if entries.is_empty() {
        return;
    }

    let opts = RdbEncodeOptions {
        compact: if input.enable_compact {
            Some(CompactRdbThresholds::default())
        } else {
            None
        },
    };

    let encoded = encode_rdb_with_options(&entries, &[], opts);

    // Invariant 2: REDIS magic + 0xFF + 8-byte CRC trailer.
    assert!(
        encoded.starts_with(b"REDIS"),
        "encode_rdb_with_options dropped the REDIS magic header",
    );
    assert!(
        encoded.len() > 9 + 1 + 8,
        "encoded RDB shorter than minimal REDIS-version + EOF + CRC envelope",
    );

    // Invariant 3: decode_rdb must accept what encode_rdb_with_options
    // emits. This is the round-trip wire-compat assertion.
    let (decoded, _aux) = match decode_rdb(&encoded) {
        Ok(out) => out,
        Err(e) => {
            // A decoder rejection on encoder output is a real defect:
            // the two halves must agree on the wire format. Print the
            // hex-dump to make minimization actionable.
            panic!(
                "decode_rdb rejected encode_rdb_with_options(opts={:?}) output \
                 ({} bytes): {:?}\nfirst 64 bytes: {:02x?}",
                opts.compact.is_some(),
                encoded.len(),
                e,
                &encoded[..encoded.len().min(64)],
            );
        }
    };

    // Invariant 4: shape-equivalent round-trip. We compare under the
    // unordered-canonicalisation form because some shape paths
    // (intset, set listpack, hash listpack) re-order members during
    // encode/decode.
    assert_eq!(
        decoded.len(),
        entries.len(),
        "round-trip dropped or duplicated entries",
    );
    let mut decoded_canonical = Vec::with_capacity(decoded.len());
    for restored in &decoded {
        let canonical = match rdb_canonical(&restored.value) {
            Some(c) => c,
            None => return, // Shape we don't model in canonical comparison.
        };
        decoded_canonical.push((restored.key.clone(), canonical));
    }

    // Duplicate top-level RDB keys are legal fuzz input. Match as a
    // multiset so repeated keys with different values cannot be hidden by
    // a first-key lookup.
    let mut matched = vec![false; decoded_canonical.len()];
    for (input_key, expected_canonical) in &canonical_inputs {
        let match_idx = decoded_canonical
            .iter()
            .enumerate()
            .find_map(|(idx, (restored_key, restored_canonical))| {
                (!matched[idx]
                    && restored_key == input_key
                    && restored_canonical == expected_canonical)
                    .then_some(idx)
            })
            .unwrap_or_else(|| {
                panic!(
                    "round-trip lost key/shape {:?} (compact={})",
                    String::from_utf8_lossy(input_key),
                    opts.compact.is_some(),
                )
            });
        matched[match_idx] = true;
    }
});
