//! Metamorphic invariants for the per-DB command family
//! (DBSIZE / KEYS / RANDOMKEY) and their composition with SELECT,
//! MOVE, COPY, FLUSHDB through dispatch_argv. Pins the integration
//! of every recent dispatch_argv fix so a future refactor that
//! breaks one without the other gets caught:
//!
//!   j22p8  SELECT — mutates dispatch_client_ctx.db_index
//!   w9yzb  MOVE   — cross-DB transfer
//!   op84s  COPY   — cross-DB clone
//!   rdz52  FLUSHDB — per-DB wipe (vs FLUSHALL all-DBs)
//!   shbbv  KEYS + DBSIZE — per-DB read scope
//!   bwkfm  RANDOMKEY — per-DB random pick
//!
//! (frankenredis-ek92t)

use fr_command::dispatch_argv;
use fr_protocol::RespFrame;
use fr_store::{Store, encode_db_key};
use std::collections::HashSet;

fn dbsize_via_dispatch(store: &mut Store) -> i64 {
    let out = dispatch_argv(&[b"DBSIZE".to_vec()], store, 0).expect("dbsize");
    let RespFrame::Integer(n) = out else {
        panic!("expected integer reply, got {out:?}"); // ubs:ignore — AI triage
    };
    n
}

fn keys_via_dispatch(store: &mut Store, pattern: &[u8]) -> HashSet<Vec<u8>> {
    let out = dispatch_argv(&[b"KEYS".to_vec(), pattern.to_vec()], store, 0).expect("keys");
    let RespFrame::Array(Some(frames)) = out else {
        panic!("expected array reply, got {out:?}"); // ubs:ignore — AI triage
    };
    frames
        .into_iter()
        .map(|f| match f {
            RespFrame::BulkString(Some(b)) => b,
            other => panic!("expected bulk string in KEYS reply, got {other:?}"), // ubs:ignore — AI triage
        })
        .collect()
}

fn select_via_dispatch(store: &mut Store, db: u8) {
    let out = dispatch_argv(&[b"SELECT".to_vec(), vec![b'0' + db]], store, 0).expect("select");
    assert_eq!(out, RespFrame::SimpleString("OK".to_string()));
}

#[test]
fn mr_select_then_dbsize_reports_selected_db_count() {
    // MR1: After SELECT N through dispatch_argv, DBSIZE replies with
    // the count for db N — pins j22p8 ↔ shbbv composition.
    let mut store = Store::new();
    store.set(encode_db_key(0, b"k0a"), b"v".to_vec(), None, 0);
    store.set(encode_db_key(0, b"k0b"), b"v".to_vec(), None, 0);
    store.set(encode_db_key(1, b"k1"), b"v".to_vec(), None, 0);

    select_via_dispatch(&mut store, 0);
    assert_eq!(dbsize_via_dispatch(&mut store), 2);

    select_via_dispatch(&mut store, 1);
    assert_eq!(dbsize_via_dispatch(&mut store), 1);

    select_via_dispatch(&mut store, 4);
    assert_eq!(dbsize_via_dispatch(&mut store), 0);
}

#[test]
fn mr_select_then_keys_returns_only_selected_db_keys() {
    // MR2: After SELECT N through dispatch_argv, KEYS '*' returns
    // only the logical names from db N — no encode_db_key prefix
    // bytes leaking, no foreign-db key names.
    let mut store = Store::new();
    store.set(encode_db_key(0, b"k0_alpha"), b"v".to_vec(), None, 0);
    store.set(encode_db_key(2, b"k2_alpha"), b"v".to_vec(), None, 0);
    store.set(encode_db_key(2, b"k2_beta"), b"v".to_vec(), None, 0);

    select_via_dispatch(&mut store, 0);
    let keys = keys_via_dispatch(&mut store, b"*");
    assert_eq!(keys, [b"k0_alpha".to_vec()].into_iter().collect());

    select_via_dispatch(&mut store, 2);
    let keys = keys_via_dispatch(&mut store, b"*");
    assert_eq!(
        keys,
        [b"k2_alpha".to_vec(), b"k2_beta".to_vec()]
            .into_iter()
            .collect::<HashSet<_>>()
    );
}

#[test]
fn mr_select_then_randomkey_only_samples_selected_db() {
    // MR3: After SELECT N, RANDOMKEY returns one of db N's logical
    // names (or Nil if db N is empty). 100 trials catches bias /
    // foreign-db leakage deterministically.
    let mut store = Store::new();
    store.set(encode_db_key(2, b"k2_a"), b"v".to_vec(), None, 0);
    store.set(encode_db_key(2, b"k2_b"), b"v".to_vec(), None, 0);
    store.set(encode_db_key(0, b"k0"), b"v".to_vec(), None, 0);

    select_via_dispatch(&mut store, 2);
    let allowed: HashSet<Vec<u8>> = [b"k2_a".to_vec(), b"k2_b".to_vec()].into_iter().collect();
    for _ in 0..100 {
        let out = dispatch_argv(&[b"RANDOMKEY".to_vec()], &mut store, 0).expect("randomkey");
        let RespFrame::BulkString(Some(name)) = out else {
            panic!("expected bulk string for db 2"); // ubs:ignore — AI triage
        };
        assert!(allowed.contains(&name));
    }

    // Empty db 5: RANDOMKEY must always be Nil.
    select_via_dispatch(&mut store, 5);
    for _ in 0..50 {
        let out = dispatch_argv(&[b"RANDOMKEY".to_vec()], &mut store, 0).expect("randomkey");
        assert_eq!(out, RespFrame::BulkString(None));
    }
}

#[test]
fn mr_flushdb_drops_only_selected_db_count() {
    // MR4: FLUSHDB on db N drops DBSIZE(N) to 0 while leaving every
    // other db's count intact. Pins rdz52 + shbbv composition.
    let mut store = Store::new();
    store.set(encode_db_key(0, b"k0"), b"v".to_vec(), None, 0);
    store.set(encode_db_key(1, b"k1a"), b"v".to_vec(), None, 0);
    store.set(encode_db_key(1, b"k1b"), b"v".to_vec(), None, 0);
    store.set(encode_db_key(2, b"k2"), b"v".to_vec(), None, 0);

    select_via_dispatch(&mut store, 1);
    let out = dispatch_argv(&[b"FLUSHDB".to_vec()], &mut store, 0).expect("flushdb");
    assert_eq!(out, RespFrame::SimpleString("OK".to_string()));

    // db 1 wiped.
    assert_eq!(dbsize_via_dispatch(&mut store), 0);
    // db 0 + db 2 unchanged.
    select_via_dispatch(&mut store, 0);
    assert_eq!(dbsize_via_dispatch(&mut store), 1);
    select_via_dispatch(&mut store, 2);
    assert_eq!(dbsize_via_dispatch(&mut store), 1);
}

#[test]
fn mr_move_balances_both_dbsizes() {
    // MR5: MOVE k from source→target must decrement DBSIZE(source)
    // and increment DBSIZE(target) atomically. Pins w9yzb + shbbv.
    let mut store = Store::new();
    store.set(encode_db_key(0, b"foo"), b"v".to_vec(), None, 0);
    store.set(encode_db_key(0, b"bar"), b"v".to_vec(), None, 0);

    select_via_dispatch(&mut store, 0);
    assert_eq!(dbsize_via_dispatch(&mut store), 2);
    select_via_dispatch(&mut store, 3);
    assert_eq!(dbsize_via_dispatch(&mut store), 0);

    // MOVE foo from db 0 → db 3.
    select_via_dispatch(&mut store, 0);
    let out = dispatch_argv(
        &[b"MOVE".to_vec(), b"foo".to_vec(), b"3".to_vec()],
        &mut store,
        0,
    )
    .expect("move");
    assert_eq!(out, RespFrame::Integer(1));

    select_via_dispatch(&mut store, 0);
    assert_eq!(dbsize_via_dispatch(&mut store), 1);
    select_via_dispatch(&mut store, 3);
    assert_eq!(dbsize_via_dispatch(&mut store), 1);
}

#[test]
fn mr_copy_with_db_option_increments_target_only() {
    // MR6: COPY k dst DB N must increment DBSIZE(N) without touching
    // DBSIZE(source). Pins op84s + shbbv composition.
    let mut store = Store::new();
    store.set(encode_db_key(0, b"foo"), b"v".to_vec(), None, 0);

    select_via_dispatch(&mut store, 0);
    assert_eq!(dbsize_via_dispatch(&mut store), 1);
    select_via_dispatch(&mut store, 5);
    assert_eq!(dbsize_via_dispatch(&mut store), 0);

    // COPY foo dst DB 5.
    select_via_dispatch(&mut store, 0);
    let out = dispatch_argv(
        &[
            b"COPY".to_vec(),
            b"foo".to_vec(),
            b"foodst".to_vec(),
            b"DB".to_vec(),
            b"5".to_vec(),
        ],
        &mut store,
        0,
    )
    .expect("copy");
    assert_eq!(out, RespFrame::Integer(1));

    // Source db unchanged.
    select_via_dispatch(&mut store, 0);
    assert_eq!(dbsize_via_dispatch(&mut store), 1);
    // Target db incremented.
    select_via_dispatch(&mut store, 5);
    assert_eq!(dbsize_via_dispatch(&mut store), 1);
}

#[test]
fn mr_keys_pattern_isolates_across_dbs() {
    // MR7: KEYS pattern matching is bounded to the selected db. A
    // pattern that *would* match a foreign db's key (same logical
    // name in another db) must NOT return that key.
    let mut store = Store::new();
    // Same logical name "shared" in three different dbs.
    store.set(encode_db_key(0, b"shared"), b"v0".to_vec(), None, 0);
    store.set(encode_db_key(1, b"shared"), b"v1".to_vec(), None, 0);
    store.set(encode_db_key(2, b"shared"), b"v2".to_vec(), None, 0);

    // Each db sees exactly one match.
    for db in [0, 1, 2] {
        select_via_dispatch(&mut store, db);
        let keys = keys_via_dispatch(&mut store, b"shared");
        assert_eq!(
            keys.len(),
            1,
            "db {db} KEYS shared should match exactly one key"
        );
        assert!(keys.contains(b"shared".as_slice()));
    }
}

#[test]
fn mr_randomkey_distribution_within_selected_db() {
    // MR8: RANDOMKEY from db M with K live keys must, over many
    // trials, return every one of those K names at least once
    // (uniformity sanity) and never return any name from db != M.
    let mut store = Store::new();
    let logical_in_db_1: Vec<&[u8]> = vec![b"alpha", b"beta", b"gamma"];
    for name in &logical_in_db_1 {
        store.set(encode_db_key(1, name), b"v".to_vec(), None, 0);
    }
    // Distractor keys in db 0 and db 2 — must never surface.
    store.set(encode_db_key(0, b"distractor0"), b"x".to_vec(), None, 0);
    store.set(encode_db_key(2, b"distractor2"), b"x".to_vec(), None, 0);

    select_via_dispatch(&mut store, 1);
    let allowed: HashSet<Vec<u8>> = logical_in_db_1.iter().map(|n| n.to_vec()).collect();
    let mut seen: HashSet<Vec<u8>> = HashSet::new();
    for _ in 0..500 {
        let out = dispatch_argv(&[b"RANDOMKEY".to_vec()], &mut store, 0).expect("randomkey");
        let RespFrame::BulkString(Some(name)) = out else {
            panic!("expected bulk string"); // ubs:ignore — AI triage
        };
        assert!(
            allowed.contains(&name),
            "RANDOMKEY returned {name:?} which is outside db 1's logical key set"
        );
        seen.insert(name);
    }
    // All 3 names should have been picked at least once over 500 trials
    // (probability of missing any one is (2/3)^500, vanishingly small).
    assert_eq!(
        seen.len(),
        3,
        "expected RANDOMKEY to surface all 3 db-1 names over 500 trials, got {seen:?}"
    );
}
