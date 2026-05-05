//! Metamorphic invariants for the MOVE command's cross-DB semantics
//! reachable through dispatch_argv (Lua redis.call, AOF replay,
//! MULTI/EXEC). Pin behaviors that go beyond w9yzb's three primitive
//! unit tests so a future refactor of Store::copy / encode_db_key /
//! the dispatcher routing can't silently regress MOVE.
//!
//! (frankenredis-6ezgn)

use fr_command::{CommandError, dispatch_argv};
use fr_protocol::RespFrame;
use fr_store::{PttlValue, Store, encode_db_key};

fn move_argv(key: &[u8], db: u8) -> Vec<Vec<u8>> {
    vec![b"MOVE".to_vec(), key.to_vec(), vec![b'0' + db]]
}

/// Drive the dispatch context's selected DB the same way the runtime
/// would after a SELECT — by mutating store.dispatch_client_ctx.db_index
/// directly. The fr-command dispatch_argv path reads source_db from
/// that field.
fn select_db(store: &mut Store, db: usize) {
    store.dispatch_client_ctx.db_index = db;
}

#[test]
fn mr_move_round_trip_restores_value_and_ttl() {
    // MR1: SET k v EX <future>; MOVE k 0→1; MOVE k 1→0 must end with
    // (k, v) in db 0 with the SAME absolute expiry deadline. A
    // refactor that drops TTL during Store::copy or resets it on
    // dispatch_argv MOVE would fail this.
    let mut store = Store::new();
    let now = 1_000_000_u64;
    let key_db0 = encode_db_key(0, b"foo");
    store.set(key_db0.clone(), b"bar".to_vec(), Some(60_000), now);
    let pttl_before = match store.pttl(&key_db0, now) {
        PttlValue::Remaining(v) => v,
        other => panic!("expected Remaining, got {other:?}"),
    };

    select_db(&mut store, 0);
    let out = dispatch_argv(&move_argv(b"foo", 1), &mut store, now).expect("move 0→1");
    assert_eq!(out, RespFrame::Integer(1));

    select_db(&mut store, 1);
    let out = dispatch_argv(&move_argv(b"foo", 0), &mut store, now).expect("move 1→0");
    assert_eq!(out, RespFrame::Integer(1));

    // Final state.
    let final_key = encode_db_key(0, b"foo");
    assert!(store.exists(&final_key, now));
    assert!(!store.exists(&encode_db_key(1, b"foo"), now));
    let pttl_after = match store.pttl(&final_key, now) {
        PttlValue::Remaining(v) => v,
        other => panic!("expected Remaining after round-trip, got {other:?}"),
    };
    // Absolute deadline preserved (no time has advanced in the test).
    assert_eq!(pttl_after, pttl_before);
}

#[test]
fn mr_move_preserves_no_ttl() {
    // MR2: MOVE on a key without TTL must keep it without TTL in the
    // target db (no spurious expire stamping during the transfer).
    let mut store = Store::new();
    let now = 1_000_000_u64;
    store.set(encode_db_key(0, b"foo"), b"bar".to_vec(), None, now);

    select_db(&mut store, 0);
    let out = dispatch_argv(&move_argv(b"foo", 2), &mut store, now).expect("move 0→2");
    assert_eq!(out, RespFrame::Integer(1));
    assert!(matches!(
        store.pttl(&encode_db_key(2, b"foo"), now),
        PttlValue::NoExpiry
    ));
}

#[test]
fn mr_move_target_collision_is_no_op() {
    // MR3: When the target db already holds the key, MOVE must
    // return 0 AND leave both source AND target untouched (upstream
    // db.c::moveCommand is non-destructive — it does NOT overwrite).
    let mut store = Store::new();
    let now = 1_000_000_u64;
    store.set(encode_db_key(0, b"foo"), b"src".to_vec(), None, now);
    store.set(encode_db_key(1, b"foo"), b"dst".to_vec(), None, now);

    select_db(&mut store, 0);
    let out = dispatch_argv(&move_argv(b"foo", 1), &mut store, now).expect("move with collision");
    assert_eq!(out, RespFrame::Integer(0));

    // Source intact.
    assert_eq!(
        store
            .get(&encode_db_key(0, b"foo"), now)
            .expect("get src")
            .as_deref(),
        Some(&b"src"[..])
    );
    // Target intact (NOT overwritten with "src").
    assert_eq!(
        store
            .get(&encode_db_key(1, b"foo"), now)
            .expect("get dst")
            .as_deref(),
        Some(&b"dst"[..])
    );
}

#[test]
fn mr_move_missing_source_returns_zero_no_target_created() {
    // MR4: MOVE on a missing source must return 0 with no spurious
    // empty key materialised in the target. Catches a future bug
    // where a tombstone or empty entry leaks across.
    let mut store = Store::new();
    let now = 1_000_000_u64;

    select_db(&mut store, 0);
    let out = dispatch_argv(&move_argv(b"ghost", 1), &mut store, now).expect("move missing");
    assert_eq!(out, RespFrame::Integer(0));
    assert!(!store.exists(&encode_db_key(0, b"ghost"), now));
    assert!(!store.exists(&encode_db_key(1, b"ghost"), now));
}

#[test]
fn mr_move_preserves_value_type_for_non_string_kinds() {
    // MR5: MOVE must transfer the underlying ValueType faithfully —
    // a hash-encoded key must remain a hash in the target db, not
    // collapse to a string. Catches a future Store::copy bug that
    // forgot to copy stream/zset/hash auxiliary state.
    let mut store = Store::new();
    let now = 1_000_000_u64;
    store
        .hset(b"myh", b"f1".to_vec(), b"v1".to_vec(), now)
        .expect("hset");
    // hset writes against the encoded key for db 0 by default;
    // verify and rebase to encode_db_key form for the metamorphic
    // assertions below. The Store API is db-naive; the dispatcher
    // is what namespaces.
    assert_eq!(store.key_type(b"myh", now), Some("hash"));

    select_db(&mut store, 0);
    let out = dispatch_argv(&move_argv(b"myh", 3), &mut store, now).expect("move hash");
    assert_eq!(out, RespFrame::Integer(1));

    // After MOVE, db-3-namespaced key exists and is still a hash;
    // db-0 row is gone.
    let target_key = encode_db_key(3, b"myh");
    assert!(store.exists(&target_key, now));
    assert_eq!(store.key_type(&target_key, now), Some("hash"));
    assert!(!store.exists(&encode_db_key(0, b"myh"), now));
}

#[test]
fn mr_move_same_db_does_not_mutate_state() {
    // MR6: MOVE k 0→0 (rejected with upstream error) must NOT
    // mutate the key. Pins the "error before side effect" ordering
    // in upstream db.c::moveCommand.
    let mut store = Store::new();
    let now = 1_000_000_u64;
    store.set(encode_db_key(0, b"foo"), b"bar".to_vec(), None, now);

    select_db(&mut store, 0);
    let err = dispatch_argv(&move_argv(b"foo", 0), &mut store, now)
        .expect_err("same-db should error");
    assert!(matches!(
        err,
        CommandError::Custom(ref s) if s == "ERR source and destination objects are the same"
    ));
    // Key still in db 0 with same value.
    assert_eq!(
        store
            .get(&encode_db_key(0, b"foo"), now)
            .expect("get untouched")
            .as_deref(),
        Some(&b"bar"[..])
    );
}

#[test]
fn mr_move_out_of_range_does_not_mutate_state() {
    // MR7: MOVE k → out-of-range db (rejected) must not mutate
    // source.
    let mut store = Store::new();
    let now = 1_000_000_u64;
    store.set(encode_db_key(0, b"foo"), b"bar".to_vec(), None, now);

    select_db(&mut store, 0);
    let err = dispatch_argv(
        &[b"MOVE".to_vec(), b"foo".to_vec(), b"999".to_vec()],
        &mut store,
        now,
    )
    .expect_err("out-of-range should error");
    assert!(matches!(
        err,
        CommandError::Custom(ref s) if s == "ERR DB index is out of range"
    ));
    assert!(store.exists(&encode_db_key(0, b"foo"), now));
}

// MR8 (SELECT-then-MOVE) intentionally not included here: SELECT
// through dispatch_argv is itself stubbed in fr-command (filed as
// frankenredis-j22p8) — it doesn't mutate dispatch_client_ctx.db_index
// and rejects every db != 0 with "ERR DB index is out of range". Once
// that stub is fixed, an MR8 invariant should pin SELECT+MOVE as a
// composed pair so MULTI/EXEC and Lua transactions are covered.
