//! Metamorphic invariants for the COPY command's cross-DB semantics
//! reachable through dispatch_argv (Lua redis.call, AOF replay,
//! MULTI/EXEC). Pin behaviors that go beyond op84s's four primitive
//! unit tests so a future refactor of Store::copy / encode_db_key /
//! the dispatcher routing can't silently regress COPY.
//!
//! (frankenredis-7h0qg)

use fr_command::dispatch_argv;
use fr_protocol::RespFrame;
use fr_store::{PttlValue, Store, encode_db_key};

fn copy_argv_db(src: &[u8], dst: &[u8], db: u8) -> Vec<Vec<u8>> {
    vec![
        b"COPY".to_vec(),
        src.to_vec(),
        dst.to_vec(),
        b"DB".to_vec(),
        vec![b'0' + db],
    ]
}

fn copy_argv_db_replace(src: &[u8], dst: &[u8], db: u8) -> Vec<Vec<u8>> {
    vec![
        b"COPY".to_vec(),
        src.to_vec(),
        dst.to_vec(),
        b"DB".to_vec(),
        vec![b'0' + db],
        b"REPLACE".to_vec(),
    ]
}

#[test]
fn mr_copy_preserves_absolute_expiry_across_db() {
    // MR1: COPY of a key with TTL T must produce dest with the SAME T
    // — no reset, no shift. Pins that Store::copy carries the expires
    // entry along with the value, even cross-db.
    let mut store = Store::new();
    let now = 1_000_000_u64;
    let key_db0 = encode_db_key(0, b"foo");
    store.set(key_db0.clone(), b"bar".to_vec(), Some(60_000), now);
    let pttl_src = match store.pttl(&key_db0, now) {
        PttlValue::Remaining(v) => v,
        other => panic!("expected Remaining, got {other:?}"),
    };

    let out = dispatch_argv(&copy_argv_db(b"foo", b"foo", 1), &mut store, now)
        .expect("cross-db COPY");
    assert_eq!(out, RespFrame::Integer(1));

    let pttl_dst = match store.pttl(&encode_db_key(1, b"foo"), now) {
        PttlValue::Remaining(v) => v,
        other => panic!("expected Remaining at dest, got {other:?}"),
    };
    // Same absolute deadline (no time advanced in test).
    assert_eq!(pttl_dst, pttl_src);
}

#[test]
fn mr_copy_no_ttl_stays_no_ttl() {
    // MR2: COPY of a key without TTL must keep the dest at NoExpiry
    // — no spurious stamping during the transfer.
    let mut store = Store::new();
    let now = 1_000_000_u64;
    store.set(encode_db_key(0, b"foo"), b"bar".to_vec(), None, now);

    let out = dispatch_argv(&copy_argv_db(b"foo", b"foo", 2), &mut store, now)
        .expect("cross-db COPY");
    assert_eq!(out, RespFrame::Integer(1));
    assert!(matches!(
        store.pttl(&encode_db_key(2, b"foo"), now),
        PttlValue::NoExpiry
    ));
}

#[test]
fn mr_copy_target_collision_is_no_op_without_replace() {
    // MR3: When the target already exists, COPY (no REPLACE) returns
    // 0 and leaves both source AND target untouched. Catches a
    // future bug that loosens the collision guard.
    let mut store = Store::new();
    let now = 1_000_000_u64;
    store.set(
        encode_db_key(0, b"foo"),
        b"src_payload".to_vec(),
        None,
        now,
    );
    store.set(
        encode_db_key(1, b"foo"),
        b"existing".to_vec(),
        None,
        now,
    );

    let out = dispatch_argv(&copy_argv_db(b"foo", b"foo", 1), &mut store, now)
        .expect("collision dispatch ok");
    assert_eq!(out, RespFrame::Integer(0));

    // Source intact.
    assert_eq!(
        store
            .get(&encode_db_key(0, b"foo"), now)
            .expect("get src")
            .as_deref(),
        Some(&b"src_payload"[..])
    );
    // Target NOT overwritten.
    assert_eq!(
        store
            .get(&encode_db_key(1, b"foo"), now)
            .expect("get dst")
            .as_deref(),
        Some(&b"existing"[..])
    );
}

#[test]
fn mr_copy_replace_flag_overwrites_target() {
    // MR4: COPY ... REPLACE must always succeed even when the target
    // already exists, and the target adopts the source value.
    let mut store = Store::new();
    let now = 1_000_000_u64;
    store.set(
        encode_db_key(0, b"foo"),
        b"src_payload".to_vec(),
        None,
        now,
    );
    store.set(
        encode_db_key(1, b"foo"),
        b"existing".to_vec(),
        None,
        now,
    );

    let out = dispatch_argv(&copy_argv_db_replace(b"foo", b"foo", 1), &mut store, now)
        .expect("replace dispatch");
    assert_eq!(out, RespFrame::Integer(1));

    // Source still intact.
    assert_eq!(
        store
            .get(&encode_db_key(0, b"foo"), now)
            .expect("src")
            .as_deref(),
        Some(&b"src_payload"[..])
    );
    // Target now reflects source.
    assert_eq!(
        store
            .get(&encode_db_key(1, b"foo"), now)
            .expect("dst")
            .as_deref(),
        Some(&b"src_payload"[..])
    );
}

#[test]
fn mr_copy_never_deletes_source() {
    // MR5: COPY is non-destructive on the source side. Pin both with
    // and without REPLACE, both same-db (different name) and cross-
    // db. A future implementation that confused COPY with MOVE would
    // fail this.
    let mut store = Store::new();
    let now = 1_000_000_u64;
    let scenarios = [
        (b"a".as_slice(), b"a_dup".as_slice(), 0_u8, false),
        (b"b".as_slice(), b"b".as_slice(), 1_u8, false),
        (b"c".as_slice(), b"c".as_slice(), 2_u8, true),
    ];
    for (src, dst, target_db, replace) in scenarios {
        store.set(encode_db_key(0, src), b"v".to_vec(), None, now);
        let argv = if replace {
            copy_argv_db_replace(src, dst, target_db)
        } else {
            copy_argv_db(src, dst, target_db)
        };
        let _ = dispatch_argv(&argv, &mut store, now).expect("copy");
        // Source row must still be present.
        assert!(
            store.exists(&encode_db_key(0, src), now),
            "source {src:?} disappeared after COPY (target_db={target_db}, replace={replace})"
        );
    }
}

#[test]
fn mr_copy_preserves_value_type_for_hash() {
    // MR6: COPY of a hash key must produce a hash in the target db,
    // not a string. Catches a future Store::copy bug that fails to
    // carry hash auxiliary state across.
    let mut store = Store::new();
    let now = 1_000_000_u64;
    // hset writes against an unprefixed key; that's the db-0
    // namespace for the dispatcher (encode_db_key(0, k) == k).
    store
        .hset(b"myh", b"f1".to_vec(), b"v1".to_vec(), now)
        .expect("hset");
    assert_eq!(store.key_type(b"myh", now), Some("hash"));

    let out = dispatch_argv(&copy_argv_db(b"myh", b"myh", 3), &mut store, now)
        .expect("copy hash");
    assert_eq!(out, RespFrame::Integer(1));

    let target = encode_db_key(3, b"myh");
    assert!(store.exists(&target, now));
    assert_eq!(store.key_type(&target, now), Some("hash"));
    // Source still a hash.
    assert_eq!(store.key_type(b"myh", now), Some("hash"));
}

#[test]
fn mr_copy_round_trip_recovers_original_via_replace() {
    // MR7: COPY src dst DB 1 then COPY dst src DB 0 REPLACE must
    // leave (db 0, src) byte-identical to its initial value, even
    // after intermediate mutations to the source.
    let mut store = Store::new();
    let now = 1_000_000_u64;
    store.set(
        encode_db_key(0, b"foo"),
        b"original".to_vec(),
        None,
        now,
    );

    let out = dispatch_argv(&copy_argv_db(b"foo", b"foo", 1), &mut store, now)
        .expect("copy 0->1");
    assert_eq!(out, RespFrame::Integer(1));

    // Mutate the source between the two halves.
    store.set(
        encode_db_key(0, b"foo"),
        b"clobbered".to_vec(),
        None,
        now,
    );
    assert_eq!(
        store
            .get(&encode_db_key(0, b"foo"), now)
            .expect("get src after mutate")
            .as_deref(),
        Some(&b"clobbered"[..])
    );

    // Restore from the cross-db backup.
    let argv = vec![
        b"COPY".to_vec(),
        b"foo".to_vec(),
        b"foo".to_vec(),
        b"DB".to_vec(),
        b"0".to_vec(),
        b"REPLACE".to_vec(),
    ];
    // The dispatch context is still db 0 by default, so the source
    // for this second COPY is db 1's "foo" — drive that by setting
    // db_index = 1 on the dispatch context.
    store.dispatch_client_ctx.db_index = 1;
    let out = dispatch_argv(&argv, &mut store, now).expect("copy 1->0 replace");
    assert_eq!(out, RespFrame::Integer(1));

    // db 0 now reflects the original value.
    assert_eq!(
        store
            .get(&encode_db_key(0, b"foo"), now)
            .expect("get src after round-trip")
            .as_deref(),
        Some(&b"original"[..])
    );
    // db 1 still holds the original (COPY non-destructive).
    assert_eq!(
        store
            .get(&encode_db_key(1, b"foo"), now)
            .expect("get db1 after round-trip")
            .as_deref(),
        Some(&b"original"[..])
    );
}

#[test]
fn mr_select_then_copy_uses_selected_source_db() {
    // MR8: SELECT through dispatch_argv must update the same
    // selected-db context COPY reads, since Lua redis.call, AOF
    // replay, and MULTI/EXEC compose these commands through this
    // path. Composes j22p8 (SELECT fix) with op84s (COPY fix).
    let mut store = Store::new();
    let now = 1_000_000_u64;
    store.set(
        encode_db_key(2, b"foo"),
        b"db2_payload".to_vec(),
        None,
        now,
    );

    let out = dispatch_argv(&[b"SELECT".to_vec(), b"2".to_vec()], &mut store, now)
        .expect("select 2");
    assert_eq!(out, RespFrame::SimpleString("OK".to_string()));
    assert_eq!(store.dispatch_client_ctx.db_index, 2);

    // COPY foo bar — source comes from db 2 (the selected one),
    // dest defaults to the same db without DB option.
    let out = dispatch_argv(
        &[
            b"COPY".to_vec(),
            b"foo".to_vec(),
            b"bar".to_vec(),
        ],
        &mut store,
        now,
    )
    .expect("same-db copy");
    assert_eq!(out, RespFrame::Integer(1));
    assert!(store.exists(&encode_db_key(2, b"foo"), now));
    assert!(store.exists(&encode_db_key(2, b"bar"), now));
    // db 0 untouched.
    assert!(!store.exists(&encode_db_key(0, b"foo"), now));
    assert!(!store.exists(&encode_db_key(0, b"bar"), now));
}
