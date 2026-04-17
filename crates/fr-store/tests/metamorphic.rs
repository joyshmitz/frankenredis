use fr_store::Store;
use proptest::prelude::*;

fn fresh_store() -> Store {
    Store::new()
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(1000))]

    // MR1: SET/GET roundtrip - SET k v then GET k must return v
    #[test]
    fn mr_set_get_roundtrip(key in prop::collection::vec(any::<u8>(), 1..64),
                            value in prop::collection::vec(any::<u8>(), 0..256)) {
        let mut store = fresh_store();
        store.set(key.clone(), value.clone(), None, 0);
        let got = store.get(&key, 0).unwrap();
        prop_assert_eq!(got, Some(value));
    }

    // MR2: INCR/DECR identity - INCRBY n then DECRBY n leaves value unchanged
    #[test]
    fn mr_incr_decr_identity(key in prop::collection::vec(any::<u8>(), 1..32),
                             initial in -1_000_000i64..1_000_000i64,
                             delta in 1i64..100_000i64) {
        let mut store = fresh_store();
        store.set(key.clone(), initial.to_string().into_bytes(), None, 0);

        let after_incr = store.incrby(&key, delta, 0).unwrap();
        let after_decr = store.incrby(&key, -delta, 0).unwrap();

        prop_assert_eq!(after_decr, initial, "INCR then DECR should restore original");
        prop_assert_eq!(after_incr, initial + delta);
    }

    // MR3: List LPUSH/RPOP queue behavior - first pushed is first popped from right
    #[test]
    fn mr_list_lpush_rpop_queue(key in prop::collection::vec(any::<u8>(), 1..32),
                                values in prop::collection::vec(
                                    prop::collection::vec(any::<u8>(), 1..64),
                                    1..10
                                )) {
        let mut store = fresh_store();

        // LPUSH all values (they go to head)
        for v in &values {
            store.lpush(&key, &[v.clone()], 0).unwrap();
        }

        // RPOP should return them in original order (FIFO from right)
        for expected in &values {
            let got = store.rpop(&key, 0).unwrap();
            prop_assert_eq!(got.as_ref(), Some(expected));
        }

        // List should now be empty
        prop_assert_eq!(store.llen(&key, 0).unwrap(), 0);
    }

    // MR4: Set membership - SADD then SISMEMBER must return true
    #[test]
    fn mr_set_membership(key in prop::collection::vec(any::<u8>(), 1..32),
                         members in prop::collection::vec(
                             prop::collection::vec(any::<u8>(), 1..64),
                             1..20
                         )) {
        let mut store = fresh_store();

        store.sadd(&key, &members, 0).unwrap();

        for member in &members {
            let is_member = store.sismember(&key, member, 0).unwrap();
            prop_assert!(is_member, "SADD member then SISMEMBER must be true");
        }

        prop_assert_eq!(store.scard(&key, 0).unwrap(), members.len());
    }

    // MR5: Hash field roundtrip - HSET then HGET must return same value
    #[test]
    fn mr_hash_field_roundtrip(key in prop::collection::vec(any::<u8>(), 1..32),
                               field in prop::collection::vec(any::<u8>(), 1..32),
                               value in prop::collection::vec(any::<u8>(), 0..256)) {
        let mut store = fresh_store();

        store.hset(&key, field.clone(), value.clone(), 0).unwrap();
        let got = store.hget(&key, &field, 0).unwrap();

        prop_assert_eq!(got, Some(value));
    }

    // MR6: ZADD/ZSCORE roundtrip - score is preserved
    #[test]
    fn mr_zset_score_roundtrip(key in prop::collection::vec(any::<u8>(), 1..32),
                               member in prop::collection::vec(any::<u8>(), 1..32),
                               score in -1e10f64..1e10f64) {
        prop_assume!(score.is_finite());

        let mut store = fresh_store();
        store.zadd(&key, &[(score, member.clone())], 0).unwrap();

        let got_score = store.zscore(&key, &member, 0).unwrap();
        prop_assert_eq!(got_score, Some(score));
    }

    // MR7: DEL removes key - SET then DEL then EXISTS must be false
    #[test]
    fn mr_del_removes_key(key in prop::collection::vec(any::<u8>(), 1..32),
                          value in prop::collection::vec(any::<u8>(), 1..64)) {
        let mut store = fresh_store();

        store.set(key.clone(), value, None, 0);
        prop_assert!(store.exists(&key, 0));

        let deleted = store.del(&[key.clone()], 0);
        prop_assert_eq!(deleted, 1);

        prop_assert!(!store.exists(&key, 0), "DEL should remove key");
    }

    // MR8: RENAME preserves value - SET k v; RENAME k k2; GET k2 == v
    #[test]
    fn mr_rename_preserves_value(src in prop::collection::vec(any::<u8>(), 1..32),
                                  dst in prop::collection::vec(any::<u8>(), 1..32),
                                  value in prop::collection::vec(any::<u8>(), 1..64)) {
        prop_assume!(src != dst);

        let mut store = fresh_store();
        store.set(src.clone(), value.clone(), None, 0);

        store.rename(&src, &dst, 0).unwrap();

        prop_assert!(!store.exists(&src, 0), "source key should be gone after RENAME");
        let got = store.get(&dst, 0).unwrap();
        prop_assert_eq!(got, Some(value), "destination should have original value");
    }

    // MR9: APPEND concatenation - SET "a"; APPEND "b"; GET == "ab"
    #[test]
    fn mr_append_concatenates(key in prop::collection::vec(any::<u8>(), 1..32),
                              prefix in prop::collection::vec(any::<u8>(), 0..64),
                              suffix in prop::collection::vec(any::<u8>(), 0..64)) {
        let mut store = fresh_store();

        store.set(key.clone(), prefix.clone(), None, 0);
        let new_len = store.append(&key, &suffix, 0).unwrap();

        let mut expected = prefix;
        expected.extend_from_slice(&suffix);

        prop_assert_eq!(new_len, expected.len());
        let got = store.get(&key, 0).unwrap().unwrap();
        prop_assert_eq!(got, expected);
    }

    // MR10: GETSET returns old value and sets new
    #[test]
    fn mr_getset_returns_old(key in prop::collection::vec(any::<u8>(), 1..32),
                             old_value in prop::collection::vec(any::<u8>(), 1..64),
                             new_value in prop::collection::vec(any::<u8>(), 1..64)) {
        let mut store = fresh_store();

        store.set(key.clone(), old_value.clone(), None, 0);
        let got_old = store.getset(key.clone(), new_value.clone(), 0).unwrap();

        prop_assert_eq!(got_old, Some(old_value));
        let got_new = store.get(&key, 0).unwrap();
        prop_assert_eq!(got_new, Some(new_value));
    }

    // MR11: SETNX only sets if not exists
    #[test]
    fn mr_setnx_respects_existing(key in prop::collection::vec(any::<u8>(), 1..32),
                                   first in prop::collection::vec(any::<u8>(), 1..64),
                                   second in prop::collection::vec(any::<u8>(), 1..64)) {
        let mut store = fresh_store();

        let set1 = store.setnx(key.clone(), first.clone(), 0);
        prop_assert!(set1, "first SETNX should succeed");

        let set2 = store.setnx(key.clone(), second, 0);
        prop_assert!(!set2, "second SETNX should fail");

        let got = store.get(&key, 0).unwrap();
        prop_assert_eq!(got, Some(first), "original value should be preserved");
    }

    // MR12: LPUSH/LLEN consistency - length equals number of pushes
    #[test]
    fn mr_list_len_consistency(key in prop::collection::vec(any::<u8>(), 1..32),
                               count in 1usize..50) {
        let mut store = fresh_store();

        for i in 0..count {
            store.lpush(&key, &[vec![i as u8]], 0).unwrap();
        }

        prop_assert_eq!(store.llen(&key, 0).unwrap(), count);
    }

    // MR13: SREM then SISMEMBER must be false
    #[test]
    fn mr_srem_removes_member(key in prop::collection::vec(any::<u8>(), 1..32),
                              member in prop::collection::vec(any::<u8>(), 1..32)) {
        let mut store = fresh_store();

        store.sadd(&key, &[member.clone()], 0).unwrap();
        prop_assert!(store.sismember(&key, &member, 0).unwrap());

        store.srem(&key, &[member.as_slice()], 0).unwrap();
        prop_assert!(!store.sismember(&key, &member, 0).unwrap(), "SREM should remove member");
    }

    // MR14: HDEL removes field
    #[test]
    fn mr_hdel_removes_field(key in prop::collection::vec(any::<u8>(), 1..32),
                             field in prop::collection::vec(any::<u8>(), 1..32),
                             value in prop::collection::vec(any::<u8>(), 1..64)) {
        let mut store = fresh_store();

        store.hset(&key, field.clone(), value, 0).unwrap();
        prop_assert!(store.hexists(&key, &field, 0).unwrap());

        store.hdel(&key, &[field.as_slice()], 0).unwrap();
        prop_assert!(!store.hexists(&key, &field, 0).unwrap(), "HDEL should remove field");
    }

    // MR15: ZREM removes member
    #[test]
    fn mr_zrem_removes_member(key in prop::collection::vec(any::<u8>(), 1..32),
                              member in prop::collection::vec(any::<u8>(), 1..32),
                              score in -1000.0f64..1000.0f64) {
        prop_assume!(score.is_finite());

        let mut store = fresh_store();

        store.zadd(&key, &[(score, member.clone())], 0).unwrap();
        prop_assert!(store.zscore(&key, &member, 0).unwrap().is_some());

        store.zrem(&key, &[member.as_slice()], 0).unwrap();
        prop_assert!(store.zscore(&key, &member, 0).unwrap().is_none(), "ZREM should remove member");
    }

    // MR16: Multiple INCR is additive
    #[test]
    fn mr_incr_additive(key in prop::collection::vec(any::<u8>(), 1..32),
                        deltas in prop::collection::vec(-1000i64..1000i64, 1..20)) {
        let mut store = fresh_store();
        store.set(key.clone(), b"0".to_vec(), None, 0);

        let mut expected: i64 = 0;
        for delta in &deltas {
            store.incrby(&key, *delta, 0).unwrap();
            expected += delta;
        }

        let got = store.get(&key, 0).unwrap().unwrap();
        let got_val: i64 = String::from_utf8(got).unwrap().parse().unwrap();
        prop_assert_eq!(got_val, expected);
    }

    // MR17: COPY preserves value without modifying source
    #[test]
    fn mr_copy_preserves_both(src in prop::collection::vec(any::<u8>(), 1..32),
                              dst in prop::collection::vec(any::<u8>(), 1..32),
                              value in prop::collection::vec(any::<u8>(), 1..64)) {
        prop_assume!(src != dst);

        let mut store = fresh_store();
        store.set(src.clone(), value.clone(), None, 0);

        let copied = store.copy(&src, &dst, false, 0);
        prop_assert!(copied.is_ok());

        // Source still exists with same value
        let src_val = store.get(&src, 0).unwrap();
        prop_assert_eq!(src_val, Some(value.clone()));

        // Destination has same value
        let dst_val = store.get(&dst, 0).unwrap();
        prop_assert_eq!(dst_val, Some(value));
    }

    // MR18: STRLEN equals value length
    #[test]
    fn mr_strlen_equals_len(key in prop::collection::vec(any::<u8>(), 1..32),
                            value in prop::collection::vec(any::<u8>(), 0..256)) {
        let mut store = fresh_store();
        store.set(key.clone(), value.clone(), None, 0);

        let strlen = store.strlen(&key, 0).unwrap();
        prop_assert_eq!(strlen, value.len());
    }

    // MR19: HLEN equals number of fields
    #[test]
    fn mr_hlen_equals_field_count(key in prop::collection::vec(any::<u8>(), 1..32),
                                   fields in prop::collection::vec(
                                       (prop::collection::vec(any::<u8>(), 1..16),
                                        prop::collection::vec(any::<u8>(), 1..32)),
                                       1..20
                                   )) {
        let mut store = fresh_store();

        // Use a set to track unique fields
        let mut unique_fields = std::collections::HashSet::new();
        for (field, value) in fields {
            store.hset(&key, field.clone(), value, 0).unwrap();
            unique_fields.insert(field);
        }

        let hlen = store.hlen(&key, 0).unwrap();
        prop_assert_eq!(hlen, unique_fields.len());
    }

    // MR20: EXISTS is false for nonexistent key
    #[test]
    fn mr_exists_false_for_nonexistent(key in prop::collection::vec(any::<u8>(), 1..32)) {
        let mut store = fresh_store();
        prop_assert!(!store.exists_no_touch(&key, 0));
    }
}
