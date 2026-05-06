//! Cross-cutting metamorphic invariants for the RESP3-Map vs RESP2-
//! Array shape contract on introspection commands. Pins the family
//! that recently flipped to dual-shape — i40x2 (CLIENT TRACKINGINFO),
//! e4njz (ACL GETUSER), udl3y (MEMORY STATS), asvh1 (FUNCTION STATS).
//!
//! Each invariant compares the RESP2 and RESP3 outputs of the SAME
//! command + state and asserts the shape contract:
//!   - RESP2 Array length is 2× the RESP3 Map entry count.
//!   - The keys in the RESP3 Map appear at even indices in the
//!     RESP2 Array, in the same order.
//!   - The values in the RESP3 Map appear at odd indices, in the
//!     same order.
//!
//! A future refactor that touches the resp_protocol_version branch
//! in one handler but breaks another now gets caught at the family
//! level instead of slipping past the per-command pin tests.
//!
//! (frankenredis-57j9w)
//!
//! ACL GETUSER lives behind the runtime layer (handle_acl_getuser
//! reads self.session.resp_protocol_version), so its invariant is
//! exercised in fr-runtime's own test suite. This file covers the
//! three fr-command-resident handlers that route through
//! dispatch_argv with store.dispatch_client_ctx.resp_protocol_version.

use fr_command::dispatch_argv;
use fr_protocol::RespFrame;
use fr_store::Store;

/// Run `argv` through dispatch_argv twice — once with RESP2, once
/// with RESP3 — using a fresh store (so deterministic state). Returns
/// (resp2_reply, resp3_reply).
fn run_both_protocols(argv: &[Vec<u8>]) -> (RespFrame, RespFrame) {
    let mut store = Store::new();
    // Default protocol_version = 2 (Store::new()).
    let resp2 = dispatch_argv(argv, &mut store, 0).expect("RESP2 dispatch");

    let mut store = Store::new();
    store.dispatch_client_ctx.resp_protocol_version = 3;
    let resp3 = dispatch_argv(argv, &mut store, 0).expect("RESP3 dispatch");

    (resp2, resp3)
}

/// Walk a flat Array of alternating k/v entries and pull out the
/// (key, value) chunks. Panics if the array length is odd or any
/// chunk has the wrong shape.
fn flat_array_to_pairs(items: &[RespFrame]) -> Vec<(RespFrame, RespFrame)> {
    assert!(
        items.len().is_multiple_of(2),
        "flat array must have even length for k/v shape, got {}",
        items.len()
    );
    items
        .chunks(2)
        .map(|chunk| (chunk[0].clone(), chunk[1].clone()))
        .collect()
}

/// Assert RESP2 flat Array of length 2N matches RESP3 Map of length N
/// in key order + paired values.
fn assert_shape_contract(label: &str, resp2: &RespFrame, resp3: &RespFrame) {
    let RespFrame::Array(Some(items)) = resp2 else {
        panic!("{label}: RESP2 reply must be Array, got {resp2:?}"); // ubs:ignore — AI triage
    };
    let RespFrame::Map(Some(entries)) = resp3 else {
        panic!("{label}: RESP3 reply must be Map, got {resp3:?}"); // ubs:ignore — AI triage
    };
    assert_eq!(
        items.len(),
        entries.len() * 2,
        "{label}: RESP2 Array length must be 2× RESP3 Map entry count"
    );
    let array_pairs = flat_array_to_pairs(items);
    for (i, ((map_k, map_v), (arr_k, arr_v))) in
        entries.iter().zip(array_pairs.iter()).enumerate()
    {
        assert_eq!(
            map_k, arr_k,
            "{label}: pair {i} key mismatch — Map key {map_k:?} != Array key {arr_k:?}"
        );
        assert_eq!(
            map_v, arr_v,
            "{label}: pair {i} value mismatch — Map value {map_v:?} != Array value {arr_v:?}"
        );
    }
}

#[test]
fn mr_client_trackinginfo_resp2_array_matches_resp3_map_shape() {
    // i40x2 contract: 3-entry Map ↔ 6-element Array.
    let (resp2, resp3) = run_both_protocols(&[b"CLIENT".to_vec(), b"TRACKINGINFO".to_vec()]);
    assert_shape_contract("CLIENT TRACKINGINFO", &resp2, &resp3);

    // Spot-check the 3 expected keys.
    let RespFrame::Map(Some(entries)) = &resp3 else {
        unreachable!("guarded above"); // ubs:ignore — AI triage
    };
    assert_eq!(entries.len(), 3);
    assert_eq!(
        entries[0].0,
        RespFrame::BulkString(Some(b"flags".to_vec()))
    );
    assert_eq!(
        entries[1].0,
        RespFrame::BulkString(Some(b"redirect".to_vec()))
    );
    assert_eq!(
        entries[2].0,
        RespFrame::BulkString(Some(b"prefixes".to_vec()))
    );
}

#[test]
fn mr_memory_stats_resp2_array_matches_resp3_map_shape() {
    // udl3y contract: ~30+ entries in both shapes.
    let (resp2, resp3) = run_both_protocols(&[b"MEMORY".to_vec(), b"STATS".to_vec()]);
    assert_shape_contract("MEMORY STATS", &resp2, &resp3);

    let RespFrame::Map(Some(entries)) = &resp3 else {
        unreachable!("guarded above"); // ubs:ignore — AI triage
    };
    assert!(
        entries.len() >= 20,
        "MEMORY STATS Map should have >=20 entries, got {}",
        entries.len()
    );
    // First 3 keys are the well-known openers.
    assert_eq!(
        entries[0].0,
        RespFrame::BulkString(Some(b"peak.allocated".to_vec()))
    );
    assert_eq!(
        entries[1].0,
        RespFrame::BulkString(Some(b"total.allocated".to_vec()))
    );
    assert_eq!(
        entries[2].0,
        RespFrame::BulkString(Some(b"startup.allocated".to_vec()))
    );
}

#[test]
fn mr_function_stats_resp3_outer_keys_match_resp2_array_keys() {
    // asvh1 contract is doubly-nested: outer 2-entry Map, inner
    // engines Map, per-engine Map. The flat-Array form has the same
    // outer keys at even indices; the nested values diverge in shape
    // (Array<...> in RESP2 vs Map<...> in RESP3). Pin only the
    // outer-key invariant — the nested shape is verified by asvh1's
    // per-command tests.
    let (resp2, resp3) = run_both_protocols(&[b"FUNCTION".to_vec(), b"STATS".to_vec()]);

    let RespFrame::Array(Some(items)) = &resp2 else {
        panic!("RESP2 FUNCTION STATS must be flat Array, got {resp2:?}"); // ubs:ignore — AI triage
    };
    let RespFrame::Map(Some(entries)) = &resp3 else {
        panic!("RESP3 FUNCTION STATS must be Map, got {resp3:?}"); // ubs:ignore — AI triage
    };
    assert_eq!(items.len(), 4, "RESP2 outer is 4-element flat array");
    assert_eq!(entries.len(), 2, "RESP3 outer is 2-entry Map");
    // Keys match at even indices.
    assert_eq!(items[0], entries[0].0);
    assert_eq!(items[2], entries[1].0);
    // Outer key names are stable.
    assert_eq!(
        entries[0].0,
        RespFrame::BulkString(Some(b"running_script".to_vec()))
    );
    assert_eq!(
        entries[1].0,
        RespFrame::BulkString(Some(b"engines".to_vec()))
    );
}

#[test]
fn mr_protocol_switch_does_not_alter_data() {
    // The wire shape must change with protocol but the underlying
    // *data* must not. After running RESP2 and RESP3 in lockstep
    // against the same fresh store, the (key, value) tuples
    // extracted from each form must be byte-identical for
    // CLIENT TRACKINGINFO and MEMORY STATS. (Not applicable to
    // FUNCTION STATS — its inner shapes diverge by design.)
    for argv in [
        vec![b"CLIENT".to_vec(), b"TRACKINGINFO".to_vec()],
        vec![b"MEMORY".to_vec(), b"STATS".to_vec()],
    ] {
        let (resp2, resp3) = run_both_protocols(&argv);
        let RespFrame::Array(Some(items)) = &resp2 else {
            panic!("expected Array for {argv:?}"); // ubs:ignore — AI triage
        };
        let RespFrame::Map(Some(entries)) = &resp3 else {
            panic!("expected Map for {argv:?}"); // ubs:ignore — AI triage
        };
        let array_pairs = flat_array_to_pairs(items);
        for (i, ((map_k, map_v), (arr_k, arr_v))) in
            entries.iter().zip(array_pairs.iter()).enumerate()
        {
            assert_eq!(
                map_k, arr_k,
                "{argv:?} pair {i} key drift across protocol switch"
            );
            assert_eq!(
                map_v, arr_v,
                "{argv:?} pair {i} value drift across protocol switch"
            );
        }
    }
}
