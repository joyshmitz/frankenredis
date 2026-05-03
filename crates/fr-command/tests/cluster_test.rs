use fr_command::{dispatch_argv, CommandError};
use fr_protocol::RespFrame;
use fr_store::Store;

fn cluster_disabled_error() -> CommandError {
    CommandError::Custom("ERR This instance has cluster support disabled".to_string())
}

#[test]
fn test_cluster_keyslot() {
    let mut store = Store::new();
    store.cluster_enabled = true;
    let out = dispatch_argv(
        &[b"CLUSTER".to_vec(), b"KEYSLOT".to_vec(), b"hello".to_vec()],
        &mut store,
        0,
    )
    .unwrap();

    // Hash of "hello" is 866
    assert_eq!(out, RespFrame::Integer(866));
}

#[test]
fn test_cluster_keyslot_hashtag() {
    let mut store = Store::new();
    store.cluster_enabled = true;
    let out = dispatch_argv(
        &[
            b"CLUSTER".to_vec(),
            b"KEYSLOT".to_vec(),
            b"{foo}bar".to_vec(),
        ],
        &mut store,
        0,
    )
    .unwrap();

    // Hash of "{foo}bar" is just the hash of "foo" = 12182
    assert_eq!(out, RespFrame::Integer(12182));
}

#[test]
fn test_cluster_getkeysinslot_and_countkeysinslot() {
    let mut store = Store::new();
    store.cluster_enabled = true;

    // The keys "foo" and "{foo}bar" will both hash to slot 12182
    dispatch_argv(
        &[b"SET".to_vec(), b"foo".to_vec(), b"val".to_vec()],
        &mut store,
        0,
    )
    .unwrap();
    dispatch_argv(
        &[b"SET".to_vec(), b"{foo}bar".to_vec(), b"val".to_vec()],
        &mut store,
        0,
    )
    .unwrap();

    // 1. COUNTKEYSINSLOT
    let out = dispatch_argv(
        &[
            b"CLUSTER".to_vec(),
            b"COUNTKEYSINSLOT".to_vec(),
            b"12182".to_vec(),
        ],
        &mut store,
        0,
    )
    .unwrap();
    assert_eq!(out, RespFrame::Integer(2));

    // 2. GETKEYSINSLOT count 1
    let out = dispatch_argv(
        &[
            b"CLUSTER".to_vec(),
            b"GETKEYSINSLOT".to_vec(),
            b"12182".to_vec(),
            b"1".to_vec(),
        ],
        &mut store,
        0,
    )
    .unwrap();

    match out {
        RespFrame::Array(Some(arr)) => {
            assert_eq!(arr.len(), 1);
        }
        other => assert_eq!(other, RespFrame::Array(Some(Vec::new()))),
    }

    // 3. GETKEYSINSLOT count 10
    let out = dispatch_argv(
        &[
            b"CLUSTER".to_vec(),
            b"GETKEYSINSLOT".to_vec(),
            b"12182".to_vec(),
            b"10".to_vec(),
        ],
        &mut store,
        0,
    )
    .unwrap();

    match out {
        RespFrame::Array(Some(arr)) => {
            assert_eq!(arr.len(), 2);
        }
        other => assert_eq!(other, RespFrame::Array(Some(Vec::new()))),
    }
}

#[test]
fn test_cluster_setslot_forms_return_cluster_disabled_when_off() {
    let mut store = Store::new();

    for argv in [
        vec![
            b"CLUSTER".to_vec(),
            b"SETSLOT".to_vec(),
            b"42".to_vec(),
            b"STABLE".to_vec(),
        ],
        vec![
            b"CLUSTER".to_vec(),
            b"SETSLOT".to_vec(),
            b"42".to_vec(),
            b"NODE".to_vec(),
            b"07c37dfeb2352e0b575fe7d96032e8c29a662a44".to_vec(),
        ],
        vec![
            b"CLUSTER".to_vec(),
            b"SETSLOT".to_vec(),
            b"42".to_vec(),
            b"MIGRATING".to_vec(),
            b"07c37dfeb2352e0b575fe7d96032e8c29a662a44".to_vec(),
        ],
        vec![
            b"CLUSTER".to_vec(),
            b"SETSLOT".to_vec(),
            b"42".to_vec(),
            b"IMPORTING".to_vec(),
            b"07c37dfeb2352e0b575fe7d96032e8c29a662a44".to_vec(),
        ],
    ] {
        let err = dispatch_argv(&argv, &mut store, 0).unwrap_err();
        assert_eq!(err, cluster_disabled_error(), "argv={argv:?}");
    }
}

#[test]
fn test_cluster_failover_force_takeover_returns_cluster_disabled_when_off() {
    let mut store = Store::new();

    for argv in [
        vec![
            b"CLUSTER".to_vec(),
            b"FAILOVER".to_vec(),
            b"FORCE".to_vec(),
            b"TAKEOVER".to_vec(),
        ],
        vec![
            b"CLUSTER".to_vec(),
            b"FAILOVER".to_vec(),
            b"TAKEOVER".to_vec(),
            b"FORCE".to_vec(),
        ],
    ] {
        let err = dispatch_argv(&argv, &mut store, 0).unwrap_err();
        assert_eq!(err, cluster_disabled_error(), "argv={argv:?}");
    }
}
