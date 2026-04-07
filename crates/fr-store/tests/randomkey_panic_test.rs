use fr_store::Store;

#[test]
fn test_randomkey_evict_last() {
    let mut store = Store::new();
    store.set(b"key1".to_vec(), b"val1".to_vec(), Some(10), 0);
    // Move time forward so key1 is expired
    // Call randomkey
    let key = store.randomkey(100);
    assert_eq!(key, None);
}
