use fr_store::Store;

#[test]
fn pfadd_empty_elements() {
    let mut store = Store::new();
    let updated = store.pfadd(b"hll", &[], 0).unwrap();
    println!("updated: {}", updated);
}
