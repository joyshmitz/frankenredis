use fr_command::command_keys;

#[test]
fn test_eval_ro_keys() {
    let argv = vec![
        b"EVAL_RO".to_vec(),
        b"return 1".to_vec(),
        b"2".to_vec(),
        b"key1".to_vec(),
        b"key2".to_vec(),
        b"arg1".to_vec(),
    ];
    let keys = command_keys(&argv);
    assert_eq!(keys, vec![b"key1".to_vec(), b"key2".to_vec()]);
}
