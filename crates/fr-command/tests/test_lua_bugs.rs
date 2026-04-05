use fr_command::lua_eval::eval_script;
use fr_store::Store;

#[test]
fn test_lua_infinite_loop() {
    let mut store = Store::new();
    let script = b"return string.rep('a', 1024*1024*1024)";
    let res = eval_script(script, &[], &[], &mut store, 0);
    println!("{:?}", res);
}

#[test]
fn test_lua_empty_loop() {
    let mut store = Store::new();
    let script = b"while true do end";
    let res = eval_script(script, &[], &[], &mut store, 0);
    println!("{:?}", res);
}

#[test]
fn test_lua_table_ref() {
    let mut store = Store::new();
    let script = b"
        local a = {}
        local b = a
        b[1] = 'hello'
        return a[1]
    ";
    let res = eval_script(script, &[], &[], &mut store, 0);
    println!("table ref res: {:?}", res);
    assert!(res.is_ok());
}
