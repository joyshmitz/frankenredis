#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

use fr_command::{
    check_command_arity, command_key_indexes, command_keys, frame_to_argv, is_known_command,
    is_write_command,
};
use fr_protocol::{RespFrame, parse_frame};

/// A structured command representation for structure-aware fuzzing.
#[derive(Debug, Arbitrary)]
struct FuzzInput {
    /// Raw bytes to test RESP parsing path
    raw_bytes: Vec<u8>,
    /// Structured command to test classification invariants
    command: FuzzCommand,
}

#[derive(Debug, Arbitrary)]
struct FuzzCommand {
    name: Vec<u8>,
    args: Vec<Vec<u8>>,
}

impl FuzzCommand {
    fn to_argv(&self) -> Vec<Vec<u8>> {
        let mut argv = vec![self.name.clone()];
        argv.extend(self.args.iter().cloned());
        argv
    }

    fn to_resp_frame(&self) -> RespFrame {
        let items: Vec<RespFrame> = self
            .to_argv()
            .into_iter()
            .map(|arg| RespFrame::BulkString(Some(arg)))
            .collect();
        RespFrame::Array(Some(items))
    }
}

fuzz_target!(|input: FuzzInput| {
    // Guard against excessively large inputs
    if input.raw_bytes.len() > 100_000 {
        return;
    }
    if input.command.name.len() > 64 || input.command.args.len() > 1000 {
        return;
    }
    for arg in &input.command.args {
        if arg.len() > 10_000 {
            return;
        }
    }

    // Path 1: Raw bytes -> RESP parse -> frame_to_argv
    if let Ok(result) = parse_frame(&input.raw_bytes) {
        let _ = frame_to_argv(&result.frame);
    }

    // Path 2: Structured command testing
    let cmd = &input.command;
    let argv = cmd.to_argv();

    // Test pure classification functions - these must not panic
    let _ = is_known_command(&cmd.name);
    let _ = is_write_command(&cmd.name);
    let _ = check_command_arity(&cmd.name, argv.len());

    // Test key extraction
    let keys = command_keys(&argv);
    let indexes = command_key_indexes(&argv);

    // Invariant: indexes should match keys
    let extracted_keys: Vec<Vec<u8>> = indexes
        .iter()
        .filter_map(|&i| argv.get(i).cloned())
        .collect();
    assert_eq!(
        extracted_keys.len(),
        keys.len(),
        "key count mismatch for command {:?}",
        String::from_utf8_lossy(&cmd.name)
    );

    // Test frame_to_argv roundtrip
    let frame = cmd.to_resp_frame();
    let recovered = frame_to_argv(&frame).expect("valid frame should parse");
    assert_eq!(recovered, argv, "frame_to_argv roundtrip failed");
});
