#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

use fr_protocol::RespFrame;
use fr_store::Store;

/// Fuzz input: a sequence of Redis commands to execute.
#[derive(Debug, Arbitrary)]
struct FuzzInput {
    commands: Vec<FuzzCommand>,
}

/// A single command with its arguments.
#[derive(Debug, Arbitrary)]
enum FuzzCommand {
    // String commands
    Set {
        key: FuzzKey,
        value: FuzzValue,
    },
    Get {
        key: FuzzKey,
    },
    Del {
        keys: Vec<FuzzKey>,
    },
    Incr {
        key: FuzzKey,
    },
    IncrBy {
        key: FuzzKey,
        delta: i64,
    },
    Decr {
        key: FuzzKey,
    },
    Append {
        key: FuzzKey,
        value: FuzzValue,
    },
    Strlen {
        key: FuzzKey,
    },

    // List commands
    LPush {
        key: FuzzKey,
        values: Vec<FuzzValue>,
    },
    RPush {
        key: FuzzKey,
        values: Vec<FuzzValue>,
    },
    LPop {
        key: FuzzKey,
    },
    RPop {
        key: FuzzKey,
    },
    LLen {
        key: FuzzKey,
    },
    LRange {
        key: FuzzKey,
        start: i32,
        stop: i32,
    },

    // Set commands
    SAdd {
        key: FuzzKey,
        members: Vec<FuzzValue>,
    },
    SRem {
        key: FuzzKey,
        members: Vec<FuzzValue>,
    },
    SMembers {
        key: FuzzKey,
    },
    SCard {
        key: FuzzKey,
    },
    SIsMember {
        key: FuzzKey,
        member: FuzzValue,
    },

    // Hash commands
    HSet {
        key: FuzzKey,
        field: FuzzValue,
        value: FuzzValue,
    },
    HGet {
        key: FuzzKey,
        field: FuzzValue,
    },
    HDel {
        key: FuzzKey,
        fields: Vec<FuzzValue>,
    },
    HLen {
        key: FuzzKey,
    },
    HGetAll {
        key: FuzzKey,
    },

    // Sorted set commands
    ZAdd {
        key: FuzzKey,
        score: f64,
        member: FuzzValue,
    },
    ZRem {
        key: FuzzKey,
        members: Vec<FuzzValue>,
    },
    ZScore {
        key: FuzzKey,
        member: FuzzValue,
    },
    ZCard {
        key: FuzzKey,
    },
    ZRange {
        key: FuzzKey,
        start: i32,
        stop: i32,
    },

    // Key commands
    Exists {
        keys: Vec<FuzzKey>,
    },
    Type {
        key: FuzzKey,
    },
    Expire {
        key: FuzzKey,
        seconds: u32,
    },
    Ttl {
        key: FuzzKey,
    },
    Persist {
        key: FuzzKey,
    },

    // DB commands
    DbSize,
    FlushDb,
    Keys {
        pattern: FuzzPattern,
    },
}

#[derive(Debug, Arbitrary, Clone)]
struct FuzzKey(Vec<u8>);

#[derive(Debug, Arbitrary, Clone)]
struct FuzzValue(Vec<u8>);

#[derive(Debug, Arbitrary, Clone)]
struct FuzzPattern(Vec<u8>);

impl FuzzKey {
    fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl FuzzValue {
    fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl FuzzPattern {
    fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl FuzzCommand {
    fn to_resp_frame(&self) -> RespFrame {
        fn bulk(data: &[u8]) -> RespFrame {
            RespFrame::BulkString(Some(data.to_vec()))
        }

        fn cmd(name: &[u8]) -> RespFrame {
            bulk(name)
        }

        let parts: Vec<RespFrame> = match self {
            FuzzCommand::Set { key, value } => {
                vec![cmd(b"SET"), bulk(key.as_bytes()), bulk(value.as_bytes())]
            }
            FuzzCommand::Get { key } => vec![cmd(b"GET"), bulk(key.as_bytes())],
            FuzzCommand::Del { keys } => {
                let mut v = vec![cmd(b"DEL")];
                v.extend(keys.iter().map(|k| bulk(k.as_bytes())));
                v
            }
            FuzzCommand::Incr { key } => vec![cmd(b"INCR"), bulk(key.as_bytes())],
            FuzzCommand::IncrBy { key, delta } => vec![
                cmd(b"INCRBY"),
                bulk(key.as_bytes()),
                bulk(delta.to_string().as_bytes()),
            ],
            FuzzCommand::Decr { key } => vec![cmd(b"DECR"), bulk(key.as_bytes())],
            FuzzCommand::Append { key, value } => {
                vec![cmd(b"APPEND"), bulk(key.as_bytes()), bulk(value.as_bytes())]
            }
            FuzzCommand::Strlen { key } => vec![cmd(b"STRLEN"), bulk(key.as_bytes())],

            FuzzCommand::LPush { key, values } => {
                let mut v = vec![cmd(b"LPUSH"), bulk(key.as_bytes())];
                v.extend(values.iter().map(|val| bulk(val.as_bytes())));
                v
            }
            FuzzCommand::RPush { key, values } => {
                let mut v = vec![cmd(b"RPUSH"), bulk(key.as_bytes())];
                v.extend(values.iter().map(|val| bulk(val.as_bytes())));
                v
            }
            FuzzCommand::LPop { key } => vec![cmd(b"LPOP"), bulk(key.as_bytes())],
            FuzzCommand::RPop { key } => vec![cmd(b"RPOP"), bulk(key.as_bytes())],
            FuzzCommand::LLen { key } => vec![cmd(b"LLEN"), bulk(key.as_bytes())],
            FuzzCommand::LRange { key, start, stop } => vec![
                cmd(b"LRANGE"),
                bulk(key.as_bytes()),
                bulk(start.to_string().as_bytes()),
                bulk(stop.to_string().as_bytes()),
            ],

            FuzzCommand::SAdd { key, members } => {
                let mut v = vec![cmd(b"SADD"), bulk(key.as_bytes())];
                v.extend(members.iter().map(|m| bulk(m.as_bytes())));
                v
            }
            FuzzCommand::SRem { key, members } => {
                let mut v = vec![cmd(b"SREM"), bulk(key.as_bytes())];
                v.extend(members.iter().map(|m| bulk(m.as_bytes())));
                v
            }
            FuzzCommand::SMembers { key } => vec![cmd(b"SMEMBERS"), bulk(key.as_bytes())],
            FuzzCommand::SCard { key } => vec![cmd(b"SCARD"), bulk(key.as_bytes())],
            FuzzCommand::SIsMember { key, member } => {
                vec![
                    cmd(b"SISMEMBER"),
                    bulk(key.as_bytes()),
                    bulk(member.as_bytes()),
                ]
            }

            FuzzCommand::HSet { key, field, value } => vec![
                cmd(b"HSET"),
                bulk(key.as_bytes()),
                bulk(field.as_bytes()),
                bulk(value.as_bytes()),
            ],
            FuzzCommand::HGet { key, field } => {
                vec![cmd(b"HGET"), bulk(key.as_bytes()), bulk(field.as_bytes())]
            }
            FuzzCommand::HDel { key, fields } => {
                let mut v = vec![cmd(b"HDEL"), bulk(key.as_bytes())];
                v.extend(fields.iter().map(|f| bulk(f.as_bytes())));
                v
            }
            FuzzCommand::HLen { key } => vec![cmd(b"HLEN"), bulk(key.as_bytes())],
            FuzzCommand::HGetAll { key } => vec![cmd(b"HGETALL"), bulk(key.as_bytes())],

            FuzzCommand::ZAdd { key, score, member } => vec![
                cmd(b"ZADD"),
                bulk(key.as_bytes()),
                bulk(score.to_string().as_bytes()),
                bulk(member.as_bytes()),
            ],
            FuzzCommand::ZRem { key, members } => {
                let mut v = vec![cmd(b"ZREM"), bulk(key.as_bytes())];
                v.extend(members.iter().map(|m| bulk(m.as_bytes())));
                v
            }
            FuzzCommand::ZScore { key, member } => {
                vec![
                    cmd(b"ZSCORE"),
                    bulk(key.as_bytes()),
                    bulk(member.as_bytes()),
                ]
            }
            FuzzCommand::ZCard { key } => vec![cmd(b"ZCARD"), bulk(key.as_bytes())],
            FuzzCommand::ZRange { key, start, stop } => vec![
                cmd(b"ZRANGE"),
                bulk(key.as_bytes()),
                bulk(start.to_string().as_bytes()),
                bulk(stop.to_string().as_bytes()),
            ],

            FuzzCommand::Exists { keys } => {
                let mut v = vec![cmd(b"EXISTS")];
                v.extend(keys.iter().map(|k| bulk(k.as_bytes())));
                v
            }
            FuzzCommand::Type { key } => vec![cmd(b"TYPE"), bulk(key.as_bytes())],
            FuzzCommand::Expire { key, seconds } => vec![
                cmd(b"EXPIRE"),
                bulk(key.as_bytes()),
                bulk(seconds.to_string().as_bytes()),
            ],
            FuzzCommand::Ttl { key } => vec![cmd(b"TTL"), bulk(key.as_bytes())],
            FuzzCommand::Persist { key } => vec![cmd(b"PERSIST"), bulk(key.as_bytes())],

            FuzzCommand::DbSize => vec![cmd(b"DBSIZE")],
            FuzzCommand::FlushDb => vec![cmd(b"FLUSHDB")],
            FuzzCommand::Keys { pattern } => vec![cmd(b"KEYS"), bulk(pattern.as_bytes())],
        };

        RespFrame::Array(Some(parts))
    }
}

fuzz_target!(|input: FuzzInput| {
    // Guard against excessively long sequences
    if input.commands.len() > 100 {
        return;
    }

    // Guard against excessively large keys/values
    for cmd in &input.commands {
        let too_large = match cmd {
            FuzzCommand::Set { key, value } => key.0.len() > 1000 || value.0.len() > 10000,
            FuzzCommand::LPush { key, values } | FuzzCommand::RPush { key, values } => {
                key.0.len() > 1000 || values.iter().any(|v| v.0.len() > 10000) || values.len() > 100
            }
            FuzzCommand::SAdd { key, members } => {
                key.0.len() > 1000
                    || members.iter().any(|m| m.0.len() > 10000)
                    || members.len() > 100
            }
            FuzzCommand::Del { keys } | FuzzCommand::Exists { keys } => {
                keys.iter().any(|k| k.0.len() > 1000) || keys.len() > 100
            }
            _ => false,
        };
        if too_large {
            return;
        }
    }

    // Create a fresh store for each fuzzing iteration
    let mut store = Store::default();
    let mut now_ms = 1000u64;

    // Execute all commands in sequence
    for cmd in &input.commands {
        let frame = cmd.to_resp_frame();

        // Use fr_command::dispatch_argv directly since we can't easily access Runtime
        if let RespFrame::Array(Some(parts)) = &frame {
            let argv: Vec<Vec<u8>> = parts
                .iter()
                .filter_map(|p| {
                    if let RespFrame::BulkString(Some(data)) = p {
                        Some(data.clone())
                    } else {
                        None
                    }
                })
                .collect();

            if !argv.is_empty() {
                let _ = fr_command::dispatch_argv(&argv, &mut store, now_ms);
            }
        }

        // Advance time slightly to test expiration
        now_ms += 1;
    }

    // Basic invariant: store shouldn't be in a corrupted state
    // This will catch panics during iteration
    let _ = store.dbsize(now_ms);
});
