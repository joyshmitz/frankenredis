# Changelog

All notable changes to FrankenRedis are documented in this file.

FrankenRedis is a clean-room Rust reimplementation of Redis targeting full drop-in replacement parity.
This project has no tagged releases or GitHub Releases yet; the changelog is organized by date-bounded
development phases derived from the linear commit history on `main`. Workspace version: **0.1.0**.

Repository: <https://github.com/Dicklesworthstone/frankenredis>

---

## [Unreleased] — development on `main` (as of 2026-03-21)

275 commits across 24 active development days. 11-crate Cargo workspace. 227+ command handlers.
3577 conformance fixture cases. No tags, no releases.

---

## Phase 7 — Real Server Telemetry, Pub/Sub Delivery, Lua Hardening (2026-03-20 .. 2026-03-21)

### Pub/Sub cross-client message delivery
- Implement multi-client Pub/Sub registry in `ServerState` with global channel/pattern routing
  ([9f0b357](https://github.com/Dicklesworthstone/frankenredis/commit/9f0b357e23621ce36ab65ebcdbd02638b2a812ea))
- Wire SUBSCRIBE/UNSUBSCRIBE/PSUBSCRIBE/PUNSUBSCRIBE/PUBLISH through the real TCP server with
  cross-client fan-out
  ([c68fafd](https://github.com/Dicklesworthstone/frankenredis/commit/c68fafd139021c23cf4af6c5fa715fe05e0c9430),
   [40f6ebb](https://github.com/Dicklesworthstone/frankenredis/commit/40f6ebb4f1f931436ec886a630648e9aaff2123c))
- Enforce subscription-mode command restriction (only SUBSCRIBE/UNSUBSCRIBE/PSUBSCRIBE/PUNSUBSCRIBE/PING/RESET allowed)
  ([b510512](https://github.com/Dicklesworthstone/frankenredis/commit/b510512b26fba78b0a62c7847a2f23ef29ff3d24))
- Deterministic channel/pattern ordering in unsubscribe-all responses
  ([6b7e1ee](https://github.com/Dicklesworthstone/frankenredis/commit/6b7e1ee3346fdf7e80d35fa62af8d7543f1f29d1))
- Fix multi-channel subscribe/unsubscribe response format
  ([a5a5e3c](https://github.com/Dicklesworthstone/frankenredis/commit/a5a5e3cc3327876df8e0a43a1713857b3deb33de))

### INFO real statistics and COMMAND LIST FILTERBY
- INFO now reports real `connected_clients`, `total_commands_processed`, `total_connections_received`,
  `run_id`, `process_id`, `tcp_port`, `used_memory`, `maxmemory_policy`, dirty counter, expires count
  ([b9a50d3](https://github.com/Dicklesworthstone/frankenredis/commit/b9a50d32c2890d88eecc05da39c7ec6b2143c853),
   [d59d4fd](https://github.com/Dicklesworthstone/frankenredis/commit/d59d4fd0002a7ae1c75d7071871f08fb0998c0b0))
- Implement `COMMAND LIST FILTERBY MODULE|ACLCAT|PATTERN`
  ([14c1f6a](https://github.com/Dicklesworthstone/frankenredis/commit/14c1f6ac60255c02b4510465227d11b32ee82468))
- `RESET` now clears pub/sub subscriptions
  ([14c1f6a](https://github.com/Dicklesworthstone/frankenredis/commit/14c1f6ac60255c02b4510465227d11b32ee82468))

### Lua scripting hardening
- Harden Lua `table.insert`, `table.remove`, `table.sort`, `table.concat` with proper type checking and bounds validation
  ([f1816d5](https://github.com/Dicklesworthstone/frankenredis/commit/f1816d5660ae2789cf532be162fb259dba17c396),
   [30c050e](https://github.com/Dicklesworthstone/frankenredis/commit/30c050eae8936b70a414dd63faed2bc1a2df425a))
- Fix `next()` iteration over tables with non-sequential keys
  ([30c050e](https://github.com/Dicklesworthstone/frankenredis/commit/30c050eae8936b70a414dd63faed2bc1a2df425a))
- Fix `select()` to handle negative indices and reject zero index per Lua 5.1 spec
  ([616ea53](https://github.com/Dicklesworthstone/frankenredis/commit/616ea5314f667c151e3bbc50da6e9ad89ef5dcdf))
- Strict numeric argument validation for Lua table library functions
  ([6169d70](https://github.com/Dicklesworthstone/frankenredis/commit/6169d700b38b9d16dfb6e30a245584348b06eb5b))
- Nested table assignment write-back and deterministic set ordering
  ([ed1a81d](https://github.com/Dicklesworthstone/frankenredis/commit/ed1a81d92fa5c78f81e78fed78f9d45f7b122df1))
- Exact float equality in Lua runtime
  ([c20cc7f](https://github.com/Dicklesworthstone/frankenredis/commit/c20cc7f73dfefcb4082c682f5f174f46a47f7a3a))

### Sorted set correctness
- Use `total_cmp` for sorted set score comparisons, reject infinity in increments
  ([cc36c39](https://github.com/Dicklesworthstone/frankenredis/commit/cc36c397d6056bbb3cc2013c6707f94ba7563d38))
- Negative-zero score canonicalization
  ([d3213f4](https://github.com/Dicklesworthstone/frankenredis/commit/d3213f47ce75bb5f19b08b9c7bf3770a90103b32))

### Server and persistence fixes
- Enable TCP_NODELAY and fix session swapping bug in `check_blocked_clients`
  ([05733ec](https://github.com/Dicklesworthstone/frankenredis/commit/05733ec981c8efc50ccd1bb148ca56c01ac4a551))
- Make AOF replay fail-closed; abort MULTI on unknown commands during replay
  ([2542319](https://github.com/Dicklesworthstone/frankenredis/commit/254231949fd2c6655d12789683871b1e3e554908))
- Handle RDB eviction opcodes; optimize pub/sub client lookup
  ([8005379](https://github.com/Dicklesworthstone/frankenredis/commit/8005379aea59c60f9a7ff799f4e2c6ed189276ff))
- Add RDB 64-bit length encoding support
  ([22797a3](https://github.com/Dicklesworthstone/frankenredis/commit/22797a360adb5ba13b9970488ab7954404a7e42d))
- Fix LTRIM and LRANGE index normalization for out-of-range indices
  ([22447c1](https://github.com/Dicklesworthstone/frankenredis/commit/22447c1772f6f3ff3aaea387e82ea4190387bd31))
- Correct INCRBYFLOAT infinity handling
  ([346f4e0](https://github.com/Dicklesworthstone/frankenredis/commit/346f4e03a5fe373f0b896fde50745b789aaa1d17))
- Improve subcommand error handling; add HELP subcommands
  ([ec18e3d](https://github.com/Dicklesworthstone/frankenredis/commit/ec18e3d8bff2fdd91f7be292fa1907579daaf0c4))

---

## Phase 6 — TCP Server, Blocking Infrastructure, Crash-Safe Persistence (2026-03-15 .. 2026-03-19)

### Standalone TCP server (`fr-server` crate)
- Add `fr-server` crate with `mio`-based non-blocking TCP event loop and RESP wire protocol
  ([9e3d06a](https://github.com/Dicklesworthstone/frankenredis/commit/9e3d06aa128258c8d74014560c7234ae9f820d72),
   [ede9226](https://github.com/Dicklesworthstone/frankenredis/commit/ede9226375ec3531522c27f57b816deee93f677d))
- Expand TCP server with connection handling, auth, multi-client session management
  ([df69fbf](https://github.com/Dicklesworthstone/frankenredis/commit/df69fbf9d83b71a355e8d85a38837b7c9ce9375e),
   [91e561b](https://github.com/Dicklesworthstone/frankenredis/commit/91e561b2890fb6cc32a6d1a09942575a8d31535c))
- Restructure sorted sets for server-level store sharing
  ([b2746b0](https://github.com/Dicklesworthstone/frankenredis/commit/b2746b039ed36a6bf5ff08f896088523183ac433))

### Blocking command infrastructure
- Wire BLPOP/BRPOP/BLMOVE/BLMPOP/BRPOPLPUSH to blocking infrastructure with timeout handling
  ([e2d46cc](https://github.com/Dicklesworthstone/frankenredis/commit/e2d46cc3ccddb6d27d6b08d6113f3b349c08c94e),
   [a38e28a](https://github.com/Dicklesworthstone/frankenredis/commit/a38e28a19a51d33aef2179c943460742877fd125))
- Wire BZPOPMIN/BZPOPMAX/BZMPOP to blocking sorted-set operations
  ([4fd3e61](https://github.com/Dicklesworthstone/frankenredis/commit/4fd3e613f23a95b829978b901cb94d4602cf5765))
- Wire XREAD BLOCK and XREADGROUP BLOCK to blocking infrastructure
  ([05f9bb1](https://github.com/Dicklesworthstone/frankenredis/commit/05f9bb155edc61603194f39b16a4ba2f5c309fb5))
- Prevent command processing during blocking operations
  ([045ae0a](https://github.com/Dicklesworthstone/frankenredis/commit/045ae0a5c14126020289f7b81fc041f1520fbd85))
- Non-finite blocking timeout rejection
  ([d3213f4](https://github.com/Dicklesworthstone/frankenredis/commit/d3213f47ce75bb5f19b08b9c7bf3770a90103b32))

### Crash-safe persistence and integrity
- Ensure crash-safe AOF persistence with atomic file I/O and mtime tracking
  ([a38e28a](https://github.com/Dicklesworthstone/frankenredis/commit/a38e28a19a51d33aef2179c943460742877fd125))
- Add CRC64 integrity checks to RDB format
  ([4fd3e61](https://github.com/Dicklesworthstone/frankenredis/commit/4fd3e613f23a95b829978b901cb94d4602cf5765))
- Update PubSub protocol, command execution, and AOF loading paths
  ([33d2f1f](https://github.com/Dicklesworthstone/frankenredis/commit/33d2f1f77ce6b40826fb6aa30539ecf12b057bae))

### ACL, config, and encoding refinements
- Real memory reporting (`used_memory`) and list encoding config (`list-max-listpack-entries/value`)
  ([39469db](https://github.com/Dicklesworthstone/frankenredis/commit/39469db9c50afebf034176179df6c3a5c6b98082))
- Enforce ACL gating on all commands; add dirty-flag mutation tracking
  ([e05c7c3](https://github.com/Dicklesworthstone/frankenredis/commit/e05c7c39b95d6ff78968cd8d5fab544e24da86c8))
- Correct list OBJECT ENCODING thresholds
  ([e50e4be](https://github.com/Dicklesworthstone/frankenredis/commit/e50e4be60adbbb880e085b3870e485ebeac9497c))
- JSON control character escaping and legacy listpack sizing
  ([4817797](https://github.com/Dicklesworthstone/frankenredis/commit/4817797c77dea536de2eb917f85b98889f33dcb9))

---

## Phase 5 — Architecture Split, Streams Maturity, Encoding Thresholds (2026-03-13 .. 2026-03-14)

### Runtime architecture refactor
- Split monolithic `Runtime` into `ServerState` + `ClientSession` for multi-client readiness
  ([01065d1](https://github.com/Dicklesworthstone/frankenredis/commit/01065d165200cedead1aef20cfee436af314221a))
- Move per-session auth state from `AuthState` to `ClientSession`
  ([ff8d62d](https://github.com/Dicklesworthstone/frankenredis/commit/ff8d62d463cc9d48c875dda96aba7d056bb25824))

### Stream command maturity
- XADD MAXLEN/MINID/NOMKSTREAM and XTRIM MINID trimming support
  ([be92f56](https://github.com/Dicklesworthstone/frankenredis/commit/be92f56b1608a3dde12a3c1c15b0e0500f3eadfb))
- XADD partial auto-ID (`ms-*`) for explicit timestamp with server-generated sequence
  ([7c36749](https://github.com/Dicklesworthstone/frankenredis/commit/7c36749bcea630a366525c85b3a853f3f300a533))
- XINFO STREAM FULL option with entries and group details
  ([6eece57](https://github.com/Dicklesworthstone/frankenredis/commit/6eece5752ae34aa715c62d943e30c09c90754114))
- Serialize stream consumer groups and XSETID in AOF output
  ([6e55a18](https://github.com/Dicklesworthstone/frankenredis/commit/6e55a18c5b6b845884d027b84e42305abfcb13de))
- Copy stream `last-generated-id` during COPY command
  ([551be7a](https://github.com/Dicklesworthstone/frankenredis/commit/551be7a9459c7e538314e1885f8035bab4b6f9ad))

### Encoding and config
- Add configurable encoding thresholds for hash, set, and zset types
  ([e18584c](https://github.com/Dicklesworthstone/frankenredis/commit/e18584c23b315ca885387683edd3193559707673))
- Add BITFIELD_RO command, LRU idle-time tracking, CONFIG SET persistence
  ([8cf020a](https://github.com/Dicklesworthstone/frankenredis/commit/8cf020a1435049ccb30fa30efe44dec67c21aed2))
- Persist CONFIG SET runtime state
  ([162af03](https://github.com/Dicklesworthstone/frankenredis/commit/162af03a7e65155c95119441e03d0a2a51e6429d))

### Conformance expansion
- Add dedicated smoke tests for `core_strings` and `core_errors`
  ([1c86790](https://github.com/Dicklesworthstone/frankenredis/commit/1c8679060d676aca7078f8d75e15260129ef47e6))
- Add 21 HyperLogLog, 22 SCAN, 28 DBSIZE/RANDOMKEY/OBJECT/COMMAND/DEBUG tests
  ([7fb3cc2](https://github.com/Dicklesworthstone/frankenredis/commit/7fb3cc28d42d668515ab3a9003e9de68162f6e9e),
   [bf5d813](https://github.com/Dicklesworthstone/frankenredis/commit/bf5d813eaed06f569af805fc499a877bd2bcd480),
   [3b2b89c](https://github.com/Dicklesworthstone/frankenredis/commit/3b2b89c8ae1104e79570d35d549cf6239ecf87de))

---

## Phase 4 — Massive Conformance Expansion, Lua Scripting, Redis 7 Compat (2026-03-03 .. 2026-03-12)

### Conformance test count: ~1500 to 3577 cases
- Systematic multi-round fixture expansion across all command families, reaching 3577 core conformance cases
- Key milestones: 2041 total
  ([64b7a44](https://github.com/Dicklesworthstone/frankenredis/commit/64b7a4475400a9d7ef37c85de520730666ec40ac)),
  2302
  ([fbb8fd2](https://github.com/Dicklesworthstone/frankenredis/commit/fbb8fd2df0a6a32c750d5094575daf86cc1e8dd2)),
  2666
  ([392fbb7](https://github.com/Dicklesworthstone/frankenredis/commit/392fbb7a7017cbf79b8102cc0f90b790eee5bbb7)),
  3000+
  ([38af4a5](https://github.com/Dicklesworthstone/frankenredis/commit/38af4a532d62b45cbca725ca76d859e603ae7dd1)),
  3336
  ([c9874cc](https://github.com/Dicklesworthstone/frankenredis/commit/c9874ccce7c69d02568e3139a47bd00a3f3acfce))
- 108 blocking command tests
  ([820a772](https://github.com/Dicklesworthstone/frankenredis/commit/820a772b20e909ebf3275b9fa2b5c3f9a10603ee))
- 28 WRONGTYPE cross-type error tests
  ([ab82985](https://github.com/Dicklesworthstone/frankenredis/commit/ab829856563a045cba188d69281bad25caca02e9))
- Replication tests expanded from 16 to 51; WAIT tests from 23 to 43
  ([2df3407](https://github.com/Dicklesworthstone/frankenredis/commit/2df340795a16cf58d63eb43e4641e56119a2e579),
   [09e280e](https://github.com/Dicklesworthstone/frankenredis/commit/09e280e5e82e883d61e4a07f7780f36aa39816b7))

### Full Lua 5.1 standard library
- String pattern matching engine (match/gmatch/gsub/find with character classes, quantifiers, anchors, captures)
  ([9c89d6d](https://github.com/Dicklesworthstone/frankenredis/commit/9c89d6d350e86bf2341a2f49d15077ccad7b4bcb))
- `string.format` with full width/precision/flags support
  ([050038d](https://github.com/Dicklesworthstone/frankenredis/commit/050038dffaae01a20d0e9c7fa65ac7f6f14354b8))
- `string.gmatch` iterator, `pcall`/`xpcall` error handling
  ([dc8db5d](https://github.com/Dicklesworthstone/frankenredis/commit/dc8db5d8affcea0f4be8236d2aa396abc366f9d9))
- `table.sort` custom comparator, `rawset` mutation fix
  ([0dfb2f1](https://github.com/Dicklesworthstone/frankenredis/commit/0dfb2f1d9b2ae07e1dc1cd5db0597d33e3e1784e))
- `table.sort`/`insert`/`remove` now mutate caller's variable correctly
  ([f126d1a](https://github.com/Dicklesworthstone/frankenredis/commit/f126d1ad92e86145d21d1eab03d53579ed472aaf))
- Math trig functions, `math.log10`/`modf`/`frexp`/`ldexp`, `os.clock`, redis stubs
  ([9f05567](https://github.com/Dicklesworthstone/frankenredis/commit/9f055675c5390ca6326b84b5733ca2e813106a9d),
   [cc0f4a1](https://github.com/Dicklesworthstone/frankenredis/commit/cc0f4a1193e757bda82097be7971bb1da9e46a17))
- Fix FCALL execution by transforming `register_function` into callable Lua
  ([c5cbcab](https://github.com/Dicklesworthstone/frankenredis/commit/c5cbcabff936251d144c2dce8326fd7e36bf2a2b))

### Redis 7.2 compatibility
- Full Redis 7.2-compatible HELLO response with client identity fields
  ([e333d50](https://github.com/Dicklesworthstone/frankenredis/commit/e333d50d0f6264e5df04654ddbb981b9ab794a68))
- HELLO with no args and SETNAME option
  ([2f60fb9](https://github.com/Dicklesworthstone/frankenredis/commit/2f60fb9df8353f09dde0e78be73eae2ca8b079cc))
- CLIENT SETINFO for Redis 7.2+ library identification
  ([000dc73](https://github.com/Dicklesworthstone/frankenredis/commit/000dc73ed1e5cee5992293f80edd5093dc99359f))
- CONFIG GET with multiple patterns (Redis 7+)
  ([1cb9170](https://github.com/Dicklesworthstone/frankenredis/commit/1cb9170a89739f948a1f60f36bb1656756cdc208))

### Server and command features
- Real SLOWLOG tracking with timing and CONFIG integration
  ([c565b38](https://github.com/Dicklesworthstone/frankenredis/commit/c565b38636e05a202862a2d4c946297e2ace0d92))
- COMMAND GETKEYS with key extraction from COMMAND_TABLE metadata
  ([35848b9](https://github.com/Dicklesworthstone/frankenredis/commit/35848b97b5801f26998d3275928b20e96a2f0c1f))
- GEORADIUS/GEORADIUSBYMEMBER STORE/STOREDIST support
  ([e20d87b](https://github.com/Dicklesworthstone/frankenredis/commit/e20d87b58a011eee40a183328023d9a802fd2247))
- Full CLUSTER subcommand dispatch (INFO/MYID/SLOTS/SHARDS/NODES/KEYSLOT/GETKEYSINSLOT/COUNTKEYSINSLOT/RESET)
  ([7b00450](https://github.com/Dicklesworthstone/frankenredis/commit/7b00450d924e8048073745736356ae0e45a592af))
- Real GETKEYSINSLOT and COUNTKEYSINSLOT with keyspace scanning
  ([0003376](https://github.com/Dicklesworthstone/frankenredis/commit/0003376120c0ac8ad07de754b4c125521c09e581))
- AOF rewrite pipeline, SORT conformance suite, intset encoding
  ([9dca209](https://github.com/Dicklesworthstone/frankenredis/commit/9dca2098523608150534ba3a6e3b5a2293f3ef31))
- Persist CONFIG SET hz with validation conformance tests
  ([3368409](https://github.com/Dicklesworthstone/frankenredis/commit/33684091cdbaad7070e6743e027693ba35b53c11))
- Preserve destination TTL during PFMERGE (Redis parity)
  ([6a63fa4](https://github.com/Dicklesworthstone/frankenredis/commit/6a63fa4613ddeba10e078d74520643f032b5afd1))
- Lowercase WrongArity error messages (Redis parity)
  ([ff7d02f](https://github.com/Dicklesworthstone/frankenredis/commit/ff7d02f534fc942083d68cff7cf859a38ffa5912))

### Bug fixes
- ZRANGE REV rank-mode correctness and BITOP validation
  ([b7fb8a6](https://github.com/Dicklesworthstone/frankenredis/commit/b7fb8a6edbca9eb63a319032cd4d2d35f657a6d8))
- Reject SET/GETEX with zero/negative expire times
  ([2fc29dc](https://github.com/Dicklesworthstone/frankenredis/commit/2fc29dc32cb00138de0356e7282ec8fa136c9e10))
- Allow INCRBYFLOAT/HINCRBYFLOAT with infinity, reject only NaN
  ([c11137d](https://github.com/Dicklesworthstone/frankenredis/commit/c11137ddd3c85dfbe20c1bd2bda57bc03eaa6a55))
- Classify MSETNX, BRPOPLPUSH, BZPOPMIN/MAX, BZMPOP, ZDIFFSTORE as write commands
  ([fa11152](https://github.com/Dicklesworthstone/frankenredis/commit/fa1115244b040a7bbab83805ef6c6f7fc988189a))
- Reject empty RESP array frames in AOF record parsing
  ([2f98ed3](https://github.com/Dicklesworthstone/frankenredis/commit/2f98ed3ed898845d1384acdacb941e56a82fee77))
- Preserve stream consumer groups on COPY
  ([ab01233](https://github.com/Dicklesworthstone/frankenredis/commit/ab0123352ae5536a7d74be621f1f8d8a414f110f))
- Redis-accurate error messages for GETBIT and BITPOS
  ([11ee508](https://github.com/Dicklesworthstone/frankenredis/commit/11ee508e684c190f2c316665184aa499c2bee9a9))

---

## Phase 3 — Scripting, Blocking Ops, DUMP/RESTORE, 215+ Commands (2026-02-25 .. 2026-02-26)

### Lua 5.1 scripting engine
- Full Lua 5.1 evaluator: variables, arithmetic, string concat, comparisons, logical ops,
  if/elseif/else, for/while/repeat loops, tables, function calls/definitions, `redis.call`/`pcall`,
  KEYS/ARGV
  ([a4c51e6](https://github.com/Dicklesworthstone/frankenredis/commit/a4c51e61f3ae50a9ded523e405154a59c589f7e9))
- EVAL/EVALSHA/EVAL_RO/EVALSHA_RO, SCRIPT LOAD/EXISTS/FLUSH
- FUNCTION subsystem (LOAD/LIST/STATS/DUMP/RESTORE/FLUSH/DELETE/HELP), FCALL/FCALL_RO
  ([5c23efe](https://github.com/Dicklesworthstone/frankenredis/commit/5c23efe2c6cbdda5b13e49f9f443ac749ea11885))

### Blocking commands and Pub/Sub model
- BZPOPMIN/BZPOPMAX/BZMPOP implementation
  ([0af6c9f](https://github.com/Dicklesworthstone/frankenredis/commit/0af6c9f6e101e985281c0beba93f05e85f084086))
- Pub/Sub message model overhaul with multi-channel subscribe replies
  ([0af6c9f](https://github.com/Dicklesworthstone/frankenredis/commit/0af6c9f6e101e985281c0beba93f05e85f084086))

### Serialization and replication
- DUMP/RESTORE serialization with full type coverage and CRC16 integrity
  ([3046ebb](https://github.com/Dicklesworthstone/frankenredis/commit/3046ebb4bf9afe33bde592dc5d5265451de935b1),
   [14643e8](https://github.com/Dicklesworthstone/frankenredis/commit/14643e8db8fad4642b23ec2c9adc7c3ac2a63c27))
- REPLCONF and PSYNC command stubs for standalone mode
  ([2f5fb13](https://github.com/Dicklesworthstone/frankenredis/commit/2f5fb139052d1e9f69bcb886c7aa9969748fd4b9))
- Enforce strict PSYNC backlog bounds
  ([98cbb19](https://github.com/Dicklesworthstone/frankenredis/commit/98cbb19f680c85cfe01b4883931d87369dbbfdb2))

### Command surface expansion to 215+
- ZADD options (NX/XX/GT/LT/CH), LPOS full (RANK/COUNT/MAXLEN), CLIENT/SLOWLOG/SAVE runtime commands
  ([b701186](https://github.com/Dicklesworthstone/frankenredis/commit/b701186f3bf1754778bc3b0b40ac7da6841ee57b))
- Expand dispatch to 140+ commands with geo, streams, pub/sub, blocking ops
  ([51f06cb](https://github.com/Dicklesworthstone/frankenredis/commit/51f06cb7cd44ddaad9e6328e43830e0822a884a6))
- Further expansion to 215+ with SORT, CLIENT, CONFIG, extended data ops
  ([a87b4e4](https://github.com/Dicklesworthstone/frankenredis/commit/a87b4e4c4d960655a545db69be7ce40341bc616d))
- CONFIG GET/SET command subsystem
  ([72bf4d2](https://github.com/Dicklesworthstone/frankenredis/commit/72bf4d270c1425012be3861447abc3a7b2d029db))

---

## Phase 2 — Multi-Type Data, Streams, Geo, ACL, Transactions (2026-02-19 .. 2026-02-22)

### Multi-type data engine
- Implement Hash, List, Set, Sorted Set extended commands
  ([19046a1](https://github.com/Dicklesworthstone/frankenredis/commit/19046a17104831ad4c996ae235ef337e11f76710),
   [d9b72ad](https://github.com/Dicklesworthstone/frankenredis/commit/d9b72ad3f96e4462806e2bd1eff1cc6c59c4bb8d))
- GETEX, SMISMEMBER, SUBSTR, BITOP, ZUNIONSTORE, ZINTERSTORE
  ([0db1169](https://github.com/Dicklesworthstone/frankenredis/commit/0db1169070110b63121f63f0d0d35f2e9e8616c2))
- Server/connection commands and SCAN family (SCAN/HSCAN/SSCAN/ZSCAN)
  ([711691a](https://github.com/Dicklesworthstone/frankenredis/commit/711691ac78e79dbb2465325df7ed07d98deb4c9f))
- List manipulation commands with key expiry integration
  ([a40b757](https://github.com/Dicklesworthstone/frankenredis/commit/a40b757c565900eedd77e7ae452661bfc24e9ea8))

### Transaction support
- MULTI/EXEC/DISCARD transaction support with memory enforcement
  ([9bb279c](https://github.com/Dicklesworthstone/frankenredis/commit/9bb279cec6f38d601df0791ff882f92a1b12a940))

### Redis Streams
- Core streams: XADD, XLEN, XDEL, XTRIM, XRANGE, XREVRANGE, XREAD
  ([cabb522](https://github.com/Dicklesworthstone/frankenredis/commit/cabb5223ea63aa8b2d184f824a48b5963a898dcc))
- Consumer groups: XACK, XCLAIM, XPENDING, XREADGROUP with pending entry tracking
  ([27ce066](https://github.com/Dicklesworthstone/frankenredis/commit/27ce066aa4e4d1e4b978650293fa94451cf421a2),
   [561db47](https://github.com/Dicklesworthstone/frankenredis/commit/561db47716e54cc7bd492007c1ad2fe6e185a87c))
- XCLAIM, XAUTOCLAIM, XPENDING with replication handshake conformance
  ([cdae192](https://github.com/Dicklesworthstone/frankenredis/commit/cdae192a20d83b39bbb94884af756616fca1d78e))

### Geospatial commands
- GEOADD, GEOPOS, GEODIST, GEOHASH
  ([4b56db2](https://github.com/Dicklesworthstone/frankenredis/commit/4b56db2b53523cc25494d67e57b33eabff5df44a))
- Geo conformance suite
  ([41e9ef7](https://github.com/Dicklesworthstone/frankenredis/commit/41e9ef7916fa768501f2aeb0cf5bf0040906b568))

### ACL subsystem
- Full ACL command subsystem: AUTH, ACL SETUSER/GETUSER/DELUSER/LIST/WHOAMI/CAT/GENPASS/LOG
  ([bbeeb57](https://github.com/Dicklesworthstone/frankenredis/commit/bbeeb578e8de40688531c63fffa60bf0a145e0dc))

### Correctness fixes
- Reject NaN in float parsing, enforce GETEX PERSIST arity, fix ZSTORE weight/aggregate parsing
  ([fa5cd94](https://github.com/Dicklesworthstone/frankenredis/commit/fa5cd94a631e48ff3c7ef3df92e9d9c33f6bdb6e))
- Stream group cleanup on key removal, transaction memory enforcement, protocol hardening
  ([f775dd8](https://github.com/Dicklesworthstone/frankenredis/commit/f775dd81b9b8138744b0ed8d9f47b185ce4df84d))
- Harden KEYS glob matching, GETSET TTL preservation
  ([5278918](https://github.com/Dicklesworthstone/frankenredis/commit/5278918f61e6bed538dcef7f9dd7503676316bf7))
- Replace `unwrap`/`unreachable` panics with proper error returns in store operations
  ([e18fc79](https://github.com/Dicklesworthstone/frankenredis/commit/e18fc799b8217020c80bd9d944b2c6663f66146f))

### Conformance suites
- Add Hash, List, Set, Sorted Set fixture suites
  ([cb671f0](https://github.com/Dicklesworthstone/frankenredis/commit/cb671f0f2ea638be5ffc67c07df959223d4b788a))
- Persistence replay conformance fixtures
  ([abb20be](https://github.com/Dicklesworthstone/frankenredis/commit/abb20be030155e24884bac4fcb0207889b5e4532))

### Tooling port: shell/Python to Rust
- Port 6 conformance orchestrators from shell/Python/jq to native Rust:
  live-oracle, RaptorQ gate, benchmark runner, adversarial triage, coverage budget
  ([31a44d7](https://github.com/Dicklesworthstone/frankenredis/commit/31a44d704de3923f8eebe6371d1cfff704a9a11a),
   [06e00cb](https://github.com/Dicklesworthstone/frankenredis/commit/06e00cb96948eeed5f841f1b5cafd45b6f570f3b),
   [a19a42c](https://github.com/Dicklesworthstone/frankenredis/commit/a19a42c666b450ccf5e15b7d397383d818e990e9),
   [c60b8bc](https://github.com/Dicklesworthstone/frankenredis/commit/c60b8bcece68105245e5cf7de5c59e0da2425f57),
   [952e477](https://github.com/Dicklesworthstone/frankenredis/commit/952e47758b6c31e69476d606054b9b8596614f2d),
   [fe45110](https://github.com/Dicklesworthstone/frankenredis/commit/fe45110f80433968a4ce133fcbe9d9fdd82e661d))

---

## Phase 1 — Foundation: Protocol, Conformance Framework, Persistence, Replication (2026-02-13 .. 2026-02-18)

### Project bootstrap
- Clean-room workspace with 10 initial crates: `fr-protocol`, `fr-command`, `fr-store`, `fr-expire`,
  `fr-persist`, `fr-repl`, `fr-config`, `fr-conformance`, `fr-runtime`, `fr-eventloop`
  ([0376f60](https://github.com/Dicklesworthstone/frankenredis/commit/0376f609b01558c15cfd79ed6092f6d1efc718e6))
- MIT + OpenAI/Anthropic rider license
  ([cacc96d](https://github.com/Dicklesworthstone/frankenredis/commit/cacc96d1faa3208526dbe703ecbc4477bac0ca34))

### RESP protocol and command dispatch
- RESP2 parser (`parse_frame`) and encoder (`RespFrame::to_bytes`) in `fr-protocol`
- Distinguish unsupported RESP3 types from truly invalid prefixes
  ([96d8271](https://github.com/Dicklesworthstone/frankenredis/commit/96d82717f505ec7ce64d8c62765dac32ddcadc86))
- Harden RESP parser canonicalization; add optimization gate and negative fixture coverage
  ([bbe0585](https://github.com/Dicklesworthstone/frankenredis/commit/bbe0585268e924d481565dd67438123957373d93))
- 18 new Redis string/key commands with glob matcher
  ([ceb6e0e](https://github.com/Dicklesworthstone/frankenredis/commit/ceb6e0e8658223e977a948bea4efc8f060abd76e))

### Conformance harness and phase2c specification
- Fixture-driven conformance runner with strict/hardened runtime modes
  ([b2d40e0](https://github.com/Dicklesworthstone/frankenredis/commit/b2d40e0e60a2b76093473862f397ff41680c8c3b))
- Phase2c conformance specification packets FR-P2C-001 through FR-P2C-009
  ([53b5eb2](https://github.com/Dicklesworthstone/frankenredis/commit/53b5eb257fa9fecc55a83bbb5aeb237507957c86),
   [fb7d8e0](https://github.com/Dicklesworthstone/frankenredis/commit/fb7d8e0aa23a3cc3a2ecc910e5ea234d19ef9f6e),
   [eebf3e3](https://github.com/Dicklesworthstone/frankenredis/commit/eebf3e34867492fa06aa7175aab4bfc2b90cf1f1))
- Phase2c parity gates, fixture manifests, golden files
  ([c3676e6](https://github.com/Dicklesworthstone/frankenredis/commit/c3676e6f38b4457e13c09b0004f787f931b8b774))
- FR-P2C-008 expire/evict differential conformance tests
  ([060c280](https://github.com/Dicklesworthstone/frankenredis/commit/060c280cb5af609e7495de88e13b8d9b2ffe1277))

### Persistence and replication scaffold
- AOF record frame contract; Store-to-AOF rewrite serialization (all data types + TTL)
- Integrate `fr-persist` AOF capture into command dispatch pipeline
  ([e705c1b](https://github.com/Dicklesworthstone/frankenredis/commit/e705c1b9f2c140f4817e0402cf241a3ff1653b53))
- Replication handshake FSM, PSYNC decision engine, WAIT/WAITAOF evaluators, AOF stream codec
  ([bf4c8f6](https://github.com/Dicklesworthstone/frankenredis/commit/bf4c8f66e8cac0ca5545d6002c1d82f4e896a821))
- WAIT and WAITAOF command surface with deterministic threshold evaluation
  ([be5b0f7](https://github.com/Dicklesworthstone/frankenredis/commit/be5b0f70a50ad51308af20281929c3ed487abb6d))

### Configuration and security
- Threat-class policy engine with strict/hardened deviation allowlists
  ([a903a6e](https://github.com/Dicklesworthstone/frankenredis/commit/a903a6e82bfdc06273d814823bfc3a7764c87547),
   [46026ae](https://github.com/Dicklesworthstone/frankenredis/commit/46026ae65b55c5b257827e10b1a84ace907fc5c3))
- TLS configuration subsystem and runtime hot-apply engine
  ([0dab746](https://github.com/Dicklesworthstone/frankenredis/commit/0dab746922ad70fb6c97390413ec66e92b428c66))
- Deterministic event loop planning and structured log contracts
  ([0b117f3](https://github.com/Dicklesworthstone/frankenredis/commit/0b117f303dea67fbc14a746c45b24b3683c03d6e))

### Runtime commands
- CLUSTER, ASKING, READONLY, READWRITE handlers
  ([95d18e6](https://github.com/Dicklesworthstone/frankenredis/commit/95d18e63029bdc4523a8895c178a121bc5fd2236))
- PEXPIRE, EXPIREAT, PEXPIREAT, EXPIRETIME, PEXPIRETIME
  ([6057451](https://github.com/Dicklesworthstone/frankenredis/commit/6057451f306fe9d6a1915fcbf41a5e7188374657))

### CI
- Overhaul live conformance gates workflow with 8-gate topology, forensics indexing, structured artifact upload
  ([414f4cd](https://github.com/Dicklesworthstone/frankenredis/commit/414f4cd7d4e4d33f4605fd4613812cb73c97c0bb))

### Documentation passes
- DOC-PASS-00 through DOC-PASS-12: baseline matrices, crate cartography, symbol census,
  invariant catalog, execution-path tracing, error taxonomy, behavioral semantics, oracle parity
  ([b0de028](https://github.com/Dicklesworthstone/frankenredis/commit/b0de0283e270bdda5cdfa14248f151970057e435),
   [6ae8922](https://github.com/Dicklesworthstone/frankenredis/commit/6ae89223621740f6ee48f25fff5e6d5f31430e39),
   [4ebe3c3](https://github.com/Dicklesworthstone/frankenredis/commit/4ebe3c3efa7ae2542333a461f8aa69f4670f2de7),
   [2a3118e](https://github.com/Dicklesworthstone/frankenredis/commit/2a3118ee21f267c0ac97be2726f7a46716f5836e))

---

## Crate Map

| Crate | Role |
|---|---|
| `fr-protocol` | RESP2 parser and encoder |
| `fr-command` | Command dispatch table (227+ handlers) |
| `fr-store` | In-memory data engine (strings, hashes, lists, sets, sorted sets, streams, HLL, geo) |
| `fr-expire` | TTL evaluation and active-expire logic |
| `fr-persist` | AOF record codec, RDB binary format, CRC64 integrity |
| `fr-repl` | Replication handshake FSM, PSYNC, WAIT/WAITAOF |
| `fr-config` | Threat-class policy engine, TLS config, encoding thresholds |
| `fr-conformance` | Fixture-driven conformance harness (3577 cases) |
| `fr-runtime` | ServerState + ClientSession, auth, ACL, Lua scripting, transaction pipeline |
| `fr-eventloop` | Deterministic event loop planning with tick budgets |
| `fr-server` | Standalone TCP server binary (`frankenredis`) using mio |

---

## Timeline Summary

| Date Range | Phase | Headline |
|---|---|---|
| 2026-02-13 .. 2026-02-18 | 1 | Foundation: 10 crates, RESP, conformance framework, persistence, replication scaffold |
| 2026-02-19 .. 2026-02-22 | 2 | Multi-type data, streams, geo, ACL, transactions, 100+ commands |
| 2026-02-25 .. 2026-02-26 | 3 | Lua scripting, FUNCTION, DUMP/RESTORE, blocking ops, 215+ commands |
| 2026-03-03 .. 2026-03-12 | 4 | Conformance explosion (1500 to 3577), full Lua stdlib, Redis 7.2 compat |
| 2026-03-13 .. 2026-03-14 | 5 | Runtime split (ServerState+ClientSession), stream maturity, encoding thresholds |
| 2026-03-15 .. 2026-03-19 | 6 | TCP server, blocking infrastructure, crash-safe persistence |
| 2026-03-20 .. 2026-03-21 | 7 | Real INFO stats, cross-client Pub/Sub, Lua hardening, sorted set correctness |
