# fr-protocol Conformance Coverage

Conformance scope: RESP2 wire protocol and partial RESP3 surface. See
`fr-protocol/src/lib.rs` for the parser + encoder and
`fr-protocol/tests/` for the conformance tests.

## Reference

Upstream source: `legacy_redis_code/redis/src/networking.c` (reply
builders) and `legacy_redis_code/redis/src/resp_parser.c` (RESP3).
Vendored commit: see `deps/` inside `legacy_redis_code/redis`.

## MUST/SHOULD coverage by reply shape

| Reply shape            | MUST clause                                | Test gate                                         | Status   |
|------------------------|---------------------------------------------|---------------------------------------------------|----------|
| Simple string `+`      | non-empty / empty both valid                | `golden_simple_string`, `golden_empty_simple_string`, `live_oracle_*` | ✓ tested |
| Error `-`              | non-empty / empty both valid                | `golden_error_string`, `golden_empty_error_string`, `live_oracle_*`   | ✓ tested |
| Integer `:`            | i64::MIN..=i64::MAX, reject leading `+`     | `golden_{zero,negative,i64_{max,min}}_integer`, `golden_integer_with_leading_plus_rejected` | ✓ tested |
| Bulk string `$`        | length-prefixed; body may contain CRLF      | `golden_bulk_string`, `golden_empty_bulk_string`, `golden_bulk_string_with_binary` | ✓ tested |
| Null bulk `$-1\r\n`    | nil scalar                                  | `golden_null_bulk_string`, `live_oracle_byte_exact_frames_for_canonical_replies` | ✓ tested |
| Array `*`              | count-prefixed; children parsed recursively | `golden_{array,nested_array,empty_array}`, `live_oracle_roundtrip_canonical_corpus` | ✓ tested |
| Null array `*-1\r\n`   | nil array (distinct from null bulk)         | `golden_null_array`, `multi_exec_linearizability::exec_aborted` | ✓ tested |
| Multibulk inline input | inline commands on TCP                      | **NOT YET** in this crate; see `fr-command::fuzz_inline_parser` | ✗ gap |

## MUST-coverage error paths

| Error variant                      | MUST clause                              | Test gate                                       | Status |
|------------------------------------|-------------------------------------------|-------------------------------------------------|--------|
| `Incomplete`                       | parser returns Incomplete when short      | `golden_incomplete_*`                           | ✓      |
| `InvalidPrefix(b)`                 | unknown leading byte                      | `golden_invalid_prefix`                         | ✓      |
| `UnsupportedResp3Type(b)`          | RESP3 prefix unsupported (fail-closed)    | `golden_unsupported_resp3_*` (7 cases)          | ✓      |
| `InvalidInteger`                   | bad integer payload                       | `golden_invalid_integer_payload`, `golden_integer_with_leading_plus_rejected` | ✓      |
| `InvalidBulkLength`                | malformed `$NN`                           | `golden_invalid_bulk_length`, `golden_bulk_length_minus_two_invalid` | ✓      |
| `InvalidMultibulkLength`           | malformed `*NN`                           | `golden_array_length_minus_two_invalid`         | ✓      |
| `BulkLengthTooLarge`               | length exceeds `max_bulk_len`             | `golden_bulk_length_exceeds_limit`              | ✓      |
| `MultibulkLengthTooLarge`          | count exceeds `max_array_len`             | `golden_multibulk_length_exceeds_limit`         | ✓      |
| `RecursionLimitExceeded`           | array nesting beyond `max_recursion_depth`| `golden_recursion_limit_exceeded`               | ✓      |
| `LineTooLong`                      | line exceeds 64 KiB                       | **NOT YET** covered directly                    | ✗ gap  |
| `InvalidUtf8`                      | non-UTF8 inside simple/error text         | **indirect** (only via bulk body testing today) | △      |

## Live oracle round-trip coverage

`tests/live_oracle_diff.rs` drives 54 canonical commands through the
vendored `redis-server` and asserts parse → re-encode → re-parse
identity for each reply. Coverage matrix expected to expand to the
full V1 command surface in follow-up beads.

## Known gaps (ownership + follow-up)

- RESP3 types `_`, `#`, `,`, `(`, `!`, `=`, `%`, `~`, `>`, `|` are
  pinned as `UnsupportedResp3Type` today; full RESP3 decoder is a
  separate work stream. Golden fixtures act as XFAIL markers.
- `LineTooLong` has no direct test; the `MAX_LINE_LENGTH = 64 KiB`
  constant is treated as implementation-private.
- Inline-command parsing (`fr-command`'s inline-parser surface) is
  tested at the `fr-command` layer, not here. A cross-layer test
  would catch drift between fr-protocol and the inline path.
- DISCREPANCIES.md records intentional divergences once the full
  corpus lands.

Last updated: 2026-04-23 (br-frankenredis-0zyf).
