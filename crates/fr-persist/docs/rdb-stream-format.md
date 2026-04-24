# Upstream Redis RDB Stream Format

This note documents the upstream Redis stream object encodings used by the RDB
type tags `RDB_TYPE_STREAM_LISTPACKS` (`15`), `RDB_TYPE_STREAM_LISTPACKS_2`
(`19`), and `RDB_TYPE_STREAM_LISTPACKS_3` (`21`). The source of truth is
`legacy_redis_code/redis/src/rdb.c`, `t_stream.c`, `stream.h`, and `rdb.h`.

The current upstream saver emits `RDB_TYPE_STREAM_LISTPACKS_3` for every stream.
The older tags remain loadable and differ only in the stream metadata and
consumer metadata noted below.

## Encoding Primitives

| Name | Upstream writer | On-disk form | Used for |
| --- | --- | --- | --- |
| RDB length | `rdbSaveLen` | Redis RDB length encoding | Counts, ID components, offsets |
| Raw string | `rdbSaveRawString` | RDB length followed by bytes | Radix keys, listpacks, group names, consumer names |
| Raw stream ID | `rdbWriteRaw` | Exactly 16 bytes | PEL entry IDs |
| Millisecond time | `rdbSaveMillisecondTime` | RDB millisecond timestamp encoding | NACK delivery time, consumer seen/active time |
| Listpack integer/string | `lpAppendInteger`, `lpAppend` | Redis listpack element encoding | Macro-node internals |

`streamEncodeID` serializes a stream ID as two big-endian `u64` words:
`ms` followed by `seq`. Redis uses that 16-byte representation for radix-tree
keys and PEL keys so lexicographic byte order matches stream ID order.

## Top-Level Object Payload

The stream object payload follows the RDB type byte. For type `21`, the payload
is:

| Order | Field | Encoding | Notes |
| --- | --- | --- | --- |
| 1 | `listpack_count` | RDB length | Number of stream radix-tree macro nodes |
| 2a | `node_key` | Raw string | Repeated `listpack_count` times; must be 16 bytes |
| 2b | `node_listpack` | Raw string | Repeated after each `node_key`; contains the macro node |
| 3 | `length` | RDB length | Live stream entries, excluding tombstones |
| 4 | `last_id.ms` | RDB length | Last generated stream ID milliseconds |
| 5 | `last_id.seq` | RDB length | Last generated stream ID sequence |
| 6 | `first_id.ms` | RDB length | First live entry ID milliseconds |
| 7 | `first_id.seq` | RDB length | First live entry ID sequence |
| 8 | `max_deleted_entry_id.ms` | RDB length | Highest tombstoned entry ID milliseconds |
| 9 | `max_deleted_entry_id.seq` | RDB length | Highest tombstoned entry ID sequence |
| 10 | `entries_added` | RDB length | Monotonic logical stream offset |
| 11 | `consumer_group_count` | RDB length | Number of consumer groups |
| 12 | consumer group payload | See below | Repeated `consumer_group_count` times |

Redis validates every loaded `node_key` as exactly `sizeof(streamID)` bytes,
validates each listpack with `streamValidateListpackIntegrity`, rejects empty
listpacks, and inserts each key/listpack pair into the stream radix tree.

## Radix Node Listpack

Each radix node maps one 16-byte `node_key` to one listpack. The node key is the
macro-node master stream ID. Entries inside the listpack store ID deltas relative
to that master ID.

Every listpack begins with a master entry:

| Order | Field | Encoding | Notes |
| --- | --- | --- | --- |
| 1 | `count` | Listpack integer | Live entries in this macro node |
| 2 | `deleted` | Listpack integer | Tombstoned entries in this macro node |
| 3 | `master_field_count` | Listpack integer | Number of field names in the master entry |
| 4 | `master_field[i]` | Listpack string | Repeated `master_field_count` times |
| 5 | `master_terminator` | Listpack integer `0` | Backward-iteration stop marker |

Each real stream entry follows the master entry:

| Order | Field | Encoding | Notes |
| --- | --- | --- | --- |
| 1 | `flags` | Listpack integer | `1` = deleted, `2` = same fields as master |
| 2 | `id_ms_delta` | Listpack integer | Entry `ms - master_id.ms` |
| 3 | `id_seq_delta` | Listpack integer | Entry `seq - master_id.seq` |
| 4 | `field_count` | Listpack integer | Present only when `same fields` is not set |
| 5 | `field[i]` | Listpack string | Present only when `same fields` is not set |
| 6 | `value[i]` | Listpack string | Always present, repeated for each field |
| 7 | `lp_count` | Listpack integer | Number of listpack elements in this entry before `lp_count` |

When the `same fields` flag is set, the entry omits `field_count` and all field
names; field names are read from the master entry. When the deleted flag is set,
the entry remains present as a tombstone and is skipped by normal stream
iteration. `lp_count` lets Redis walk backward from the end of the listpack.

## Consumer Group Payload

Each consumer group payload is:

| Order | Field | Encoding | Notes |
| --- | --- | --- | --- |
| 1 | `group_name` | Raw string | Radix-tree key from `stream.cgroups` |
| 2 | `last_id.ms` | RDB length | Group last delivered ID milliseconds |
| 3 | `last_id.seq` | RDB length | Group last delivered ID sequence |
| 4 | `entries_read` | RDB length | Logical reads counter; type `19+` only |
| 5 | global PEL | See below | Pending entries for the whole group |
| 6 | consumers | See below | Consumer records and local PEL links |

The global pending entries list is saved first:

| Order | Field | Encoding | Notes |
| --- | --- | --- | --- |
| 1 | `pel_count` | RDB length | Number of global pending entries |
| 2 | `entry_id` | Raw stream ID | Repeated `pel_count` times |
| 3 | `delivery_time` | Millisecond time | Repeated after each `entry_id` in the global PEL |
| 4 | `delivery_count` | RDB length | Repeated after each `delivery_time` |

Redis deliberately does not save the owning consumer name in global PEL entries.
Ownership is reconstructed from each consumer-local PEL.

The consumer list is:

| Order | Field | Encoding | Notes |
| --- | --- | --- | --- |
| 1 | `consumer_count` | RDB length | Number of consumers in the group |
| 2 | `consumer_name` | Raw string | Repeated `consumer_count` times |
| 3 | `seen_time` | Millisecond time | Last time the consumer was seen |
| 4 | `active_time` | Millisecond time | Type `21+` only; type `15/19` derive it from `seen_time` |
| 5 | `consumer_pel_count` | RDB length | Number of entries owned by this consumer |
| 6 | `consumer_entry_id` | Raw stream ID | Repeated `consumer_pel_count` times |

When loading a consumer-local PEL ID, Redis looks up the matching NACK in the
group global PEL, assigns that NACK to the consumer, and inserts the same NACK
pointer into the consumer PEL. Missing global entries or duplicate local PEL
entries make the RDB corrupt.

## Type Version Differences

| Type | Added fields | Loader fallback for absent fields |
| --- | --- | --- |
| `15` (`RDB_TYPE_STREAM_LISTPACKS`) | `length`, `last_id`, consumer groups, global PELs, consumer `seen_time`, consumer-local PELs | Derive `first_id` from the radix tree, set `max_deleted_entry_id` to `0-0`, set `entries_added = length`, estimate group `entries_read`, set `active_time = seen_time` |
| `19` (`RDB_TYPE_STREAM_LISTPACKS_2`) | `first_id`, `max_deleted_entry_id`, `entries_added`, group `entries_read` | Set `active_time = seen_time` |
| `21` (`RDB_TYPE_STREAM_LISTPACKS_3`) | Consumer `active_time` | No fallback for current stream fields |

## Decoder Checklist

An upstream-compatible decoder should preserve these invariants:

- Accept only stream type tags `15`, `19`, and `21` for this payload shape.
- Require every radix node key and PEL entry ID to be exactly 16 bytes.
- Decode stream IDs as big-endian `u64 ms` plus big-endian `u64 seq`.
- Validate listpack byte structure before trusting inner fields.
- Reject empty stream macro-node listpacks.
- Reject duplicate radix keys, duplicate consumer names within a group, and
  duplicate consumer-local PEL entries.
- Require every consumer-local PEL ID to exist in the group global PEL.
- For deep integrity validation, require every global PEL NACK to be assigned to
  a consumer by the end of the group load.
- For type `15`, reconstruct missing stream and group offsets using the same
  estimation rules as upstream rather than storing zeroes.
