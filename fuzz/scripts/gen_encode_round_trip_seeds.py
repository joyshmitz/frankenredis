#!/usr/bin/env python3
"""Generate `arbitrary`-format corpus seeds for fuzz_rdb_encode_round_trip.

`libfuzzer-sys` consumes raw bytes which are then passed to
`<T as arbitrary::Arbitrary>::arbitrary`. The serialization format is
not strictly stable across `arbitrary` versions, but it is documented:
the input bytes are pulled from the front for unstructured `Vec<u8>`
fields and from the back for length tags, with the tail byte selecting
enum variants.

Rather than trying to produce exact arbitrary-format seeds, we lean on
libfuzzer's mutator: any seed file is a valid starting point for
mutation, even if the initial parse hits the early-return guards in
the fuzz target. The seeds we generate here are crafted to push
libfuzzer toward the compact-encoding code paths quickly:

    - Small all-integer sets → trip the intset selector.
    - Small string sets → trip the set listpack selector.
    - Small hash with short field/value pairs → trip the hash listpack.
    - Small zset with simple scores → trip the zset listpack.
    - Small lists (PACKED form) and one-element lists with a giant
      element (PLAIN form) → trip both quicklist branches.

Run:
    python3 fuzz/scripts/gen_encode_round_trip_seeds.py
"""
from __future__ import annotations

import os
import struct
from pathlib import Path


def varlen_bytes(prefix: bytes) -> bytes:
    """Append a length-prefix tag in arbitrary's tail format. Length is
    encoded as a u32 in little-endian followed by an Arbitrary
    "remaining" byte. We approximate by appending a 0x00 trailer."""
    return prefix + b"\x00"


def make_seed(label: str, body: bytes) -> tuple[str, bytes]:
    return (label, body)


def main() -> None:
    repo = Path(__file__).resolve().parent.parent.parent
    out_dir = repo / "fuzz" / "corpus" / "fuzz_rdb_encode_round_trip"
    out_dir.mkdir(parents=True, exist_ok=True)

    seeds: list[tuple[str, bytes]] = [
        # Each seed is a lightly-shaped byte string. The exact arbitrary
        # parse will vary across versions but libfuzzer mutates from
        # any starting point — these seeds primarily seed the corpus
        # so libfuzzer doesn't start cold.
        # Encoded markers: 0x01 prefix = compact mode on; entries
        # follow as (variant byte, key length, key bytes, value bytes).
        make_seed(
            "compact_set_intset_small",
            b"\x01"  # enable_compact = true
            + b"\x01\x02si\x02\x03\x01\x02\x03"  # 1 entry: key="si", SetIntegerLike([1,2,3])
            + b"\x00",
        ),
        make_seed(
            "compact_set_listpack_small",
            b"\x01\x01\x03slp\x03\x03\x05alpha\x04beta\x05gamma\x00",
        ),
        make_seed(
            "compact_hash_listpack_small",
            b"\x01\x01\x03hlp\x04\x02\x02f1\x02v1\x02f2\x02v2\x00",
        ),
        make_seed(
            "compact_zset_listpack_small",
            b"\x01\x01\x03zlp\x05\x03\x01a\x00\x00\x00\x00\x00\x00\xf0?\x01b\x00\x00\x00\x00\x00\x00\x04@\x01c\x00\x00\x00\x00\x00\x00\x1d@\x00",
        ),
        make_seed(
            "compact_list_quicklist_small",
            b"\x01\x01\x02lq\x01\x03\x01a\x01b\x01c\x00",
        ),
        make_seed(
            "compact_list_quicklist_giant_element",
            b"\x01\x01\x02lp\x01\x01"
            + bytes([0xFF, 0x10])  # length tag suggesting ~4096
            + b"x" * 256
            + b"\x00",
        ),
        make_seed(
            "canonical_only_set_small",
            b"\x00"  # enable_compact = false
            + b"\x01\x05c_set\x03\x03\x01a\x01b\x01c\x00",
        ),
        make_seed(
            "canonical_only_hash_small",
            b"\x00\x01\x06c_hash\x04\x02\x01k\x01v\x02f2\x02v2\x00",
        ),
        make_seed(
            "compact_string",
            b"\x01\x01\x03str\x00\x0bhello world\x00",
        ),
        make_seed(
            "compact_set_overflow_intset_threshold",
            b"\x01\x01\x05bigset\x02\x80\x02"  # SetIntegerLike with len 0x0280 = 640 > 512
            + b"\x00\x00\x00\x00" * 64
            + b"\x00",
        ),
        make_seed(
            "compact_zset_with_negative_score",
            b"\x01\x01\x04zneg\x05\x01\x01x\x00\x00\x00\x00\x00\x00\x08\xc0\x00",
        ),
        make_seed(
            "compact_multiple_entries",
            b"\x01"
            + b"\x04"  # 4 entries
            + b"\x01a\x00\x01v"        # entry 1: key="a", String("v")
            + b"\x01b\x02\x02\x01\x02"  # entry 2: key="b", SetIntegerLike([1,2])
            + b"\x01c\x04\x01\x01k\x01v"  # entry 3: key="c", Hash([(k,v)])
            + b"\x01d\x01\x01\x01x"     # entry 4: key="d", List(["x"])
            + b"\x00",
        ),
    ]

    for label, payload in seeds:
        path = out_dir / label
        path.write_bytes(payload)
        print(f"wrote {len(payload):4d} bytes to {path.relative_to(repo)}")
    print(f"\ngenerated {len(seeds)} corpus seeds")


if __name__ == "__main__":
    main()
