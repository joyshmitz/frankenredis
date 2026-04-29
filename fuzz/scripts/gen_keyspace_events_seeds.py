#!/usr/bin/env python3
"""Generate structured corpus seeds for fuzz_keyspace_events.

The fuzz target runs each input through BOTH paths
(`fuzz_raw_keyspace_events` and `fuzz_structured_keyspace_events`):
the raw path feeds the bytes straight into
`fr_store::keyspace_events_parse` (after a UTF-8-lossy conversion),
and the structured path drives the same parser via `arbitrary` —
the latter format isn't version-stable, so we lean on libfuzzer's
mutator and only seed the raw path here.

The seed catalogue exercises every documented branch of
`keyspace_events_parse`:

  Accept-class:
    - empty input → zero flags (the documented identity)
    - canonical "AKE" → all-classes + K + E
    - canonical "KEA" (parser is order-insensitive) → same
    - K+E with no class chars → returns 0 (no-op since no class bit)
    - K alone, E alone → both return 0 per the
      "K/E without any class disables all" rule
    - "Kg", "Egn$", "KEm", "KEt" → individual classes
    - "Km" — Redis 6.0 key-miss notifications
    - "KEn" — Redis 7.0 NEW-key notifications
    - "KEA$" — A is a superset, $ is a class already in A,
      idempotent
    - one-char-per-class enumeration: `KE` + each of g,$,l,s,h,z,x,e,t,m,n

  Reject-class:
    - lowercase 'k' (parser is case-sensitive)
    - 'X', '?', '7', space, tab → unknown chars
    - "K?" — valid prefix + invalid char in middle
    - non-ASCII Unicode char (snowman)

Run:
    python3 fuzz/scripts/gen_keyspace_events_seeds.py
"""
from __future__ import annotations

from pathlib import Path


def seed(label: str, body: bytes) -> tuple[str, bytes]:
    return (label, body)


def main() -> None:
    repo = Path(__file__).resolve().parent.parent.parent
    out_dir = repo / "fuzz" / "corpus" / "fuzz_keyspace_events"
    out_dir.mkdir(parents=True, exist_ok=True)

    seeds: list[tuple[str, bytes]] = [
        # ── Accept-class ─────────────────────────────────────────
        seed("empty.txt", b""),
        seed("canonical_AKE.txt", b"AKE"),
        seed("KEA_alternate_ordering.txt", b"KEA"),
        seed("K_alone_no_class_disables.txt", b"K"),
        seed("E_alone_no_class_disables.txt", b"E"),
        seed("KE_no_class_disables.txt", b"KE"),
        seed("Kg_generic_only.txt", b"Kg"),
        seed("Egn_generic_plus_new.txt", b"Egn"),
        seed("KEm_key_miss.txt", b"KEm"),
        seed("KEt_stream.txt", b"KEt"),
        seed("KEn_new_key_redis7.txt", b"KEn"),
        seed("KEA_dollar_idempotent.txt", b"KEA$"),
        seed("K_string_class.txt", b"K$"),
        seed("E_list_class.txt", b"El"),
        seed("K_set_class.txt", b"Ks"),
        seed("K_hash_class.txt", b"Kh"),
        seed("K_zset_class.txt", b"Kz"),
        seed("K_expired_class.txt", b"Kx"),
        seed("K_evicted_class.txt", b"Ke"),
        seed("K_stream_class.txt", b"Kt"),
        seed("K_keymiss_class.txt", b"Km"),
        seed("K_new_class.txt", b"Kn"),
        seed("KE_all_per_class_chars.txt", b"KEg$lshzxetmn"),
        seed(
            "KEA_with_explicit_redundants.txt",
            b"KEAg$lshzxetmn",
        ),
        # ── Reject-class ─────────────────────────────────────────
        seed("lowercase_k_rejected.txt", b"k"),
        seed("uppercase_g_rejected.txt", b"G"),
        seed("question_mark.txt", b"?"),
        seed("digit_7.txt", b"7"),
        seed("space_only.txt", b" "),
        seed("tab_only.txt", b"\t"),
        seed("K_then_invalid_char.txt", b"K?"),
        seed("KEA_then_invalid.txt", b"KEAa"),
        seed("snowman_unicode.txt", "☃".encode("utf-8")),
        seed("crlf_only.txt", b"\r\n"),
    ]

    for label, payload in seeds:
        path = out_dir / label
        path.write_bytes(payload)
        print(f"wrote {len(payload):4d} bytes to {path.relative_to(repo)}")
    print(f"\ngenerated {len(seeds)} corpus seeds")


if __name__ == "__main__":
    main()
