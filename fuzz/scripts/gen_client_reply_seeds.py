#!/usr/bin/env python3
"""Generate structured corpus seeds for fuzz_client_reply.

The fuzz target runs each input through both `fuzz_raw_command_stream`
(parsing newline-separated argv lines and feeding each through
`apply_client_reply_state`) and a structured-arbitrary path. The
shadow-model invariant is: actual `apply_client_reply_state` must
match the harness's reference implementation for every command
sequence — both result and post-state.

Seeds are most valuable as newline-separated argv text covering
each CLIENT REPLY transition + interaction with non-CLIENT-REPLY
commands.

  Accept-class (CLIENT REPLY transitions + interactions):
    - CLIENT REPLY ON / OFF / SKIP alone
    - ON → OFF → ON cycle
    - OFF → command (suppressed reply)
    - SKIP → command (one-shot suppression)
    - SKIP → command → command (second responds)
    - lowercase / mixed case (subcommand is case-insensitive)
    - non-CLIENT-REPLY CLIENT subcommand mixed in
    - PING / ECHO interleaved
    - empty input
    - whitespace-only input

  Reject-class (parser surfaces an error):
    - CLIENT REPLY (no mode arg, wrong arity)
    - CLIENT REPLY ON NOW (extra arg, wrong arity)
    - CLIENT REPLY BOGUS (invalid mode token)
    - bare `CLIENT` with no subcommand

Run:
    python3 fuzz/scripts/gen_client_reply_seeds.py
"""
from __future__ import annotations

from pathlib import Path


def seed(label: str, body: bytes) -> tuple[str, bytes]:
    return (label, body)


def main() -> None:
    repo = Path(__file__).resolve().parent.parent.parent
    out_dir = repo / "fuzz" / "corpus" / "fuzz_client_reply"
    out_dir.mkdir(parents=True, exist_ok=True)

    seeds: list[tuple[str, bytes]] = [
        # ── Accept-class: CLIENT REPLY transitions ───────────────
        seed("empty.txt", b""),
        seed("whitespace_only.txt", b"   \t\n"),
        seed("reply_on_alone.txt", b"CLIENT REPLY ON\n"),
        seed("reply_off_alone.txt", b"CLIENT REPLY OFF\n"),
        seed("reply_skip_alone.txt", b"CLIENT REPLY SKIP\n"),
        seed("on_off_on_cycle.txt",
             b"CLIENT REPLY ON\nCLIENT REPLY OFF\nCLIENT REPLY ON\n"),
        seed("off_then_command.txt",
             b"CLIENT REPLY OFF\nSET key value\n"),
        seed("skip_then_one_command.txt",
             b"CLIENT REPLY SKIP\nPING\n"),
        seed("skip_then_two_commands.txt",
             b"CLIENT REPLY SKIP\nPING\nPING\n"),
        seed("off_command_then_on.txt",
             b"CLIENT REPLY OFF\nGET k1\nCLIENT REPLY ON\n"),
        # ── Case sensitivity (subcommand is case-insensitive) ────
        seed("lowercase_subcommand.txt", b"client reply on\n"),
        seed("mixed_case_subcommand.txt", b"Client Reply Off\n"),
        seed("uppercase_value.txt", b"CLIENT REPLY ON\n"),
        seed("mixed_case_value.txt", b"CLIENT REPLY Skip\n"),
        # ── Interleaved CLIENT REPLY + other commands ────────────
        seed("multiple_skips_only_one_persists.txt",
             b"CLIENT REPLY SKIP\nCLIENT REPLY SKIP\nPING\nPING\n"),
        seed("client_other_subcommand_mixed.txt",
             b"CLIENT NO-EVICT ON\nCLIENT REPLY ON\nPING\n"),
        seed("echo_hello_alone.txt", b"ECHO hello\n"),
        seed("ping_alone.txt", b"PING\n"),
        seed("ping_then_echo.txt", b"PING\nECHO hello\n"),
        # ── Long sequences ────────────────────────────────────────
        seed("long_alternating_off_on.txt",
             (b"CLIENT REPLY OFF\nGET k\nCLIENT REPLY ON\nGET k\n" * 4)),
        seed("many_skips_with_intervening_commands.txt",
             b"CLIENT REPLY SKIP\nGET a\n"
             b"CLIENT REPLY SKIP\nGET b\n"
             b"CLIENT REPLY SKIP\nGET c\n"),
        # ── Reject-class: parser surfaces wrong arity / invalid ──
        seed("reply_no_mode_arg.txt", b"CLIENT REPLY\n"),
        seed("reply_extra_arg.txt", b"CLIENT REPLY ON NOW\n"),
        seed("reply_bogus_mode.txt", b"CLIENT REPLY BOGUS\n"),
        seed("client_only_no_subcommand.txt", b"CLIENT\n"),
        seed("reply_with_two_extras.txt", b"CLIENT REPLY ON ALSO TODAY\n"),
        seed("reply_empty_mode.txt", b"CLIENT REPLY \n"),
        seed("reply_lowercase_invalid_mode.txt", b"CLIENT REPLY maybe\n"),
        seed("reply_numeric_mode.txt", b"CLIENT REPLY 1\n"),
        # ── Edge: NUL byte as command separator ─────────────────
        seed("nul_separator_in_stream.txt",
             b"CLIENT REPLY OFF\x00CLIENT REPLY ON\n"),
    ]

    for label, payload in seeds:
        path = out_dir / label
        path.write_bytes(payload)
        print(f"wrote {len(payload):4d} bytes to {path.relative_to(repo)}")
    print(f"\ngenerated {len(seeds)} corpus seeds")


if __name__ == "__main__":
    main()
