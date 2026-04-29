#!/usr/bin/env python3
"""Generate structured corpus seeds for fuzz_runtime_execute_bytes.

The fuzz target dispatches the first byte two ways (`mode % 2`):

    0 → fuzz_raw_bytes(body)
        body is fed straight into Runtime::execute_bytes. The
        invariant: any byte stream whose first frame parses under
        the runtime's wire-side parser config must produce the
        same reply as Runtime::execute_frame on that parsed frame.

    1 → fuzz_valid_command(structured)
        body is fed to `arbitrary` to derive a StructuredCommand,
        which is encoded as a RESP array and fed to BOTH
        execute_bytes and execute_frame; the replies must match.

The arbitrary format isn't version-stable, so we only seed mode 0
here — every seed carries `\\x00<resp-body>` so `mode % 2 == 0`
selects the raw path. The seed catalogue covers each meaningful
class of RESP input the runtime handles:

  Accept-class (the runtime produces a reply, no parser error):
    - canonical PING
    - PING with payload (echoed back)
    - ECHO hello
    - SELECT 0 (DB switch)
    - SET k v / GET k / DEL k / EXISTS k
    - INCR / DECR
    - TYPE / TTL / DBSIZE / TIME
    - KEYS * (glob)
    - INFO / INFO server
    - CONFIG GET maxmemory
    - CLIENT GETNAME / CLIENT SETNAME
    - HELLO 2 (RESP2 negotiation)
    - RESET
    - inline-protocol PING (no `*` prefix, just bytes)

  Error-path (parser or command-level rejection — runtime returns
  an Error frame, but the bytes themselves still parse):
    - empty array  *0\\r\\n
    - unknown command
    - SUBSCRIBE chan (multi-channel pubsub setup)
    - bare `\\r\\n`  (parser early-Incomplete)

  Adversarial (parser-level rejection — runtime emits a protocol
  error but never panics):
    - $-2\\r\\n  (negative bulk length)
    - RESP3 prefix `%0\\r\\n` (rejected by allow_resp3=false)
    - bulk length way over MAX_BULK_LEN
    - truncated bulk length

Run:
    python3 fuzz/scripts/gen_runtime_execute_bytes_seeds.py
"""
from __future__ import annotations

from pathlib import Path

# Mode byte 0x00 → mode % 2 == 0 → fuzz_raw_bytes path.
RAW_MODE = b"\x00"


def resp_array(parts: list[bytes]) -> bytes:
    """Encode a RESP2 array of bulk strings."""
    out = bytearray(b"*")
    out.extend(str(len(parts)).encode())
    out.extend(b"\r\n")
    for part in parts:
        out.extend(b"$")
        out.extend(str(len(part)).encode())
        out.extend(b"\r\n")
        out.extend(part)
        out.extend(b"\r\n")
    return bytes(out)


def seed(label: str, body: bytes) -> tuple[str, bytes]:
    return (label, RAW_MODE + body)


def main() -> None:
    repo = Path(__file__).resolve().parent.parent.parent
    out_dir = repo / "fuzz" / "corpus" / "fuzz_runtime_execute_bytes"
    out_dir.mkdir(parents=True, exist_ok=True)

    seeds: list[tuple[str, bytes]] = [
        # ── Accept-class (canonical RESP commands) ─────────────
        seed("ping_no_arg.resp", resp_array([b"PING"])),
        seed("ping_with_payload.resp", resp_array([b"PING", b"hello"])),
        seed("echo.resp", resp_array([b"ECHO", b"hello"])),
        seed("select_db_zero.resp", resp_array([b"SELECT", b"0"])),
        seed("set_basic.resp", resp_array([b"SET", b"k", b"v"])),
        seed("get_basic.resp", resp_array([b"GET", b"k"])),
        seed("del_basic.resp", resp_array([b"DEL", b"k"])),
        seed("exists_basic.resp", resp_array([b"EXISTS", b"k"])),
        seed("incr.resp", resp_array([b"INCR", b"counter"])),
        seed("decr.resp", resp_array([b"DECR", b"counter"])),
        seed("type_check.resp", resp_array([b"TYPE", b"k"])),
        seed("ttl_check.resp", resp_array([b"TTL", b"k"])),
        seed("dbsize.resp", resp_array([b"DBSIZE"])),
        seed("time.resp", resp_array([b"TIME"])),
        seed("keys_glob_all.resp", resp_array([b"KEYS", b"*"])),
        seed("info_default.resp", resp_array([b"INFO"])),
        seed("info_server_section.resp", resp_array([b"INFO", b"server"])),
        seed("config_get_maxmem.resp",
             resp_array([b"CONFIG", b"GET", b"maxmemory"])),
        seed("client_getname.resp", resp_array([b"CLIENT", b"GETNAME"])),
        seed("client_setname.resp",
             resp_array([b"CLIENT", b"SETNAME", b"alice"])),
        seed("hello_resp2.resp", resp_array([b"HELLO", b"2"])),
        seed("reset.resp", resp_array([b"RESET"])),
        seed("set_with_ex.resp",
             resp_array([b"SET", b"k", b"v", b"EX", b"60"])),
        seed("set_nx.resp",
             resp_array([b"SET", b"k", b"v", b"NX"])),
        seed("subscribe_one_channel.resp",
             resp_array([b"SUBSCRIBE", b"chan1"])),
        seed("subscribe_multi_channels.resp",
             resp_array([b"SUBSCRIBE", b"alpha", b"beta", b"gamma"])),
        # ── Error-path (parser accepts, runtime returns Error) ─
        seed("empty_array.resp", b"*0\r\n"),
        seed("unknown_command.resp",
             resp_array([b"NOTACOMMAND", b"arg"])),
        seed("set_wrong_arity.resp", resp_array([b"SET", b"k"])),
        seed("get_wrong_arity_zero.resp", resp_array([b"GET"])),
        # Inline-protocol form (no `*` prefix). Runtime supports
        # this for legacy clients.
        seed("inline_ping.resp", b"PING\r\n"),
        seed("inline_echo_with_arg.resp", b"ECHO hello\r\n"),
        # ── Adversarial (parser-level rejection) ───────────────
        seed("negative_bulk_len.resp", b"$-2\r\n"),
        seed("bulk_length_too_large.resp",
             b"$1000000000\r\nSHORT\r\n"),
        seed("truncated_bulk_length_no_crlf.resp", b"$5"),
        seed("array_negative_count.resp", b"*-2\r\n"),
        seed("resp3_map_prefix_rejected.resp", b"%0\r\n"),
        seed("resp3_set_prefix_rejected.resp", b"~0\r\n"),
        # ── Edge ────────────────────────────────────────────────
        seed("empty_resp_body.resp", b""),
        seed("just_crlf.resp", b"\r\n"),
        seed("bare_lf.resp", b"\n"),
    ]

    for label, payload in seeds:
        path = out_dir / label
        path.write_bytes(payload)
        print(f"wrote {len(payload):4d} bytes to {path.relative_to(repo)}")
    print(f"\ngenerated {len(seeds)} corpus seeds")


if __name__ == "__main__":
    main()
