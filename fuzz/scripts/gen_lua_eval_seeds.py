#!/usr/bin/env python3
"""Generate structured corpus seeds for fuzz_lua_eval.

The fuzz target dispatches the first byte two ways (`mode % 2`):

    0 → fuzz_raw_lua(body)
        body is fed straight into `fr_command::eval_script`. The
        harness wires keys=["key"] and argv=["arg"]. The invariant
        is purely "does not panic" — the eval result (Ok or Err) is
        not asserted, since the result depends on the script.

    1 → fuzz_structured_lua(case)
        body is fed to `arbitrary` which builds a StructuredLuaCase.
        The invariants tested are determinism: the same script must
        produce the same result across fresh stores, and harmless
        whitespace padding must not change the result.

The arbitrary format isn't version-stable, so we only seed the raw
path here — every seed has mode_byte = 0x00 so `mode % 2 == 0`
selects raw Lua. The seed catalogue covers each meaningful branch
of the eval path:

  Valid scripts (must complete without panic):
    - empty script
    - simple integer / string / boolean returns
    - arithmetic, modulo, length operators
    - string concatenation
    - if/else with comparison
    - numeric `for` loop
    - local / global identifier shadowing
    - table literal construction + indexing
    - ipairs / pairs iteration
    - redis.call with valid args (SET/GET/DEL flow)
    - redis.error_reply + redis.status_reply
    - redis.sha1hex
    - KEYS / ARGV table access (harness wires "key"/"arg")
    - cjson.encode + cjson.decode round-trip
    - pcall around a failing redis.call

  Edge cases / error-path scripts (must reject without panic):
    - syntax error (mismatched parens)
    - undefined global access
    - explicit error("…") call
    - infinite while-true (must hit step limit)
    - Redis 7.0 #! shebang header (parser must strip)

Run:
    python3 fuzz/scripts/gen_lua_eval_seeds.py
"""
from __future__ import annotations

from pathlib import Path

# mode_byte = 0x00 → fuzz_raw_lua path.
RAW_MODE = b"\x00"


def seed(label: str, script: bytes) -> tuple[str, bytes]:
    return (label, RAW_MODE + script)


def main() -> None:
    repo = Path(__file__).resolve().parent.parent.parent
    out_dir = repo / "fuzz" / "corpus" / "fuzz_lua_eval"
    out_dir.mkdir(parents=True, exist_ok=True)

    seeds: list[tuple[str, bytes]] = [
        # ── Valid scripts ────────────────────────────────────────
        seed("empty.lua", b""),
        seed("return_integer.lua", b"return 42"),
        seed("return_string.lua", b'return "hello"'),
        seed("return_bool.lua", b"return true"),
        seed("return_nil.lua", b"return nil"),
        seed("arithmetic.lua", b"return 1 + 2 * 3"),
        seed("modulo.lua", b"return 10 % 3"),
        seed("string_length.lua", b'return #"abc"'),
        seed("string_concat.lua", b'return "a" .. "b" .. "c"'),
        seed(
            "if_else.lua",
            b'if 1 < 2 then return "less" else return "ge" end',
        ),
        seed(
            "numeric_for_sum.lua",
            b"local total = 0\nfor i = 1, 5 do total = total + i end\nreturn total",
        ),
        seed(
            "local_alias.lua",
            b"local x = 7\nlocal x = x + 1\nreturn x",
        ),
        seed(
            "table_index.lua",
            b'local t = {"a", "b", "c"}\nreturn t[2]',
        ),
        seed(
            "ipairs_iter.lua",
            b"local t = {10, 20, 30}\nlocal sum = 0\nfor _, v in ipairs(t) do sum = sum + v end\nreturn sum",
        ),
        seed(
            "pairs_iter.lua",
            b'local t = {a=1, b=2}\nlocal sum = 0\nfor _, v in pairs(t) do sum = sum + v end\nreturn sum',
        ),
        seed(
            "keys_argv_echo.lua",
            b"return {KEYS[1], ARGV[1]}",
        ),
        seed(
            "redis_call_set_get.lua",
            b'redis.call("SET", KEYS[1], ARGV[1])\nreturn redis.call("GET", KEYS[1])',
        ),
        seed(
            "redis_status_reply.lua",
            b'return redis.status_reply("OK")',
        ),
        seed(
            "redis_error_reply.lua",
            b'return redis.error_reply("ERR custom")',
        ),
        seed(
            "redis_sha1hex.lua",
            b'return redis.sha1hex("hello")',
        ),
        seed(
            "cjson_roundtrip.lua",
            b'local s = cjson.encode({1, 2, 3})\nlocal v = cjson.decode(s)\nreturn v[2]',
        ),
        seed(
            "pcall_redis_call_failure.lua",
            b'local ok, err = pcall(redis.call, "SET")\nif ok then return "ok" else return "caught" end',
        ),
        seed(
            "shebang_header_redis7.lua",
            b'#!lua flags=no-writes\nreturn 1 + 1',
        ),
        # ── Error-path / edge scripts ────────────────────────────
        seed(
            "syntax_error_paren.lua",
            b'return (1 + 2',
        ),
        seed(
            "undefined_global.lua",
            b"return totallyMadeUpGlobal",
        ),
        seed(
            "explicit_error.lua",
            b'error("forced failure")',
        ),
        seed(
            "infinite_while_true.lua",
            b"while true do end\nreturn 0",
        ),
        seed(
            "table_index_out_of_range.lua",
            b"local t = {1, 2}\nreturn t[100]",
        ),
        seed(
            "long_concat.lua",
            b'local s = ""\nfor i = 1, 8 do s = s .. "x" end\nreturn #s',
        ),
        seed(
            "nested_function.lua",
            b"local function f(x) return x * 2 end\nlocal function g(x) return f(x) + 1 end\nreturn g(5)",
        ),
    ]

    for label, payload in seeds:
        path = out_dir / label
        path.write_bytes(payload)
        print(f"wrote {len(payload):4d} bytes to {path.relative_to(repo)}")
    print(f"\ngenerated {len(seeds)} corpus seeds")


if __name__ == "__main__":
    main()
