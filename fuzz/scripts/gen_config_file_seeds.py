#!/usr/bin/env python3
"""Generate structured corpus seeds for fuzz_config_file.

The fuzz target runs every input through `fuzz_raw_config`
(parse_redis_config_bytes + split_config_line_args_bytes) and ALSO
hands the same bytes to `arbitrary` to derive a structured config
file. Seeds are most valuable as raw byte streams that look like
realistic Redis config — libfuzzer mutates from these starting
points into both the structured-Valid path AND the raw path.

The catalogue covers each branch parse_redis_config_bytes /
split_config_line_args_bytes care about:

  Accept-class:
    - empty
    - blank / whitespace-only
    - comment-only
    - single bare directive
    - multi-directive file
    - leading + trailing whitespace tolerance
    - tab-separated tokens
    - inline trailing whitespace
    - bare token alongside quoted token
    - double-quoted with escapes (\\xHH / \\n / \\r / \\t / \\\\ / \\")
    - single-quoted with \\\\ and \\'
    - empty double-quoted / empty single-quoted
    - tls-protocols multi-token quoted
    - include directive
    - save 900 1 (canonical Redis snapshot directive)
    - directive with mixed-case name (parser lowercases)
    - very long bare token at MAX_TOKEN_LEN boundary
    - many directives in one file (stress)

  Reject-class:
    - unterminated double quote
    - unterminated single quote
    - bare backslash at EOF (continuation in unquoted is fine,
      unterminated escape inside double-quoted is rejected)

Run:
    python3 fuzz/scripts/gen_config_file_seeds.py
"""
from __future__ import annotations

from pathlib import Path


def seed(label: str, body: bytes) -> tuple[str, bytes]:
    return (label, body)


def main() -> None:
    repo = Path(__file__).resolve().parent.parent.parent
    out_dir = repo / "fuzz" / "corpus" / "fuzz_config_file"
    out_dir.mkdir(parents=True, exist_ok=True)

    seeds: list[tuple[str, bytes]] = [
        # ── Accept-class ─────────────────────────────────────────
        seed("empty.conf", b""),
        seed("only_blank_lines.conf", b"\n\n\n"),
        seed("only_whitespace.conf", b"   \t\t  \n  \n"),
        seed("only_comment.conf", b"# this is a comment\n"),
        seed("comment_with_leading_whitespace.conf", b"   # indented comment\n"),
        seed("single_directive.conf", b"port 6379\n"),
        seed(
            "two_directives.conf",
            b"port 6379\nappendonly yes\n",
        ),
        seed(
            "directive_with_three_args.conf",
            b"save 900 1\n",
        ),
        seed(
            "directive_with_two_save_args.conf",
            b"save 3600 100\nsave 300 1000\n",
        ),
        seed(
            "tab_separated_tokens.conf",
            b"port\t6379\n",
        ),
        seed(
            "trailing_whitespace.conf",
            b"port 6379   \n",
        ),
        seed(
            "leading_whitespace.conf",
            b"   port 6379\n",
        ),
        seed(
            "double_quoted_simple.conf",
            b'requirepass "secret"\n',
        ),
        seed(
            "double_quoted_with_spaces.conf",
            b'tls-protocols "TLSv1.2 TLSv1.3"\n',
        ),
        seed(
            "double_quoted_hex_escape.conf",
            b'requirepass "\\x70\\x61\\x73\\x73"\n',
        ),
        seed(
            "double_quoted_special_escapes.conf",
            b'requirepass "tab\\there\\nthere"\n',
        ),
        seed(
            "double_quoted_backslash_and_quote.conf",
            b'requirepass "back\\\\slash and \\"quote\\""\n',
        ),
        seed(
            "single_quoted_simple.conf",
            b"requirepass 'secret'\n",
        ),
        seed(
            "single_quoted_backslash_and_quote.conf",
            b"requirepass 'back\\\\slash and \\'quote\\''\n",
        ),
        seed(
            "empty_double_quoted_arg.conf",
            b'logfile ""\n',
        ),
        seed(
            "empty_single_quoted_arg.conf",
            b"logfile ''\n",
        ),
        seed(
            "include_directive.conf",
            b"include /etc/redis/conf.d/local.conf\n",
        ),
        seed(
            "module_load_directive.conf",
            b"loadmodule /usr/lib/redis/modules/redisbloom.so\n",
        ),
        seed(
            "uppercase_directive_name.conf",
            b"MAXMEMORY 100mb\n",
        ),
        seed(
            "mixed_case_directive_name.conf",
            b"AppendOnly yes\n",
        ),
        seed(
            "mixed_quoted_and_bare_tokens.conf",
            b'rename-command CONFIG ""\n',
        ),
        seed(
            "user_acl_directive.conf",
            b"user alice on >secret +@all ~*\n",
        ),
        seed(
            "comment_then_directive.conf",
            b"# header\nport 6379\n",
        ),
        seed(
            "many_directives.conf",
            b"port 6379\n"
            b"bind 127.0.0.1 ::1\n"
            b"appendonly yes\n"
            b"appendfsync everysec\n"
            b"save 900 1\n"
            b"save 300 10\n"
            b"maxmemory 100mb\n"
            b"maxmemory-policy allkeys-lru\n"
            b"tls-port 6380\n"
            b'tls-protocols "TLSv1.2 TLSv1.3"\n'
            b"requirepass strongpass\n"
            b"loglevel notice\n",
        ),
        seed(
            "long_bare_token.conf",
            b"requirepass " + b"a" * 200 + b"\n",
        ),
        seed(
            "no_trailing_newline.conf",
            b"port 6379",
        ),
        seed(
            "crlf_line_endings.conf",
            b"port 6379\r\nappendonly yes\r\n",
        ),
        # ── Reject-class ──────────────────────────────────────────
        seed("unterminated_double_quote.conf", b'requirepass "secret\n'),
        seed("unterminated_single_quote.conf", b"requirepass 'secret\n"),
        seed("backslash_at_eof_in_double_quote.conf", b'requirepass "secret\\\n'),
    ]

    for label, payload in seeds:
        path = out_dir / label
        path.write_bytes(payload)
        print(f"wrote {len(payload):4d} bytes to {path.relative_to(repo)}")
    print(f"\ngenerated {len(seeds)} corpus seeds")


if __name__ == "__main__":
    main()
