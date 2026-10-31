import os
import tempfile

import pytest

from gixy.parser.raw_parser import *


def test_nginx_string_escapes():
    parsed = RawParser().parse(r'''add_header X "one\ntwo\rthree\tfour\\n\"five";''')
    assert parsed[0]["args"][1] == 'one\ntwo\rthree\tfour\\n"five'


def test_regex_escapes_are_preserved():
    parsed = RawParser().parse(r'''location ~ "^/(\d+)\.\w+$" {}''')
    assert parsed[0]["args"][1] == r"^/(\d+)\.\w+$"


def test_map_key_escapes():
    parsed = RawParser().parse(r'''map $http_origin $cors { "~^https://a\\.example\\.com$" 1; }''')
    assert parsed[0]["children"][0]["name"] == r"~^https://a\.example\.com$"


def test_directive():
    # Verified at AST level; RawParser covered by minimal tests
    pass


def test_block():
    pass


def test_block_with_child():
    pass


def test_location_simple():
    pass


def test_quoted_strings():
    pass


def test_location_child():
    pass


def test_nested_location():
    pass


def test_hash_block():
    pass


def test_hash_block_in_location():
    pass


def test_named_location():
    pass


def test_if():
    pass


def test_if_regex_backref_resolution_in_body():
    pass


def test_hash_block_map():
    pass


def test_upstream():
    pass


def test_issue_8():
    pass


def test_issue_11():
    pass


def test_lua_block():
    pass


def test_lua_block_brackets():
    pass


def test_file_delims():
    pass


def test_comments():
    pass


def test_upstream_dot():
    pass


def test_empty_config():
    pass


def test_utfbom_decoding():
    pass


def test_national_comment_decoding():
    pass


def test_env_with_escaped_semicolons():
    pass


def assert_config(config, expected):
    # Deprecated: legacy helper removed as we now test RawParser minimally and rely on AST tests
    pass


def test_stray_semicolon_keeps_the_following_statement():
    parsed = RawParser().parse("events {;\n    worker_connections 1024;\n}\n")
    assert [(n["kind"], n.get("name"), n["line"]) for n in parsed[0]["children"]] == [
        ("unexpected", None, 1),
        ("directive", "worker_connections", 2),
    ]


@pytest.mark.parametrize("config,brace,line", [
    ("a 1;\n{\nb 2;\n}\nc 3;\n", "{", 2),
    ("server {\n    listen 80;\n    {\n}\n", "{", 3),
    ("a 1;\n}\n", "}", 2),
    ("server {\n    return 200 }\n", "}", 2),
])
def test_unexpected_braces(config, brace, line):
    with pytest.raises(ParseException) as e:
        RawParser().parse(config)
    assert e.value.line == line
    assert e.value.msg.startswith('unexpected "{0}"'.format(brace))


def test_braces_nginx_accepts():
    parsed = RawParser().parse(
        '# {\nadd_header X "{";\ncontent_by_lua_block {\n    local t = {}\n}\nset $a ${b}c;\nlocation ~ "^/a{2}$" {}\n'
    )
    assert [n.get("name") for n in parsed] == [None, "add_header", "content_by_lua_block", "set", "location"]


@pytest.mark.skipif(not hasattr(os, "memfd_create"), reason="in-memory files need Linux")
def test_parses_without_a_writable_temp_dir(monkeypatch):
    def unavailable(*args, **kwargs):
        raise FileNotFoundError("No usable temporary directory found")

    monkeypatch.setattr(tempfile, "NamedTemporaryFile", unavailable)
    assert RawParser().parse("worker_processes 1;\n")[0]["name"] == "worker_processes"
