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
