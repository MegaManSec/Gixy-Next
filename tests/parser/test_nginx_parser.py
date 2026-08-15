import pytest

from gixy.directives.block import *
from gixy.directives.directive import *
from gixy.parser.nginx_parser import NginxParser


def _parse(config):
    return NginxParser(cwd="", allow_includes=False).parse_string(config)


def _parse_via_compat_parse(config):
    """Use the deprecated NginxParser.parse() alias for backward-compat tests."""
    return NginxParser(cwd="", allow_includes=False).parse(config)


@pytest.mark.parametrize('config,expected', zip(
    [
        'access_log syslog:server=127.0.0.1,tag=nginx_sentry toolsformat;',
        'user http;',
        'internal;',
        'set $foo "bar";',
        "set $foo 'bar';",
        'proxy_pass http://unix:/run/sock.socket;',
        'rewrite ^/([a-zA-Z0-9]+)$ /$1/${arg_v}.pb break;'
    ],

    [
        [Directive],
        [Directive],
        [Directive],
        [Directive, SetDirective],
        [Directive, SetDirective],
        [Directive],
        [Directive, RewriteDirective]
    ]
))
def test_directive(config, expected):
    assert_config(config, expected)


@pytest.mark.parametrize('config,expected', zip(
    [
        'if (-f /some) {}',
        'map $uri $avar {}',
        'location / {}'
    ],

    [
        [Directive, Block, IfBlock],
        [Directive, Block, MapBlock],
        [Directive, Block, LocationBlock],
    ]
))
def test_blocks(config, expected):
    assert_config(config, expected)


def test_dump_simple():
    config = '''
# configuration file /etc/nginx/nginx.conf:
http {
    include sites/*.conf;
}

# configuration file /etc/nginx/conf.d/listen:
listen 80;

# configuration file /etc/nginx/sites/default.conf:
server {
    include conf.d/listen;
}
    '''

    tree = _parse(config)
    assert isinstance(tree, Directive)
    assert isinstance(tree, Block)
    assert isinstance(tree, Root)

    assert len(tree.children) == 1
    http = tree.children[0]
    assert isinstance(http, Directive)
    assert isinstance(http, Block)
    assert isinstance(http, HttpBlock)

    # After flattening dump includes, server block is directly under http
    assert len(http.children) == 1
    server = http.children[0]
    assert isinstance(server, Directive)
    assert isinstance(server, Block)
    assert isinstance(server, ServerBlock)

    # listen directive from included file is now flattened under server
    assert len(server.children) == 1
    listen = server.children[0]
    assert isinstance(listen, Directive)
    assert listen.args == ['80']


def test_encoding():
    configs = [
        'bar "\xD1\x82\xD0\xB5\xD1\x81\xD1\x82";'
    ]

    for i, config in enumerate(configs):
        _parse(config)


def test_dump_nested_include_resolves_relative_to_root():
    config = '''
# configuration file /etc/nginx/nginx.conf:
http {
    include sites/a.conf;
}

# configuration file /etc/nginx/sites/a.conf:
server {
    include snippets/shared;
}

# configuration file /etc/nginx/snippets/shared:
add_header X-Test 1;
    '''

    tree = _parse(config)
    assert isinstance(tree, Directive)
    assert isinstance(tree, Block)
    assert isinstance(tree, Root)

    assert len(tree.children) == 1
    http = tree.children[0]
    assert isinstance(http, Directive)
    assert isinstance(http, Block)
    assert isinstance(http, HttpBlock)

    # server is directly under http after flattening
    assert len(http.children) == 1
    server = http.children[0]
    assert isinstance(server, Directive)
    assert isinstance(server, Block)
    assert isinstance(server, ServerBlock)

    # add_header from snippets/shared is flattened under server
    assert len(server.children) == 1
    add_header = server.children[0]
    assert isinstance(add_header, Directive)
    assert add_header.name == 'add_header'
    assert add_header.args == ['X-Test', '1']


def test_dump_sibling_includes_resolve_from_prefix():
    config = '''
# configuration file /etc/nginx/nginx.conf:
http {
    include sites/default.conf;
}

# configuration file /etc/nginx/sites/default.conf:
server {
    include conf.d/listen;
    include conf.d/add_header;
}

# configuration file /etc/nginx/conf.d/listen:
listen 80;

# configuration file /etc/nginx/conf.d/add_header:
add_header X-Foo bar;
    '''

    tree = _parse(config)
    http = tree.children[0]
    server = http.children[0]

    assert len(server.children) == 2
    names = [c.name for c in server.children]
    assert 'listen' in names
    assert 'add_header' in names


@pytest.mark.parametrize("config", [
    'user http;',
    'location / {}',
])
def test_parse_alias_matches_parse_string_for_simple_configs(config):
    tree_direct = _parse(config)
    tree_compat = _parse_via_compat_parse(config)

    # Both APIs should return a Root with a single child of the same directive type.
    assert isinstance(tree_direct, Root)
    assert isinstance(tree_compat, Root)
    assert len(tree_direct.children) == len(tree_compat.children) == 1
    assert type(tree_direct.children[0]) is type(tree_compat.children[0])


def test_parse_alias_handles_dump_same_as_parse_string():
    config = '''
# configuration file /etc/nginx/nginx.conf:
http {
    include sites/*.conf;
}

# configuration file /etc/nginx/conf.d/listen:
listen 80;

# configuration file /etc/nginx/sites/default.conf:
server {
    include conf.d/listen;
}
    '''

    tree_direct = _parse(config)
    tree_compat = _parse_via_compat_parse(config)

    # Both trees should have the same high-level shape for dump parsing.
    assert isinstance(tree_direct, Root)
    assert isinstance(tree_compat, Root)
    assert len(tree_direct.children) == len(tree_compat.children) == 1
    assert isinstance(tree_direct.children[0], HttpBlock)
    assert isinstance(tree_compat.children[0], HttpBlock)


def test_include_self_cycle_is_broken(tmp_path):
    """A file that includes itself must not recurse forever."""
    (tmp_path / "self.conf").write_text("worker_processes 1;\ninclude self.conf;\n")
    root = NginxParser(cwd=str(tmp_path), allow_includes=True).parse_file(
        str(tmp_path / "self.conf")
    )
    assert isinstance(root, Root)
    assert len(root.children) < 10


def test_include_mutual_cycle_is_broken(tmp_path):
    """An A <-> B mutual include cycle is broken instead of recursing."""
    (tmp_path / "a.conf").write_text("include b.conf;\n")
    (tmp_path / "b.conf").write_text("include a.conf;\n")
    root = NginxParser(cwd=str(tmp_path), allow_includes=True).parse_file(
        str(tmp_path / "a.conf")
    )
    assert isinstance(root, Root)
    assert len(root.children) < 10


def test_include_transitive_cycle_is_broken(tmp_path):
    """An A -> B -> C -> A transitive include cycle is broken."""
    (tmp_path / "a.conf").write_text("include b.conf;\n")
    (tmp_path / "b.conf").write_text("include c.conf;\n")
    (tmp_path / "c.conf").write_text("include a.conf;\n")
    root = NginxParser(cwd=str(tmp_path), allow_includes=True).parse_file(
        str(tmp_path / "a.conf")
    )
    assert isinstance(root, Root)
    assert len(root.children) < 10


def test_dump_include_self_cycle_is_broken():
    """A dump file that includes itself must not recurse forever."""
    config = '''
# configuration file /etc/nginx/nginx.conf:
worker_processes 1;
include /etc/nginx/nginx.conf;
    '''

    tree = _parse(config)
    assert isinstance(tree, Root)
    assert len(tree.children) < 10
    names = [c.name for c in tree.children]
    assert 'worker_processes' in names


def test_dump_include_mutual_cycle_is_broken():
    """An A <-> B mutual include cycle between dump files is broken."""
    config = '''
# configuration file /etc/nginx/nginx.conf:
worker_processes 1;
include /etc/nginx/a.conf;

# configuration file /etc/nginx/a.conf:
include /etc/nginx/b.conf;

# configuration file /etc/nginx/b.conf:
include /etc/nginx/a.conf;
    '''

    tree = _parse(config)
    assert isinstance(tree, Root)
    assert len(tree.children) < 10
    names = [c.name for c in tree.children]
    assert 'worker_processes' in names


def assert_config(config, expected):
    tree = _parse(config)
    assert isinstance(tree, Directive)
    assert isinstance(tree, Block)
    assert isinstance(tree, Root)

    child = tree.children[0]
    for ex in expected:
        assert isinstance(child, ex)
