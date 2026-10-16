from gixy.directives.block import *
from gixy.parser.nginx_parser import NginxParser

# TODO(buglloc): what about include block?


def _get_parsed(config):
    root = NginxParser(cwd='', allow_includes=False).parse_string(config)
    return root.children[0]


def test_block():
    config = 'some {some;}'

    directive = _get_parsed(config)
    assert isinstance(directive, Block)
    assert directive.is_block
    assert directive.self_context
    assert not directive.provide_variables


def test_http():
    config = '''
http {
    default_type  application/octet-stream;
    sendfile        on;
    keepalive_timeout  65;
}
    '''

    directive = _get_parsed(config)
    assert isinstance(directive, HttpBlock)
    assert directive.is_block
    assert directive.self_context
    assert not directive.provide_variables


def test_server():
    config = '''
server {
    listen 80;
    server_name _;
    server_name cool.io;
}

    '''

    directive = _get_parsed(config)
    assert isinstance(directive, ServerBlock)
    assert directive.is_block
    assert directive.self_context
    assert [d.args[0] for d in directive.get_names()] == ['_', 'cool.io']
    assert not directive.provide_variables


def test_location():
    config = '''
location / {
}
    '''

    directive = _get_parsed(config)
    assert isinstance(directive, LocationBlock)
    assert directive.is_block
    assert directive.self_context
    assert directive.provide_variables
    assert directive.modifier is None
    assert directive.path == '/'
    assert not directive.is_internal


def test_location_internal():
    config = '''
location / {
    internal;
}
    '''

    directive = _get_parsed(config)
    assert isinstance(directive, LocationBlock)
    assert directive.is_internal


def test_location_modifier():
    config = '''
location = / {
}
    '''

    directive = _get_parsed(config)
    assert isinstance(directive, LocationBlock)
    assert directive.modifier == '='
    assert directive.path == '/'


def test_if():
    config = '''
if ($some) {
}
    '''

    directive = _get_parsed(config)
    assert isinstance(directive, IfBlock)
    assert directive.is_block
    assert not directive.self_context
    assert not directive.provide_variables
    assert directive.variable == '$some'
    assert directive.operand is None
    assert directive.value is None


def test_if_with_regex():
    config = '''
if ($var ~* (a)(b)) {
return 301 /$1/$2;
}
    '''

    directive = _get_parsed(config)
    assert isinstance(directive, IfBlock)
    assert directive.is_block
    assert not directive.self_context
    assert directive.provide_variables
    assert directive.variable == '$var'
    assert directive.operand == '~*'
    assert directive.value == '(a)(b)'
    assert len(directive.variables[0].value.parsed) == 2


def test_if_modifier():
    config = '''
if (-f /some) {
}
    '''

    directive = _get_parsed(config)
    assert isinstance(directive, IfBlock)
    assert directive.operand == '-f'
    assert directive.value == '/some'
    assert directive.variable is None


def test_if_variable():
    config = '''
if ($http_some = '/some') {
}
    '''

    directive = _get_parsed(config)
    assert isinstance(directive, IfBlock)
    assert directive.variable == '$http_some'
    assert directive.operand == '='
    assert directive.value == '/some'


def test_if_regex_backrefs_provide_variables():
    from gixy.core.manager import Manager
    from gixy.directives.block import IfBlock
    from gixy.parser.nginx_parser import NginxParser

    config = r"""
    if ($request_uri ~ ^/old-path/(.*)) {
        set $new_value $1;
        return 301 /new-path/$new_value;
    }
    """

    tree = NginxParser(cwd='', allow_includes=False).parse_string(config)
    # Find the IfBlock and ensure variables (numeric backrefs) are provided
    if_block = None
    for child in tree.children:
        if child.name == 'if':
            if_block = child
            break
    assert if_block is not None
    # Backref variables should be present (at least group 0 and 1)
    var_names = sorted([v.name for v in if_block.variables])
    assert 0 in var_names and 1 in var_names


def test_block_some_flat():
    config = '''
    some {
        default_type  application/octet-stream;
        sendfile        on;
        if (-f /some/) {
            keepalive_timeout  65;
        }
    }
        '''

    directive = _get_parsed(config)
    for d in ['default_type', 'sendfile', 'keepalive_timeout']:
        c = directive.some(d, flat=True)
        assert c is not None
        assert c.name == d


def test_block_some_not_flat():
    config = '''
    some {
        default_type  application/octet-stream;
        sendfile        on;
        if (-f /some/) {
            keepalive_timeout  65;
        }
    }
        '''

    directive = _get_parsed(config)
    c = directive.some('keepalive_timeout', flat=False)
    assert c is None


def test_block_find_flat():
    config = '''
    some {
        directive 1;
        if (-f /some/) {
            directive 2;
        }
    }
        '''

    directive = _get_parsed(config)
    finds = directive.find('directive', flat=True)
    assert len(finds) == 2
    assert [x.name for x in finds] == ['directive', 'directive']
    assert [x.args[0] for x in finds] == ['1', '2']


def test_block_find_not_flat():
    config = '''
    some {
        directive 1;
        if (-f /some/) {
            directive 2;
        }
    }
        '''

    directive = _get_parsed(config)
    finds = directive.find('directive', flat=False)
    assert len(finds) == 1
    assert [x.name for x in finds] == ['directive']
    assert [x.args[0] for x in finds] == ['1']


def test_block_map():
    config = '''
map $some_var $some_other_var {
    a   b;
    ~*(.*) $1;
    default c;
}
    '''

    directive = _get_parsed(config)
    assert isinstance(directive, MapBlock)
    assert directive.is_block
    assert not directive.self_context
    assert directive.provide_variables
    assert directive.source == '$some_var'
    assert directive.variable == 'some_other_var'
    assert directive.children
    assert len(directive.children) == 3
    assert [c.src_val for c in directive.children] == ['a', '~*(.*)', 'default']
    assert [c.dest_val for c in directive.children] == ['b', '$1', 'c']


def test_block_geo_two_vars():
    config = '''
geo $some_var $some_other_var {
    1.2.3.4 b;
    default c;
}
    '''

    directive = _get_parsed(config)
    assert isinstance(directive, GeoBlock)
    assert directive.is_block
    assert not directive.self_context
    assert directive.provide_variables
    assert directive.source == '$some_var'
    assert directive.variable == 'some_other_var'
    assert directive.children
    assert len(directive.children) == 2
    assert [c.src_val for c in directive.children] == ['1.2.3.4', 'default']
    assert [c.dest_val for c in directive.children] == ['b', 'c']


def test_block_geo_one_var():
    config = '''
geo $some_var {
    5.6.7.8 d;
    default e;
}
    '''

    directive = _get_parsed(config)
    assert isinstance(directive, GeoBlock)
    assert directive.is_block
    assert not directive.self_context
    assert directive.provide_variables
    assert directive.source == '$remote_addr'
    assert directive.variable == 'some_var'
    assert directive.children
    assert len(directive.children) == 2
    assert [c.src_val for c in directive.children] == ['5.6.7.8', 'default']
    assert [c.dest_val for c in directive.children] == ['d', 'e']


def test_content_by_lua_block_preserves_raw():
    config = r'''
    some {
        content_by_lua_block {
            ngx.say("hi")
        }
    }
    '''

    directive = _get_parsed(config)
    lua_block = directive.some('content_by_lua_block', flat=True)
    assert lua_block is not None
    assert isinstance(lua_block, Block)
    assert lua_block.is_block
    assert getattr(lua_block, 'raw', None) is not None
    assert len(lua_block.raw) == 1
    assert 'ngx.say("hi")' in lua_block.raw[0]


def test_block_str_quotes_args():
    config = '''
if ($http_some = "") {
}
    '''

    directive = _get_parsed(config)
    assert str(directive) == 'if ($http_some = "") {'

    config = '''
map $some_var $some_other_var {
    default "";
}
    '''

    directive = _get_parsed(config)
    assert str(directive.children[0]) == 'default "";'

    config = '''
location ~ "^/a{2}$" {
}
    '''

    directive = _get_parsed(config)
    assert str(directive) == 'location ~ "^/a{2}$" {'

    config = '''
map "$request_method $uri" $some_var {
}
    '''

    directive = _get_parsed(config)
    assert str(directive) == 'map "$request_method $uri" $some_var {'
