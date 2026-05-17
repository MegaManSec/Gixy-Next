import pytest

from gixy.core import builtin_variables as builtins
from gixy.core.context import get_context, purge_context, push_context
from gixy.core.regexp import Regexp
from gixy.core.variable import Variable
from gixy.directives.block import Root


def setup_function():
    push_context(Root())
    builtins.clear_custom_variables()


def teardown_function():
    purge_context()
    builtins.clear_custom_variables()


def test_literal():
    var = Variable(name='simple', value='$uri', have_script=False)
    assert not var.depends
    assert not var.regexp
    assert var.value == '$uri'

    assert not var.can_startswith('$')
    assert not var.can_contain('i')
    assert var.must_contain('$')
    assert var.must_contain('u')
    assert not var.must_contain('a')
    assert var.must_startswith('$')
    assert not var.must_startswith('u')


def test_regexp():
    var = Variable(name='simple', value=Regexp('^/.*'))
    assert not var.depends
    assert var.regexp

    assert var.can_startswith('/')
    assert not var.can_startswith('a')
    assert var.can_contain('a')
    assert not var.can_contain('\n')
    assert var.must_contain('/')
    assert not var.must_contain('a')
    assert var.must_startswith('/')
    assert not var.must_startswith('a')


def test_script():
    get_context().add_var('foo', Variable(name='foo', value=Regexp('.*')))
    var = Variable(name='simple', value='/$foo')
    assert var.depends
    assert not var.regexp

    assert not var.can_startswith('/')
    assert not var.can_startswith('a')
    assert var.can_contain('/')
    assert var.can_contain('a')
    assert not var.can_contain('\n')
    assert var.must_contain('/')
    assert not var.must_contain('a')
    assert var.must_startswith('/')
    assert not var.must_startswith('a')


def test_regexp_boundary():
    var = Variable(name='simple', value=Regexp('.*'), boundary=Regexp('/[a-z]', strict=True))
    assert not var.depends
    assert var.regexp

    assert var.can_startswith('/')
    assert not var.can_startswith('a')
    assert not var.can_contain('/')
    assert var.can_contain('a')
    assert not var.can_contain('0')
    assert not var.can_contain('\n')
    assert var.must_contain('/')
    assert not var.must_contain('a')
    assert var.must_startswith('/')
    assert not var.must_startswith('a')


def test_script_boundary():
    get_context().add_var('foo', Variable(name='foo', value=Regexp('.*'), boundary=Regexp('[a-z]', strict=True)))
    var = Variable(name='simple', value='/$foo', boundary=Regexp('[/a-z0-9]', strict=True))
    assert var.depends
    assert not var.regexp

    assert not var.can_startswith('/')
    assert not var.can_startswith('a')
    assert not var.can_contain('/')
    assert var.can_contain('a')
    assert not var.can_contain('\n')
    assert not var.can_contain('0')
    assert var.must_contain('/')
    assert not var.must_contain('a')
    assert var.must_startswith('/')
    assert not var.must_startswith('a')


def test_custom_variable_dropin_literal_and_regex(tmp_path):
    # Create drop-in files
    d = tmp_path / "vars"
    d.mkdir()
    # Literal value
    (d / "nginx-module-foo.cfg").write_text("foo_host \"example.com\"\n")
    # Regex value with raw marker
    (d / "nginx-module-bar.cfg").write_text("foo_uri  r'/[^\\s]*',\n")

    builtins.load_custom_variables_from_dirs([str(d)])

    # foo_host is treated as non-user-controlled: cannot contain newline
    v1 = builtins.builtin_var("foo_host")
    assert v1 is not None
    assert not v1.can_contain("\n")
    assert v1.must_contain(".")

    # foo_uri is regex: must start with '/'; cannot contain newlines
    v2 = builtins.builtin_var("foo_uri")
    assert v2 is not None
    assert v2.must_startswith("/")
    assert not v2.can_contain("\n")
    assert not v2.must_contain(".")


def test_custom_variable_dropin_more_cases(tmp_path):
    builtins.clear_custom_variables()

    d = tmp_path / "vars"
    d.mkdir()

    # literal + regex metachar
    (d / "a.cfg").write_text('lit_plus "a+b"\n')      # literal
    (d / "b.cfg").write_text("rx_plus r'a+b'\n")      # regex

    # unquoted is regex (compat)
    (d / "c.cfg").write_text("compat_dot example.com\n")

    # empty and null, plus separators and trailing comma
    (d / "d.cfg").write_text('empty = ""\nnone: null,\n')

    builtins.load_custom_variables_from_dirs([str(d)])

    v = builtins.builtin_var("lit_plus")
    assert v is not None
    assert v.must_contain("+")          # literal plus required
    assert not v.can_contain("\n")

    v = builtins.builtin_var("rx_plus")
    assert v is not None
    assert v.must_contain("b")
    assert not v.must_contain("+")      # plus is not literal here (usually)

    v = builtins.builtin_var("compat_dot")
    assert v is not None
    assert not v.must_contain(".")      # '.' is wildcard in regex example.com

    v = builtins.builtin_var("empty")
    assert v is not None
    assert not v.can_contain("\n")      # depending on how Regexp("") behaves in your code,
                                        # you may need to assert it becomes "builtin" instead

    v = builtins.builtin_var("none")
    assert v is not None


@pytest.mark.parametrize(
    "name",
    [
        "http3",
        "connection_time",
        "request_port",
        "is_request_port",
        "limit_conn_status",
        "limit_req_status",
        "proxy_protocol_addr",
        "proxy_protocol_server_addr",
        "proxy_protocol_server_port",
        "proxy_protocol_tlv_authority",
        "realip_remote_addr",
        "sent_trailer_grpc_status",
        "upstream_trailer_grpc_status",
    ],
)
def test_modern_nginx_variables_recognized(name):
    assert builtins.is_builtin(name), f"{name!r} should be a recognized builtin"
