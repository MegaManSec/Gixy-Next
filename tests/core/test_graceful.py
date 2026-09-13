"""Graceful handling of invalid config: malformed input vs. internal errors.

Gixy is a security linter, not a syntax checker, but it must not crash with a
raw traceback when handed input nginx itself would reject. These tests pin the
three crash surfaces (parse-time, the special include path, audit-time) and the
malformed/internal taxonomy that the CLI maps onto exit codes 2 and 3.
"""

import io

import pytest

from gixy.core.context import purge_context
from gixy.core.diagnostics import Diagnostic
from gixy.core.exceptions import InvalidConfiguration, MalformedDirective
from gixy.core.manager import Manager
from gixy.core.plugins_manager import PluginsManager
from gixy.directives.block import Root
from gixy.directives.directive import Directive
from gixy.parser.nginx_parser import NginxParser


def teardown_function():
    purge_context()


def _parse(config):
    parser = NginxParser(cwd="", allow_includes=False)
    root = parser.parse_string(config)
    return parser, root


def _audit(config):
    m = Manager()
    m.audit("/tmp/inline.conf", io.StringIO(config), is_stdin=True)
    return m


def _kinds(diagnostics):
    return [d.kind for d in diagnostics]


def _names(root):
    return [c.name for c in root.children]


# ---------------------------------------------------------------------------
# Diagnostic
# ---------------------------------------------------------------------------

def test_diagnostic_rejects_unknown_kind():
    with pytest.raises(ValueError):
        Diagnostic("catastrophe", "parse", "boom")


def test_diagnostic_defaults_are_optional():
    d = Diagnostic("malformed", "parse", "boom")
    assert d.directive is None
    assert d.line is None
    assert d.file is None
    assert d.plugin is None
    assert d.traceback is None


# ---------------------------------------------------------------------------
# Directive.arg
# ---------------------------------------------------------------------------

def test_arg_returns_positional_argument():
    d = Directive("proxy_pass", ["http://backend"])
    assert d.arg(0) == "http://backend"


def test_arg_raises_malformed_directive_when_missing():
    d = Directive("proxy_pass", [])
    with pytest.raises(MalformedDirective) as exc:
        d.arg(0)
    assert exc.value.directive is d
    assert "proxy_pass" in str(exc.value)


def test_malformed_directive_is_an_invalid_configuration():
    assert issubclass(MalformedDirective, InvalidConfiguration)


def test_arg_default_tolerates_missing_argument():
    d = Directive("proxy_pass", [])
    assert d.arg(0, "fallback") == "fallback"


def test_arg_default_of_none_is_honoured():
    """An explicit default of None must not be mistaken for "no default"."""
    d = Directive("proxy_pass", [])
    assert d.arg(0, None) is None


def test_int_arg_parses_a_number():
    assert Directive("worker_connections", ["1024"]).int_arg(0) == 1024


def test_int_arg_rejects_a_non_numeric_value():
    d = Directive("worker_connections", ["abc"])
    with pytest.raises(MalformedDirective) as exc:
        d.int_arg(0)
    assert "expects a number" in str(exc.value)


def test_int_arg_rejects_a_missing_value():
    with pytest.raises(MalformedDirective):
        Directive("worker_connections", []).int_arg(0)


def test_int_arg_default_is_returned_verbatim():
    assert Directive("worker_connections", []).int_arg(0, None) is None


# ---------------------------------------------------------------------------
# Parse-time: a directive whose construction fails
# ---------------------------------------------------------------------------

def test_missing_argument_is_recorded_and_skipped():
    parser, root = _parse("add_header;")
    assert _kinds(parser.malformed) == ["malformed"]
    rec = parser.malformed[0]
    assert rec.phase == "parse"
    assert rec.directive == "add_header"
    assert rec.line == 1
    assert "add_header" not in _names(root)


def test_malformed_directive_does_not_stop_the_rest_of_the_file():
    parser, root = _parse("add_header;\nserver_tokens off;")
    assert len(parser.malformed) == 1
    assert "server_tokens" in _names(root)


def test_bare_include_is_recorded_not_crashed():
    """`include;` is resolved before the generic construction path, so it needs
    its own guard."""
    parser, _ = _parse("include;")
    assert _kinds(parser.malformed) == ["malformed"]
    assert parser.malformed[0].directive == "include"


def test_unparsable_config_still_raises_invalid_configuration():
    """A file-level syntax error aborts parsing; the CLI reports it, not the
    parser's diagnostic list."""
    with pytest.raises(InvalidConfiguration):
        _parse("http { server { listen 80;")


def test_unexpected_construction_error_is_recorded_as_internal(monkeypatch):
    parser = NginxParser(cwd="", allow_includes=False)

    def boom(*args, **kwargs):
        raise RuntimeError("kaboom")

    monkeypatch.setattr(parser, "directive_factory", boom)
    parser.parse_string("server_tokens off;")

    assert _kinds(parser.malformed) == ["internal"]
    rec = parser.malformed[0]
    assert "RuntimeError: kaboom" in rec.message
    assert "kaboom" in rec.traceback


def test_simple_directive_used_as_a_block_is_malformed():
    parser, root = _parse("add_header { }")
    assert _kinds(parser.malformed) == ["malformed"]
    assert "add_header" not in _names(root)


def test_block_used_as_a_simple_directive_is_malformed():
    for name in ("http", "if", "location", "geo", "map"):
        parser, root = _parse("{0};".format(name))
        assert _kinds(parser.malformed) == ["malformed"], name
        assert name not in _names(root), name


def test_server_stays_a_valid_simple_directive_in_upstream():
    """`server host:port;` inside `upstream` must survive the shape check."""
    parser, root = _parse("http { upstream backend { server example.com; } }")
    assert parser.malformed == []
    upstream = root.children[0].children[0]
    assert [c.name for c in upstream.children] == ["server"]


def test_include_stays_a_valid_simple_directive():
    parser, _ = _parse("include /etc/nginx/conf.d/*.conf;")
    assert parser.malformed == []


def test_malformed_if_condition_is_not_a_bare_exception():
    parser, root = _parse("if ($foo $bar $baz $qux) { }")
    assert _kinds(parser.malformed) == ["malformed"]
    assert "if" not in _names(root)


# ---------------------------------------------------------------------------
# Audit-time: a plugin that raises
# ---------------------------------------------------------------------------

class _Boom(Exception):
    pass


class _FakePlugin(object):
    directives = []
    supports_full_config = True

    def __init__(self, exc):
        self.exc = exc
        self.audited = 0

    @property
    def name(self):
        return "fake_plugin"

    def audit(self, directive):
        self.audited += 1
        raise self.exc

    def post_audit(self, root):
        raise self.exc


def _run_audit_with(plugin, directive):
    manager = PluginsManager()
    manager._plugins = [plugin]
    manager.audit(directive)
    return manager.audit_errors


def test_plugin_exception_is_recorded_as_internal():
    directive = Directive("proxy_pass", ["http://backend"])
    directive.line = 7
    errors = _run_audit_with(_FakePlugin(_Boom("kaboom")), directive)

    assert _kinds(errors) == ["internal"]
    rec = errors[0]
    assert rec.phase == "audit"
    assert rec.plugin == "fake_plugin"
    assert rec.directive == "proxy_pass"
    assert rec.line == 7
    assert "_Boom: kaboom" in rec.message
    assert "kaboom" in rec.traceback


def test_plugin_malformed_directive_is_recorded_as_malformed():
    directive = Directive("proxy_pass", [])
    errors = _run_audit_with(_FakePlugin(MalformedDirective("missing arg")), directive)

    assert _kinds(errors) == ["malformed"]
    assert errors[0].traceback is None


def test_plugin_invalid_configuration_is_recorded_as_malformed():
    directive = Directive("proxy_pass", [])
    errors = _run_audit_with(_FakePlugin(InvalidConfiguration("nope")), directive)
    assert _kinds(errors) == ["malformed"]


def test_one_failing_plugin_does_not_stop_the_others():
    directive = Directive("proxy_pass", ["http://backend"])
    failing = _FakePlugin(_Boom("kaboom"))
    surviving = _FakePlugin(_Boom("also kaboom"))

    manager = PluginsManager()
    manager._plugins = [failing, surviving]
    manager.audit(directive)

    assert failing.audited == 1
    assert surviving.audited == 1
    assert len(manager.audit_errors) == 2


def test_post_audit_failure_is_isolated():
    root = Root()
    root.append(Directive("http", []))

    manager = PluginsManager()
    manager._plugins = [_FakePlugin(_Boom("kaboom"))]
    manager.post_audit(root)

    assert _kinds(manager.audit_errors) == ["internal"]
    assert manager.audit_errors[0].directive is None


# ---------------------------------------------------------------------------
# Manager.errors aggregates both phases
# ---------------------------------------------------------------------------

def test_manager_errors_include_parse_diagnostics():
    m = _audit("http { server { location / { add_header; } } }")
    assert _kinds(m.errors) == ["malformed"]


def test_manager_errors_include_audit_diagnostics():
    m = _audit("http { server { location / { proxy_pass ; } } }")
    assert m.errors
    assert all(d.kind == "malformed" for d in m.errors)
    assert any(d.phase == "audit" for d in m.errors)


def test_manager_errors_empty_for_valid_config():
    m = _audit("http { server { listen 80; } }")
    assert m.errors == []


def test_manager_audit_completes_despite_malformed_directive():
    m = _audit(
        "http { server { location / {\n"
        "  add_header;\n"
        "  proxy_pass http://$http_host;\n"
        "} } }"
    )
    assert any(type(p).__name__ == "ssrf" for p in m.results)


def test_non_numeric_value_is_malformed_not_an_internal_error():
    m = _audit("events { worker_connections abc; }\nworker_rlimit_nofile 100;\n")
    assert _kinds(m.errors) == ["malformed"]
    assert "expects a number" in m.errors[0].message


# ---------------------------------------------------------------------------
# map/geo entries are not directives
# ---------------------------------------------------------------------------

def test_map_entry_key_is_not_dispatched_as_a_directive():
    """A map key is arbitrary text; it must not be audited as the directive it
    happens to be spelled like."""
    m = _audit("http { map $host $x { proxy_pass http://$http_host; } }")
    assert [type(p).__name__ for p in m.results if type(p).__name__ == "ssrf"] == []
    assert m.errors == []


def test_real_proxy_pass_is_still_audited():
    m = _audit("http { server { location / { proxy_pass http://$http_host; } } }")
    assert any(type(p).__name__ == "ssrf" for p in m.results)


def test_map_block_itself_is_still_audited():
    m = _audit("http { map $host $x { a 1; b 2; } }")
    assert any(type(p).__name__ == "hash_without_default" for p in m.results)


# ---------------------------------------------------------------------------
# Sweep: no directive with too few arguments may escape as a traceback
# ---------------------------------------------------------------------------

_SWEEP_DIRECTIVES = [
    "add_header",
    "alias",
    "auth_request",
    "auth_request_set",
    "fastcgi_pass",
    "geo",
    "grpc_pass",
    "include",
    "internal",
    "map",
    "proxy_pass",
    "proxy_set_header",
    "return",
    "rewrite",
    "root",
    "scgi_pass",
    "server_name",
    "set",
    "set_by_lua",
    "ssl_stapling_responder",
    "try_files",
    "uwsgi_pass",
    "valid_referers",
    "worker_connections",
    "worker_processes",
    "worker_rlimit_nofile",
]


@pytest.mark.parametrize("name", _SWEEP_DIRECTIVES)
def test_directive_without_arguments_never_escapes(name):
    config = "http {{ server {{ location / {{ {0}; }} }} }}".format(name)
    m = _audit(config)
    assert all(d.kind == "malformed" for d in m.errors), [
        (d.kind, d.message) for d in m.errors
    ]


@pytest.mark.parametrize("name", _SWEEP_DIRECTIVES)
def test_block_form_without_arguments_never_escapes(name):
    config = "http {{ server {{ {0} {{ }} }} }}".format(name)
    m = _audit(config)
    assert all(d.kind == "malformed" for d in m.errors), [
        (d.kind, d.message) for d in m.errors
    ]
