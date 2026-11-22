import io

import pytest

from gixy.core.config import Config
from gixy.core.manager import Manager


def _issues(config):
    with Manager(config=Config(plugins=["stale_dns_cache"])) as manager:
        manager.audit("/tmp/inline.conf", io.StringIO(config), is_stdin=True)
    assert not manager.errors
    return [issue for plugin in manager.results for issue in plugin.issues]


@pytest.mark.timeout(60)
def test_chained_conditional_assignments_are_audited_in_linear_time():
    branches = " ".join('if ($arg_%d) { set $value "${value}%d"; }' % (i, i) for i in range(64))
    issues = _issues('server { set $value ""; %s location / { proxy_pass http://$value; } }' % branches)
    assert len(issues) == 1


def _shared(config):
    return [
        (issue.severity, issue.directives[0].args[0], issue.directives[1].args[0])
        for issue in _issues(config)
        if "names the same host and port" in issue.reason
    ]


STATIC = "location /static/ { %s }"


@pytest.mark.parametrize("variable,static,expected", [
    ("set $h api.example.com; proxy_pass http://$h:8080;", "proxy_pass http://api.example.com:8080;",
     ("MEDIUM", "http://$h:8080", "http://api.example.com:8080")),
    ("set $h api.example.com; proxy_pass http://$h;", "proxy_pass http://API.example.com;",
     ("MEDIUM", "http://$h", "http://API.example.com")),
    ("proxy_pass http://api.example.com$request_uri;", "proxy_pass http://api.example.com;",
     ("MEDIUM", "http://api.example.com$request_uri", "http://api.example.com")),
    ("set $h backend; proxy_pass http://$h:9000;", "fastcgi_pass backend:9000;",
     ("LOW", "http://$h:9000", "backend:9000")),
])
def test_variable_target_reuses_group_of_static_target(variable, static, expected):
    config = "http { resolver 127.0.0.1; server { location /var/ { %s } %s } }" % (variable, STATIC % static)
    assert _shared(config) == [expected]


@pytest.mark.parametrize("variable,static", [
    ("set $h api.example.com; proxy_pass https://$h;", "proxy_pass http://api.example.com;"),
    ("set $h api.example.com; proxy_pass http://$h:8081;", "proxy_pass http://api.example.com:8080;"),
    ("set $h api.example.com; proxy_pass $scheme://$h;", "proxy_pass http://api.example.com;"),
    ("proxy_pass http://api.example.com$http_x_port;", "proxy_pass http://api.example.com;"),
    ("proxy_pass http://api.example.com:80$http_x_port;", "proxy_pass http://api.example.com;"),
])
def test_variable_target_on_another_port_uses_resolver(variable, static):
    config = "http { resolver 127.0.0.1; server { location /var/ { %s } %s } }" % (variable, STATIC % static)
    assert _shared(config) == []


def test_shared_group_needs_no_resolver():
    reasons = [issue.reason for issue in _issues(
        "http { server { location /var/ { set $h api.example.com; proxy_pass http://$h:8080; } %s } }"
        % (STATIC % "proxy_pass http://api.example.com:8080;")
    )]
    assert len(reasons) == 2 and not any("resolver" in reason for reason in reasons)


def test_map_values_are_matched_with_the_port_that_follows():
    issues = _issues(
        "http { map $arg_x $h { default api.example.com; 1 other.example.com; } "
        "server { location /var/ { proxy_pass http://$h:8080; } %s %s } }"
        % (STATIC % "proxy_pass http://api.example.com:8080;", "location /b/ { proxy_pass http://other.example.com; }")
    )
    shared = [issue.directives[1].args[0] for issue in issues if "names the same host and port" in issue.reason]
    assert shared == ["http://api.example.com:8080"]
    assert any("no `resolver`" in issue.reason for issue in issues)


def test_set_value_cut_short_is_not_matched_on_the_default_port():
    issues = _issues(
        "http { resolver 127.0.0.1; map $arg_x $a { default a.example.com; 1 c.example.com; } "
        'server { location /var/ { set $h "${a}:8080"; proxy_pass http://$h; } %s } }'
        % (STATIC % "proxy_pass http://a.example.com;")
    )
    assert not any("names the same host and port" in issue.reason for issue in issues)


def test_stream_and_http_groups_are_separate():
    config = (
        "http { resolver 127.0.0.1; server { location / { set $h api.example.com; proxy_pass http://$h:9000; } } } "
        "stream { server { listen 1; proxy_pass api.example.com:9000; } }"
    )
    assert _shared(config) == []


def test_map_and_geo_keys_named_like_a_pass_directive_create_no_group():
    config = (
        "http { resolver 127.0.0.1; map $x $y { proxy_pass api.example.com:8080; } "
        "geo $g { proxy_pass api.example.com:8080; } "
        "server { location / { set $h api.example.com; proxy_pass http://$h:8080; } } }"
    )
    assert _shared(config) == []
