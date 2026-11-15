import pytest

import gixy
from gixy.parser.nginx_parser import NginxParser
from gixy.plugins.return_bypasses_allow_deny import return_bypasses_allow_deny


def _issues(config):
    root = NginxParser(cwd="", allow_includes=False).parse_string(config)
    plugin = return_bypasses_allow_deny({})
    for name in return_bypasses_allow_deny.directives:
        for directive in root.find_recursive(name):
            plugin.audit(directive)
    return plugin.issues


@pytest.mark.parametrize("body,severity", [
    ("return 200 hi;", gixy.severity.HIGH),
    ("return 404 hi;", gixy.severity.HIGH),
    ("return 301 https://$host$request_uri;", gixy.severity.LOW),
    ("return 302 /login;", gixy.severity.LOW),
    ("return https://example.com/;", gixy.severity.LOW),
    ("rewrite ^ /new permanent;", gixy.severity.LOW),
    ("rewrite ^ https://example.com/;", gixy.severity.LOW),
    ("return 204;", gixy.severity.LOW),
    ("return 200 '';", gixy.severity.LOW),
    ("if ($request_method = OPTIONS) { return 204; } return 302 /login;", gixy.severity.LOW),
    ("if ($arg_a) { return 301 /new; } return 200 hi;", gixy.severity.HIGH),
])
def test_severity(body, severity):
    issues = _issues("location /a {{ allow 127.0.0.1; deny all; {0} }}".format(body))
    assert [issue.severity for issue in issues] == [severity]


def test_access_rules_and_auth_in_one_scope_report_once():
    issues = _issues(
        'location /a { allow 127.0.0.1; deny all; auth_basic "x"; '
        "auth_basic_user_file /etc/htpasswd; return 200 hi; }"
    )
    assert len(issues) == 1
    assert issues[0].reason.startswith("`allow`/`deny` and `auth_basic` cannot restrict")


@pytest.mark.parametrize("config,count", [
    ('http { server { location /a { auth_basic "x"; return 200 hi; } } }', 0),
    ('http { auth_basic_user_file /etc/htpasswd; server { location /a { auth_basic "x"; return 200 hi; } } }', 1),
    ('http { server { auth_basic "x"; location /a { auth_basic_user_file /etc/htpasswd; return 200 hi; } '
     "location /b { return 200 hi; } } }", 1),
    ('server { location /a { auth_basic "x"; return 200 hi; } }', 1),
])
def test_auth_basic_needs_user_file(config, count):
    assert len(_issues(config)) == count


@pytest.mark.parametrize("auth,code,count", [
    ('auth_basic "x"; auth_basic_user_file /etc/htpasswd;', "401", 0),
    ('auth_basic "x"; auth_basic_user_file /etc/htpasswd;', "403", 1),
    ("auth_jwt api;", "401", 0),
    ("auth_request /auth;", "401", 0),
    ("auth_request /auth;", "403", 0),
    ("auth_oidc idp;", "401", 1),
])
def test_auth_denial_status(auth, code, count):
    config = "server {{ error_page 401 403 /e.html; location /a {{ {0} return {1}; }} }}".format(auth, code)
    assert len(_issues(config)) == count
