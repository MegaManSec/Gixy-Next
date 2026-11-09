import io

import pytest

from gixy.core.config import Config
from gixy.core.manager import Manager


def _reasons(config):
    with Manager(config=Config(plugins=["origins"])) as manager:
        manager.audit("/tmp/inline.conf", io.StringIO(config), is_stdin=True)
        return [issue.reason for plugin in manager.results for issue in plugin.issues]


def _reflected(config):
    return any(reason.startswith("Reflecting `$http_origin`") for reason in _reasons(config))


@pytest.mark.parametrize("guard,reflected", [
    (r"^https://", True),
    (r"^https://.*$", True),
    (r"^https://(www\.)?trusted\.example$", False),
])
def test_only_a_valid_regex_guard_exempts_reflection(guard, reflected):
    assert _reflected("""
        http { server {
            if ($http_origin ~* "%s") { add_header Access-Control-Allow-Origin $http_origin; }
        } }
    """ % guard) == reflected


@pytest.mark.parametrize("body,reflected", [
    ('more_set_headers "Access-Control-Allow-Origin: $http_origin";', True),
    ('more_set_headers -s 404 "access-control-allow-origin: $http_origin" "Vary: Origin";', True),
    ('more_set_headers "Access-Control-Allow-Origin: https://trusted.example";', False),
    ("set $tmp $http_origin; set $cors $tmp; add_header Access-Control-Allow-Origin $cors;", True),
    ("set $a $http_origin; set $b $a; set $c ${b}; more_set_headers 'Access-Control-Allow-Origin: $c';", True),
    ("set $tmp https://$http_origin; set $cors $tmp; add_header Access-Control-Allow-Origin $cors;", False),
    ("set $a $b; set $b $a; add_header Access-Control-Allow-Origin $a;", False),
    ("set $cors $cors; add_header Access-Control-Allow-Origin $cors;", False),
    (
        'if ($http_origin ~ "^https://trusted\\.example$") { set $cors $http_origin; }'
        " add_header Access-Control-Allow-Origin $cors;",
        False,
    ),
    (
        'if ($http_origin ~ "^https://") { set $cors $http_origin; }'
        " add_header Access-Control-Allow-Origin $cors;",
        True,
    ),
    (
        'if ($http_origin ~ "^https://trusted\\.example$") { set $tmp $http_origin; }'
        " set $cors $tmp; add_header Access-Control-Allow-Origin $cors;",
        False,
    ),
])
def test_reflection_through_variable_chains(body, reflected):
    assert _reflected("http { server { %s } }" % body) == reflected


@pytest.mark.parametrize("default,reflected", [
    ("$tmp", True),
    ("$other", False),
    ('""', False),
])
def test_map_default_hop_is_followed(default, reflected):
    assert _reflected("""
        http {
            map $http_origin $cors { default %s; https://trusted.example ""; }
            server { set $tmp $http_origin; add_header Access-Control-Allow-Origin $cors; }
        }
    """ % default) == reflected


def test_map_default_hop_requires_an_origin_keyed_map():
    assert not _reflected("""
        http {
            map $http_origin $allowed { default 0; ~^https://trusted\\.example$ 1; }
            map $allowed $cors { default $tmp; 0 ""; }
            server { set $tmp $http_origin; add_header Access-Control-Allow-Origin $cors; }
        }
    """)


def test_chain_report_lists_every_hop():
    config = (
        "http { server {\n"
        "set $tmp $http_origin;\n"
        "set $cors $tmp;\n"
        "add_header Access-Control-Allow-Origin $cors;\n"
        "} }\n"
    )
    with Manager(config=Config(plugins=["origins"])) as manager:
        manager.audit("/tmp/inline.conf", io.StringIO(config), is_stdin=True)
        issues = [issue for plugin in manager.results for issue in plugin.issues]
    assert len(issues) == 1
    assert [str(d) for d in issues[0].directives] == [
        "set $tmp $http_origin;",
        "set $cors $tmp;",
        "add_header Access-Control-Allow-Origin $cors;",
    ]
