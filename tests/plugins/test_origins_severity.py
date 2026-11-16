import io
from pathlib import Path

import pytest

from gixy.core.config import Config
from gixy.core.manager import Manager

FIXTURES = Path(__file__).parent / "simply" / "origins"


def _severities(config):
    with Manager(config=Config(plugins=["origins"])) as manager:
        manager.audit("/tmp/inline.conf", io.StringIO(config), is_stdin=True)
        return [issue.severity for plugin in manager.results for issue in plugin.issues]


def test_referrer_typo_is_low():
    config = 'http { server { if ($http_referrer !~ "^https://example\\.com/") { return 403; } } }'
    assert _severities(config) == ["LOW"]


@pytest.mark.parametrize("fixture,severity", [
    ("reflect_add_header.conf", "MEDIUM"),
    ("reflect_more_set_headers.conf", "MEDIUM"),
    ("reflect_set_chain.conf", "MEDIUM"),
    ("reflect_map_preflight.conf", "MEDIUM"),
    ("reflect_in_if_credentials_outside.conf", "MEDIUM"),
    ("reflect_server_credentials_not_inherited.conf", "MEDIUM"),
    ("reflect_credentials.conf", "HIGH"),
    ("reflect_more_set_headers_credentials.conf", "HIGH"),
    ("reflect_server_credentials_merged.conf", "HIGH"),
    ("reflect_server_more_credentials.conf", "HIGH"),
])
def test_reflection_is_high_only_with_credentials(fixture, severity):
    assert _severities((FIXTURES / fixture).read_text()) == [severity]


@pytest.mark.parametrize("value,severity", [
    ("true", "HIGH"),
    ('"true"', "HIGH"),
    ("True", "MEDIUM"),
    ("false", "MEDIUM"),
])
def test_credentials_header_must_be_exactly_true(value, severity):
    config = (
        "http { server { add_header Access-Control-Allow-Origin $http_origin;"
        " add_header Access-Control-Allow-Credentials %s; } }" % value
    )
    assert _severities(config) == [severity]
