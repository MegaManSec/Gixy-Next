import io

import pytest

from gixy.core.config import Config
from gixy.core.manager import Manager


def _severities(config):
    with Manager(config=Config(plugins=["allow_without_deny"])) as manager:
        manager.audit("/tmp/inline.conf", io.StringIO(config), is_stdin=True)
        assert manager.errors == []
        return sorted(issue.severity or plugin.severity for plugin in manager.results for issue in plugin.issues)


@pytest.mark.parametrize("config,severities", [
    ("location / { allow 10.0.0.0/8; deny 10.0.0.0/8; }", ["HIGH"]),
    ("location / { allow 10.0.0.0/8; deny 10.1.2.3; }", ["HIGH"]),
    ("location / { allow 10.1.1.1; deny all; allow 10.0.0.0/8; }", ["MEDIUM"]),
    ("location / { allow 127.0.0.1; deny all; allow 10.0.0.0/8; deny 10.0.0.0/8; }", ["MEDIUM"]),
    ("location / { allow 192.0.2.5; deny all; deny all; }", []),
    ("location / { allow 10.1.1.1; deny all; deny 10.0.0.0/8; }", []),
    ("location / { allow 10.0.0.0/8; deny all; allow 10.1.0.0/16; }", []),
])
def test_severity(config, severities):
    assert _severities(config) == severities
