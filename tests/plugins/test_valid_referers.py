import io

import pytest

from gixy.core.config import Config
from gixy.core.manager import Manager


def _severities(config):
    with Manager(config=Config(plugins=["valid_referers"])) as manager:
        manager.audit("/tmp/inline.conf", io.StringIO(config), is_stdin=True)
        return sorted(issue.severity or plugin.severity for plugin in manager.results for issue in plugin.issues)


@pytest.mark.parametrize("args,severities", [
    ("none example.com", ["HIGH"]),
    ("none blocked example.com", ["HIGH"]),
    ("blocked example.com", ["LOW"]),
    (r"~\.example\.com", ["MEDIUM"]),
    ("example.*", ["MEDIUM"]),
    (r"none ~\.example\.com", ["HIGH", "MEDIUM"]),
    (r"~\.example\.com example.* ~^www\.example\.org", ["MEDIUM"]),
])
def test_severity(args, severities):
    assert _severities("valid_referers %s;" % args) == severities
