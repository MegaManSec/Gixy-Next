import io

import pytest

from gixy.core.config import Config
from gixy.core.manager import Manager


def _reasons(config):
    with Manager(config=Config(plugins=["origins"])) as manager:
        manager.audit("/tmp/inline.conf", io.StringIO(config), is_stdin=True)
        return [issue.reason for plugin in manager.results for issue in plugin.issues]


@pytest.mark.parametrize("guard,reflected", [
    (r"^https://", True),
    (r"^https://.*$", True),
    (r"^https://(www\.)?trusted\.example$", False),
])
def test_only_a_valid_regex_guard_exempts_reflection(guard, reflected):
    reasons = _reasons("""
        http { server {
            if ($http_origin ~* "%s") { add_header Access-Control-Allow-Origin $http_origin; }
        } }
    """ % guard)
    assert any(reason.startswith("Reflecting `$http_origin`") for reason in reasons) == reflected
