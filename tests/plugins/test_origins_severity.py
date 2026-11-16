import io

from gixy.core.config import Config
from gixy.core.manager import Manager


def test_referrer_typo_is_low():
    config = 'http { server { if ($http_referrer !~ "^https://example\\.com/") { return 403; } } }'
    with Manager(config=Config(plugins=["origins"])) as manager:
        manager.audit("/tmp/inline.conf", io.StringIO(config), is_stdin=True)
        issues = [issue for plugin in manager.results for issue in plugin.issues]
    assert [issue.severity for issue in issues] == ["LOW"]
