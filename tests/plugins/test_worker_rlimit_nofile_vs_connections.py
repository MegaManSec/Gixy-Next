import io

import pytest

from gixy.core.config import Config
from gixy.core.manager import Manager


def _severities(config):
    with Manager(config=Config(plugins=["worker_rlimit_nofile_vs_connections"])) as manager:
        manager.audit("/tmp/inline.conf", io.StringIO(config), is_stdin=True)
        assert manager.errors == []
        return [issue.severity or plugin.severity for plugin in manager.results for issue in plugin.issues]


@pytest.mark.parametrize("config,severity", [
    ("events { worker_connections 1024; }", "LOW"),
    ("worker_rlimit_nofile 1024; events { worker_connections 1024; }", "MEDIUM"),
    ("worker_rlimit_nofile 800; events { } http { }", "MEDIUM"),
])
def test_severity(config, severity):
    assert _severities(config) == [severity]
