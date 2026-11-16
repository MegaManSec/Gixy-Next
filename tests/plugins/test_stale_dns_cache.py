import io

from gixy.core.config import Config
from gixy.core.manager import Manager


def _issues(config):
    with Manager(config=Config(plugins=["stale_dns_cache"])) as manager:
        manager.audit("/tmp/inline.conf", io.StringIO(config), is_stdin=True)
    assert not manager.errors
    return [issue for plugin in manager.results for issue in plugin.issues]


def test_chained_conditional_assignments_are_audited_in_linear_time():
    branches = " ".join('if ($arg_%d) { set $value "${value}%d"; }' % (i, i) for i in range(64))
    issues = _issues('server { set $value ""; %s location / { proxy_pass http://$value; } }' % branches)
    assert len(issues) == 1
