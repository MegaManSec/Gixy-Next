import io

import pytest

from gixy.core.config import Config
from gixy.core.manager import Manager
from gixy.plugins.ssrf import _is_open_suffix_name


def _issues(config):
    with Manager(config=Config(plugins=["ssrf"])) as manager:
        manager.audit("/tmp/inline.conf", io.StringIO(config), is_stdin=True)
    assert not manager.errors
    return [issue for plugin in manager.results for issue in plugin.issues]


def test_back_reference_in_server_name_is_not_an_error():
    config = (
        "http { resolver 127.0.0.53; "
        "server { listen 80 default_server; return 444; } "
        "server { listen 80; server_name ~^(\\w)\\1\\.example\\.com$; location / { proxy_pass http://$host; } } }"
    )
    assert not _issues(config)


@pytest.mark.parametrize("start,count", [("a", 0), ("$arg_a", 1)])
@pytest.mark.timeout(60)
def test_chained_conditional_assignments_are_audited_in_linear_time(start, count):
    branches = " ".join('if ($arg_%d) { set $value "${value}%d"; }' % (i, i) for i in range(64))
    config = "http { server { listen 80; set $value %s; %s location / { proxy_pass http://$value; } } }" % (
        start, branches,
    )
    assert len(_issues(config)) == count


@pytest.mark.parametrize("name,is_open", [
    ("example.*", True),
    (r"~^api\.", True),
    (r"~^api\.(.+)$", True),
    (r"~^app\.example\.(.+)$", True),
    (r"~^(.+)\.com$", True),
    (r"~^api.example.com$", True),
    (r"~example\.com$", True),
    (r"~^api\.[a-z]+$", True),
    (r"~^(.+)\.co\.uk$", True),
    (r"~^[a-z0-9-]+\.co\.uk$", True),
    (r"~^(.+)\.github\.io$", True),
    ("*.example.com", False),
    (r"~^(.+)\.example\.com$", False),
    (r"~^api\.(.+)\.example\.com$", False),
    (r"~^api\.example\.(com|net)$", False),
    (r"~^(.+)\.example\.co\.uk$", False),
    (r"~^(www\.)?example\.com\.?$", False),
])
def test_open_suffix_name(name, is_open):
    assert _is_open_suffix_name(name) is is_open
