import io

import pytest

from gixy.core.config import Config
from gixy.core.manager import Manager
from gixy.plugins.ssrf import _is_open_suffix_name


def test_back_reference_in_server_name_is_not_an_error():
    config = (
        "http { resolver 127.0.0.53; "
        "server { listen 80 default_server; return 444; } "
        "server { listen 80; server_name ~^(\\w)\\1\\.example\\.com$; location / { proxy_pass http://$host; } } }"
    )
    with Manager(config=Config(plugins=["ssrf"])) as manager:
        manager.audit("/tmp/inline.conf", io.StringIO(config), is_stdin=True)
        assert manager.errors == []
        assert not [issue for plugin in manager.results for issue in plugin.issues]


@pytest.mark.parametrize("name,is_open", [
    ("example.*", True),
    (r"~^api\.", True),
    (r"~^api\.(.+)$", True),
    (r"~^app\.example\.(.+)$", True),
    (r"~^(.+)\.com$", True),
    (r"~^api.example.com$", True),
    (r"~example\.com$", True),
    ("*.example.com", False),
    (r"~^(.+)\.example\.com$", False),
    (r"~^api\.(.+)\.example\.com$", False),
    (r"~^api\.example\.(com|net)$", False),
    (r"~^api\.[a-z]+$", False),
    (r"~^(www\.)?example\.com\.?$", False),
])
def test_open_suffix_name(name, is_open):
    assert _is_open_suffix_name(name) is is_open
