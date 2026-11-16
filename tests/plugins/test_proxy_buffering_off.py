import io

import pytest

import gixy
from gixy.core.config import Config
from gixy.core.manager import Manager


@pytest.mark.parametrize("name,severity", [
    ("proxy_buffering", gixy.severity.MEDIUM),
    ("fastcgi_buffering", gixy.severity.MEDIUM),
    ("uwsgi_buffering", gixy.severity.MEDIUM),
    ("scgi_buffering", gixy.severity.MEDIUM),
    ("proxy_request_buffering", gixy.severity.LOW),
    ("fastcgi_request_buffering", gixy.severity.LOW),
    ("uwsgi_request_buffering", gixy.severity.LOW),
    ("scgi_request_buffering", gixy.severity.LOW),
])
def test_severity(name, severity):
    with Manager(config=Config(plugins=["proxy_buffering_off"])) as manager:
        manager.audit("/tmp/inline.conf", io.StringIO("location / { %s off; }" % name), is_stdin=True)
        severities = [issue.severity or plugin.severity for plugin in manager.results for issue in plugin.issues]
        assert severities == [severity]
