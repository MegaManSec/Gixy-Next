import io

from gixy.core.context import purge_context
from gixy.core.manager import Manager
from gixy.formatters.text import TextFormatter

UNICODE_CONFIG = """
http {
server {
    location /café {
        alias /var/www/café/;
    }
}
}
"""


def teardown_function():
    purge_context()


def _format(path, config):
    manager = Manager()
    manager.audit(path, io.StringIO(config), is_stdin=True)
    formatter = TextFormatter()
    formatter.feed(path, manager)
    return formatter.flush()


def test_text_report_with_non_ascii_config():
    report = _format("/etc/nginx/nginx.conf", UNICODE_CONFIG)

    assert "alias_traversal" in report
    assert "/café" in report
