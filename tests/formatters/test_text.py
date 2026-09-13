import io

from gixy.core.context import purge_context
from gixy.core.manager import Manager
from gixy.formatters.console import ConsoleFormatter
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

LATIN1_ROUNDTRIP_CONFIG = """
http {
server {
    location /Ã© {
        alias /var/www/Ã©/;
    }
}
}
"""


def teardown_function():
    purge_context()


def _format(path, config, formatter_class=TextFormatter):
    manager = Manager()
    manager.audit(path, io.StringIO(config), is_stdin=True)
    formatter = formatter_class()
    formatter.feed(path, manager)
    return formatter.flush()


def test_text_report_with_non_ascii_config():
    report = _format("/etc/nginx/nginx.conf", UNICODE_CONFIG)

    assert "alias_traversal" in report
    assert "/café" in report


def test_console_report_with_non_ascii_config():
    report = _format(
        "/etc/nginx/nginx.conf", UNICODE_CONFIG, formatter_class=ConsoleFormatter
    )

    assert "/café" in report


def test_text_report_keeps_latin1_encodable_config_verbatim():
    report = _format("/etc/nginx/nginx.conf", LATIN1_ROUNDTRIP_CONFIG)

    assert "/Ã©" in report
    assert "/é " not in report


def test_console_report_keeps_latin1_encodable_config_verbatim():
    report = _format(
        "/etc/nginx/nginx.conf",
        LATIN1_ROUNDTRIP_CONFIG,
        formatter_class=ConsoleFormatter,
    )

    assert "/Ã©" in report
