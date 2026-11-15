import pytest

from gixy.parser.nginx_parser import NginxParser
from gixy.plugins.add_header_content_type import add_header_content_type


def _reasons(config):
    root = NginxParser(cwd="", allow_includes=False).parse_string(config)
    plugin = add_header_content_type({})
    for directive in root.find_recursive("add_header"):
        plugin.audit(directive)
    return [issue.reason for issue in plugin.issues]


@pytest.mark.parametrize("config,reason", [
    (
        "location / { add_header Content-Type text/plain; }",
        "Use `types {} default_type text/plain;` instead of `add_header` to set Content-Type.",
    ),
    (
        'location / { add_header Content-Type "text/html; charset=utf-8"; }',
        'Use `types {} default_type "text/html; charset=utf-8";` instead of `add_header` to set Content-Type.',
    ),
    (
        "location / { add_header Content-Type $mime; }",
        "`add_header` sends a second Content-Type header, and `default_type` does not expand variables; "
        "map the type with a `types` block instead.",
    ),
    (
        "location / { proxy_pass http://127.0.0.1:8080; add_header Content-Type text/plain; }",
        "Also hide the upstream header with `proxy_hide_header Content-Type;`, "
        "or the response carries two Content-Type headers.",
    ),
    (
        "location / { proxy_hide_header Content-Type; fastcgi_pass 127.0.0.1:9000; "
        "add_header Content-Type text/plain; }",
        "Also hide the upstream header with `fastcgi_hide_header Content-Type;`, "
        "or the response carries two Content-Type headers.",
    ),
    (
        "server { add_header Content-Type text/plain; location / { proxy_pass http://127.0.0.1:8080; } }",
        "Also hide the upstream header with `proxy_hide_header Content-Type;`, "
        "or the response carries two Content-Type headers.",
    ),
    (
        "server { add_header Content-Type text/plain; "
        "location / { proxy_hide_header Content-Type; proxy_pass http://127.0.0.1:8080; } }",
        "Use `types {} default_type text/plain;` instead of `add_header` to set Content-Type.",
    ),
    (
        "server { add_header Content-Type text/plain; "
        "location / { add_header X-Other 1; proxy_pass http://127.0.0.1:8080; } }",
        "Use `types {} default_type text/plain;` instead of `add_header` to set Content-Type.",
    ),
])
def test_reason(config, reason):
    assert _reasons(config) == [reason]
