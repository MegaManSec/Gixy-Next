import io

import pytest

from gixy.core.config import Config
from gixy.core.manager import Manager


def _issues(config):
    with Manager(config=Config(plugins=["non_expanding_variable"])) as manager:
        manager.audit("/tmp/inline.conf", io.StringIO(config), is_stdin=True)
        assert manager.errors == []
        return [(issue.severity, issue.reason) for plugin in manager.results for issue in plugin.issues]


@pytest.mark.parametrize("config,severity", [
    ("http { geo $key { default $binary_remote_addr; } limit_req_zone $key zone=z:1m rate=1r/s; }", "HIGH"),
    ("http { geo $key { default $binary_remote_addr; } }", "MEDIUM"),
    ("http { geo $g { default $binary_remote_addr; } limit_req_zone $g$binary_remote_addr zone=z:1m rate=1r/s; }",
     "MEDIUM"),
    ("http { geo $g { default $binary_remote_addr; } map $x $k { default $g$binary_remote_addr; } "
     "limit_req_zone $k zone=z:1m rate=1r/s; }", "MEDIUM"),
    ("http { geo $g { default $binary_remote_addr; } map $x $k { default $g; admin ''; } "
     "limit_req_zone $k zone=z:1m rate=1r/s; }", "HIGH"),
    ("http { split_clients $remote_addr $s { * $host; } limit_conn_zone $s zone=z:1m; }", "HIGH"),
    ("error_log /var/log/$host.log;", "LOW"),
    ("server { location /$x/ { return 200; } }", "MEDIUM"),
    ("server { location /$x/ { deny all; } }", "HIGH"),
    ("server { location ~ ^/$x/ { return 403; } }", "HIGH"),
    ("server { location ~ ^/$x/ { if ($a) { return 444; } } }", "HIGH"),
    ("server { location ~ ^/$x/ { limit_except GET { deny all; } } }", "HIGH"),
    ("server { location ~ ^/$x/ { location /a/ { deny all; } } }", "HIGH"),
    ("server { location ~ ^/$x/ { auth_basic off; } }", "MEDIUM"),
    ("server { location ~ \"(?m)^/a$x\" { } }", "MEDIUM"),
    ("server { location ~ ^/a${x}$ { } }", "MEDIUM"),
    ("server { if ($uri ~ ^/$x) { return 403; } }", "HIGH"),
    ("server { if ($uri !~ ^/$x) { return 403; } }", "MEDIUM"),
    ("http { geo $g { ranges; default 1; 10.0.0.1-10.0.0.9 $x; } }", "MEDIUM"),
])
def test_severity(config, severity):
    assert [found for found, _ in _issues(config)] == [severity]


@pytest.mark.parametrize("config", [
    "http { map $request_method $is_post { POST 1; default ''; } server { location $is_post { return 405; } } }",
    "server { location @named { return 404; } }",
    "server { server_name $hostname; }",
    "server { location ~ \"^/(api|$version)/\" { return 403; } }",
    "server { location ~ \"^/opt(/$v)?$\" { return 403; } }",
    "server { location ~ \"^/n(?!$x)a\" { return 403; } }",
    "server { location ~ \"^/q\\Q$b\\E\" { } }",
    "server { location ~ \"^/a{4294967296}$b\" { } }",
    "http { geo $g { ranges; default 0; 10.0.0.1-10.0.0.9 1; } }",
    "http { geo $price { default \"$5\"; } }",
])
def test_not_reported(config):
    assert _issues(config) == []


@pytest.mark.parametrize("config,reason", [
    ("server { rewrite ^/${lang}/(.*)$ /$1 last; }",
     "`${lang}` in this regex is an end-of-string anchor followed by `lang`, not a variable, "
     "so the rewrite never applies."),
    ("server { if ($uri !~ ^/$x) { return 403; } }",
     "`$x` in this regex is an end-of-string anchor followed by `x`, not a variable, "
     "so the condition always matches."),
])
def test_reason(config, reason):
    assert [found for _, found in _issues(config)] == [reason]
