import io
import logging

from gixy.core.context import purge_context
from gixy.core.manager import Manager


def setup_function():
    pass


def teardown_function():
    purge_context()


def _audit(config, caplog=None):
    if caplog is not None:
        caplog.set_level(logging.INFO, logger='gixy.core.variable')
    m = Manager()
    m.audit('/tmp/inline.conf', io.StringIO(config), is_stdin=True)
    return m


def _missing(caplog):
    return [
        r for r in caplog.records
        if r.name == 'gixy.core.variable' and "Can't find variable" in r.getMessage()
    ]


def test_set_after_location_is_visible(caplog):
    _audit("""
http { server {
    location @err { root $Root_Path/pages; }
    set $Root_Path /var/www;
} }
""", caplog)
    assert _missing(caplog) == []


def test_map_after_server_is_visible(caplog):
    _audit("""
http {
    server {
        location = /.well-known/security.txt {
            return 200 "Canonical: https://$canonical_host/security.txt";
        }
    }
    map $ssl_server_name $canonical_host {
        default $ssl_server_name;
    }
}
""", caplog)
    assert _missing(caplog) == []


def test_geo_after_server_is_visible(caplog):
    _audit("""
http {
    server {
        location / { return 200 $country_code; }
    }
    geo $country_code {
        default ZZ;
        192.168.1.0/24 US;
    }
}
""", caplog)
    assert _missing(caplog) == []



def test_set_in_if_block_is_visible_to_sibling_location(caplog):
    _audit("""
http { server {
    location / { return 200 $mode; }
    if ($request_method = POST) { set $mode write; }
} }
""", caplog)
    assert _missing(caplog) == []


def test_chained_set_forward_ref_does_not_log(caplog):
    _audit("""
http { server {
    set $X "$Y/sub";
    set $Y /base;
    location / { return 200 $X; }
} }
""", caplog)
    assert _missing(caplog) == []


def test_map_status_to_error_code_after_server_is_visible(caplog):
    # Reproduces issue #105: $error_code defined via map $status after the server block
    _audit("""
http {
    server {
        location = /50x.html {
            return 200 "Error: $error_code - $request_id";
        }
    }
    map $status $error_code {
        default      "Internal Server Error";
        400          "Bad Request";
        401          "Unauthorized";
        403          "Forbidden";
        404          "Not Found";
    }
}
""", caplog)
    assert _missing(caplog) == []


def test_set_in_one_location_does_not_leak_to_sibling(caplog):
    _audit("""
http { server {
    location /a { set $LocalOnly x; }
    location /b { return 200 $LocalOnly; }
} }
""", caplog)
    assert any('LocalOnly' in r.getMessage() for r in _missing(caplog))


def test_prepopulated_map_taint_still_fires_security_check():
    # map-after-server routes tainted $uri through $target; http_splitting must still fire
    config = """
http {
    server {
        location / { return 301 http://$target; }
    }
    map $uri $target {
        default $uri;
    }
}
"""
    m = _audit(config)
    assert any(type(p).__name__ == 'http_splitting' for p in m.results)
