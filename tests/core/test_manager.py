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


# ---------------------------------------------------------------------------
# Named capture groups from regex `if` blocks (issue #111)
# ---------------------------------------------------------------------------
# nginx supports three named-group syntaxes via PCRE:
#   (?P<name>...)  — Python/PCRE8 style
#   (?<name>...)   — Perl/PCRE style
#   (?'name'...)   — PCRE7 style
# Variables produced by these captures must be visible to:
#   • set directives inside the if block
#   • set directives after  the if block at the same scope level
#   • set directives before the if block at the same scope level
# All four regex operands are tested: ~  ~*  !~  !~*

def test_if_regex_named_capture_set_inside_python_style(caplog):
    # Basic case from issue #111: (?P<name>...) syntax, set inside the if block.
    _audit("""
http { server {
    server_name example.com;
    if ($http_referer ~ "^https?://example\\.com(?P<path>.*)") {
        set $normalised_referrer $path;
    }
} }
""", caplog)
    assert _missing(caplog) == []


def test_if_regex_named_capture_set_inside_nginx_style(caplog):
    # Perl/nginx (?<name>...) syntax, set inside the if block.
    _audit("""
http { server {
    if ($host ~ "^(?<subdomain>[^.]+)\\.example\\.com$") {
        set $sub $subdomain;
    }
} }
""", caplog)
    assert _missing(caplog) == []


def test_if_regex_named_capture_set_inside_pcre7_style(caplog):
    # PCRE7 (?'name'...) syntax, set inside the if block.
    _audit("""
http { server {
    if ($host ~ "^(?'subdomain'[^.]+)\\.example\\.com$") {
        set $sub $subdomain;
    }
} }
""", caplog)
    assert _missing(caplog) == []


def test_if_regex_named_capture_case_insensitive(caplog):
    # ~* operator: case-insensitive named captures.
    _audit("""
http { server {
    if ($http_referer ~* "^https?://example\\.com(?P<path>.*)") {
        set $r $path;
    }
} }
""", caplog)
    assert _missing(caplog) == []


def test_if_regex_named_capture_negative_match(caplog):
    # !~ operator: named captures are registered even when the if body runs on
    # non-match (nginx still exposes the group variables, set to empty string).
    _audit("""
http { server {
    if ($http_referer !~ "^https?://example\\.com(?P<path>.*)") {
        set $r $path;
    }
} }
""", caplog)
    assert _missing(caplog) == []


def test_if_regex_named_capture_negative_case_insensitive(caplog):
    # !~* operator.
    _audit("""
http { server {
    if ($http_referer !~* "^https?://example\\.com(?P<path>.*)") {
        set $r $path;
    }
} }
""", caplog)
    assert _missing(caplog) == []


def test_if_regex_named_capture_set_after_same_level(caplog):
    # set appears *after* the if block at the same scope level.
    _audit("""
http { server {
    if ($http_referer ~ "^https?://example\\.com(?P<path>.*)") { }
    set $normalised_referrer $path;
} }
""", caplog)
    assert _missing(caplog) == []


def test_if_regex_named_capture_set_before_same_level(caplog):
    # set appears *before* the if block at the same scope level.
    # Requires the names pre-pass to register capture names before values are
    # compiled, otherwise compile_script sees $path as unknown.
    _audit("""
http { server {
    set $normalised_referrer $path;
    if ($http_referer ~ "^https?://example\\.com(?P<path>.*)") { }
} }
""", caplog)
    assert _missing(caplog) == []


def test_if_regex_multiple_named_captures(caplog):
    # Multiple named captures in a single regex, all used.
    _audit("""
http { server {
    if ($request_uri ~ "^/(?P<section>[^/]+)/(?P<id>[0-9]+)$") {
        set $sec $section;
        set $item_id $id;
    }
} }
""", caplog)
    assert _missing(caplog) == []


def test_if_regex_nested_named_captures(caplog):
    # Nested if blocks: outer capture visible inside inner block and to siblings;
    # inner capture visible inside its own block.
    _audit("""
http { server {
    if ($request_uri ~ "^/(?P<section>[^/]+)/") {
        if ($http_host ~ "^(?P<subdomain>[^.]+)\\.example\\.com$") {
            set $combo "$section-$subdomain";
        }
        set $s $section;
    }
} }
""", caplog)
    assert _missing(caplog) == []


def test_if_regex_named_capture_custom_set_var_in_condition(caplog):
    # The variable being matched in the if condition is itself a set variable.
    # The set appears before the if, so both the matched variable and the
    # capture must be resolvable.
    _audit("""
http { server {
    set $myvar "hello-world";
    if ($myvar ~ "^(?P<prefix>[^-]+)-") {
        set $captured $prefix;
    }
} }
""", caplog)
    assert _missing(caplog) == []


def test_if_regex_named_capture_custom_set_var_after_condition(caplog):
    # The variable being matched is a set variable declared *after* the if block.
    _audit("""
http { server {
    if ($myvar ~ "^(?P<prefix>[^-]+)-") {
        set $captured $prefix;
    }
    set $myvar "hello-world";
} }
""", caplog)
    assert _missing(caplog) == []


def test_if_regex_named_and_numeric_captures_coexist(caplog):
    # Named and unnamed (numeric) captures in the same regex.
    # $section is a named capture; $2 is numeric — both must resolve.
    _audit("""
http { server {
    if ($request_uri ~ "^/(?P<section>[^/]+)/([0-9]+)$") {
        set $s $section;
        set $num $2;
    }
} }
""", caplog)
    assert _missing(caplog) == []


def test_if_regex_numeric_capture_set_before_same_level(caplog):
    # Numeric capture used in a set that appears *before* the if block.
    _audit("""
http { server {
    set $num $1;
    if ($request_uri ~ "^/([0-9]+)$") { }
} }
""", caplog)
    assert _missing(caplog) == []


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
