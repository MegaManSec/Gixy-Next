import pytest

from gixy.parser.nginx_parser import NginxParser
from gixy.plugins.regex_redos import regex_redos


def _regexes(config, name):
    """Collect (pattern, modifier) the plugin would send to the recheck server
    for every `name` directive in `config`."""
    root = NginxParser(cwd="", allow_includes=False).parse_string(config)
    plugin = regex_redos({})
    out = []
    for directive in root.find_recursive(name):
        out.extend(plugin._regexes(directive))
    return out


@pytest.mark.parametrize("config,name,expected", [
    ("location ~ ^/(a+)+$ { }", "location", [("^/(a+)+$", "")]),
    ("location ~* ^/(a+)+$ { }", "location", [("^/(a+)+$", "i")]),
    ('if ($http_user_agent ~ "(a+)+x") { }', "if", [("(a+)+x", "")]),
    ('if ($http_user_agent ~* "(a+)+x") { }', "if", [("(a+)+x", "i")]),
    ("rewrite ^/(a+)+$ /x last;", "rewrite", [("^/(a+)+$", "")]),
    ("server_name ~*^(a+)+\\.ex$ www.ex.com;", "server_name", [("^(a+)+\\.ex$", "i")]),
    ("server_name ~^(a+)+x;", "server_name", [("^(a+)+x", "")]),
    ("map $uri $x { ~*^(a+)+$ 1; ~^/b 2; default 0; }", "map", [("^(a+)+$", "i"), ("^/b", "")]),
    # gzip_disable and valid_referers regexes are always case-insensitive
    ('gzip_disable msie6 "^(a+)+x";', "gzip_disable", [("^(a+)+x", "i")]),
    ("valid_referers none blocked ~^(a+)+\\.ex/ www.ex.com;", "valid_referers", [("^(a+)+\\.ex/", "i")]),
    ("fastcgi_split_path_info ^(.+\\.php)(/.+)$;", "fastcgi_split_path_info", [("^(.+\\.php)(/.+)$", "")]),
    ("proxy_redirect ~*^http://(a+)+$ /$1;", "proxy_redirect", [("^http://(a+)+$", "i")]),
    ("proxy_cookie_path ~^/(a+)+$ /;", "proxy_cookie_path", [("^/(a+)+$", "")]),
    ("proxy_cookie_domain ~^(a+)+$ ex.com;", "proxy_cookie_domain", [("^(a+)+$", "i")]),
    ("proxy_cookie_flags ~^(a+)+$ secure;", "proxy_cookie_flags", [("^(a+)+$", "i")]),
])
def test_regexes_extracted(config, name, expected):
    assert _regexes(config, name) == expected


@pytest.mark.parametrize("config,name", [
    ("location /static/ { }", "location"),                 # prefix match, no regex
    ("if ($request_method = POST) { }", "if"),             # comparison, no regex
    ("server_name example.com *.example.com;", "server_name"),  # plain/wildcard names
    ("map $uri $x { /a 1; default 0; }", "map"),           # literal keys, no regex
    ("gzip_disable msie6 degradation;", "gzip_disable"),   # built-in masks, no regex
    ("valid_referers none blocked server_names *.ex.com;", "valid_referers"),  # names only
    ("proxy_redirect http://$host:8080/ /;", "proxy_redirect"),  # plain prefix, no regex
])
def test_no_regexes_for_non_regex_forms(config, name):
    assert _regexes(config, name) == []
