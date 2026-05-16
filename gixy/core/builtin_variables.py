import logging
import os
import re

from gixy.core.regexp import Regexp
from gixy.core.variable import Variable

LOG = logging.getLogger(__name__)

BUILTIN_VARIABLES = {
    # https://nginx.org/en/docs/http/ngx_http_core_module.html#var_uri
    "uri": r"/[^\x20\t]*",
    # https://nginx.org/en/docs/http/ngx_http_core_module.html#var_document_uri
    "document_uri": r"/[^\x20\t]*",
    # https://nginx.org/en/docs/http/ngx_http_core_module.html#var_arg_
    "arg_": r"[^\s&]+",
    # https://nginx.org/en/docs/http/ngx_http_core_module.html#var_args
    "args": r"[^\s]+",
    # https://nginx.org/en/docs/http/ngx_http_core_module.html#var_query_string
    "query_string": r"[^\s]+",
    # https://nginx.org/en/docs/http/ngx_http_core_module.html#var_request_uri
    "request_uri": r"/[^\s]*",
    # https://nginx.org/en/docs/http/ngx_http_core_module.html#var_http_
    "http_": r"[\x21-\x7e]",
    # https://nginx.org/en/docs/http/ngx_http_upstream_module.html#var_upstream_http_
    "upstream_http_": "",
    # https://nginx.org/en/docs/http/ngx_http_upstream_module.html#var_upstream_cookie_
    "upstream_cookie_": "",
    # https://nginx.org/en/docs/http/ngx_http_proxy_module.html#var_proxy_add_x_forwarded_for
    "proxy_add_x_forwarded_for": "",
    # https://nginx.org/en/docs/http/ngx_http_proxy_module.html#var_proxy_host
    "proxy_host": "",
    # https://nginx.org/en/docs/http/ngx_http_proxy_module.html#var_proxy_port
    "proxy_port": "",
    # https://nginx.org/en/docs/http/ngx_http_core_module.html#var_proxy_protocol_addr
    # https://nginx.org/en/docs/stream/ngx_stream_core_module.html#var_proxy_protocol_addr
    # https://nginx.org/en/docs/http/ngx_http_core_module.html#var_proxy_protocol_port
    # https://nginx.org/en/docs/stream/ngx_stream_core_module.html#var_proxy_protocol_port
    "proxy_protocol_port": "",
    # https://nginx.org/en/docs/http/ngx_http_fastcgi_module.html#var_fastcgi_path_info
    "fastcgi_path_info": "",
    # https://nginx.org/en/docs/http/ngx_http_fastcgi_module.html#var_fastcgi_script_name
    "fastcgi_script_name": "",
    # https://nginx.org/en/docs/http/ngx_http_core_module.html#var_content_type
    "content_type": "",
    # https://nginx.org/en/docs/http/ngx_http_core_module.html#var_cookie_
    "cookie_": "",
    # https://nginx.org/en/docs/http/ngx_http_core_module.html#var_host
    "host": "",
    # https://nginx.org/en/docs/http/ngx_http_core_module.html#var_hostname
    # https://nginx.org/en/docs/stream/ngx_stream_core_module.html#var_hostname
    "hostname": "",
    # https://nginx.org/en/docs/http/ngx_http_core_module.html#var_limit_rate
    "limit_rate": "",
    # https://nginx.org/en/docs/http/ngx_http_memcached_module.html#var_memcached_key
    "memcached_key": "",
    # https://nginx.org/en/docs/http/ngx_http_core_module.html#var_realpath_root
    "realpath_root": "",
    # https://nginx.org/en/docs/http/ngx_http_core_module.html#var_remote_user
    "remote_user": "",
    # https://nginx.org/en/docs/http/ngx_http_core_module.html#var_request
    "request": "",
    # https://nginx.org/en/docs/http/ngx_http_core_module.html#var_request_body
    "request_body": "",
    # https://nginx.org/en/docs/http/ngx_http_core_module.html#var_request_completion
    "request_completion": "",
    # https://nginx.org/en/docs/http/ngx_http_core_module.html#var_request_filename
    "request_filename": "",
    # https://nginx.org/en/docs/http/ngx_http_core_module.html#var_request_id
    "request_id": "",
    # https://nginx.org/en/docs/http/ngx_http_slice_module.html#var_slice_range
    "slice_range": "",
    # https://nginx.org/en/docs/http/ngx_http_secure_link_module.html#var_secure_link
    "secure_link": "",
    # https://nginx.org/en/docs/http/ngx_http_secure_link_module.html#var_secure_link_expires
    "secure_link_expires": "",
    # https://nginx.org/en/docs/http/ngx_http_core_module.html#var_sent_http_
    "sent_http_": "",
    # https://nginx.org/en/docs/http/ngx_http_core_module.html#var_server_name
    "server_name": "",
    # "Secure" variables that can't content or strictly limited user input
    # https://nginx.org/en/docs/http/ngx_http_browser_module.html#var_ancient_browser
    "ancient_browser": None,
    # https://nginx.org/en/docs/http/ngx_http_core_module.html#var_binary_remote_addr
    # https://nginx.org/en/docs/stream/ngx_stream_core_module.html#var_binary_remote_addr
    "binary_remote_addr": None,
    # https://nginx.org/en/docs/http/ngx_http_core_module.html#var_body_bytes_sent
    "body_bytes_sent": None,
    # https://nginx.org/en/docs/stream/ngx_stream_core_module.html#var_bytes_received
    "bytes_received": None,
    # https://nginx.org/en/docs/http/ngx_http_core_module.html#var_bytes_sent
    # https://nginx.org/en/docs/http/ngx_http_log_module.html#var_bytes_sent
    # https://nginx.org/en/docs/stream/ngx_stream_core_module.html#var_bytes_sent
    "bytes_sent": None,
    # https://nginx.org/en/docs/http/ngx_http_core_module.html#var_connection
    # https://nginx.org/en/docs/http/ngx_http_log_module.html#var_connection
    # https://nginx.org/en/docs/stream/ngx_stream_core_module.html#var_connection
    "connection": None,
    # https://nginx.org/en/docs/http/ngx_http_core_module.html#var_connection_requests
    # https://nginx.org/en/docs/http/ngx_http_log_module.html#var_connection_requests
    "connection_requests": None,
    # https://nginx.org/en/docs/http/ngx_http_stub_status_module.html#var_connections_active
    "connections_active": None,
    # https://nginx.org/en/docs/http/ngx_http_stub_status_module.html#var_connections_reading
    "connections_reading": None,
    # https://nginx.org/en/docs/http/ngx_http_stub_status_module.html#var_connections_waiting
    "connections_waiting": None,
    # https://nginx.org/en/docs/http/ngx_http_stub_status_module.html#var_connections_writing
    "connections_writing": None,
    # https://nginx.org/en/docs/http/ngx_http_core_module.html#var_content_length
    "content_length": None,
    # https://nginx.org/en/docs/http/ngx_http_ssi_module.html#var_date_gmt
    "date_gmt": None,
    # https://nginx.org/en/docs/http/ngx_http_ssi_module.html#var_date_local
    "date_local": None,
    # https://nginx.org/en/docs/http/ngx_http_core_module.html#var_document_root
    "document_root": "/etc/nginx",
    # https://nginx.org/en/docs/http/ngx_http_geoip_module.html
    # https://nginx.org/en/docs/stream/ngx_stream_geoip_module.html
    "geoip_": None,
    # https://nginx.org/en/docs/http/ngx_http_gzip_module.html#var_gzip_ratio
    "gzip_ratio": None,
    # https://nginx.org/en/docs/http/ngx_http_v2_module.html#var_http2
    "http2": None,
    # https://nginx.org/en/docs/http/ngx_http_core_module.html#var_https
    "https": None,
    # https://nginx.org/en/docs/http/ngx_http_referer_module.html#var_invalid_referer
    "invalid_referer": None,
    # https://nginx.org/en/docs/http/ngx_http_core_module.html#var_is_args
    "is_args": None,
    # https://nginx.org/en/docs/http/ngx_http_auth_jwt_module.html
    "jwt_": None,
    # https://nginx.org/en/docs/http/ngx_http_browser_module.html#var_modern_browser
    "modern_browser": None,
    # https://nginx.org/en/docs/http/ngx_http_core_module.html#var_msec
    # https://nginx.org/en/docs/http/ngx_http_log_module.html#var_msec
    # https://nginx.org/en/docs/stream/ngx_stream_core_module.html#var_msec
    "msec": None,
    # https://nginx.org/en/docs/http/ngx_http_browser_module.html#var_msie
    "msie": None,
    # https://nginx.org/en/docs/http/ngx_http_core_module.html#var_nginx_version
    # https://nginx.org/en/docs/stream/ngx_stream_core_module.html#var_nginx_version
    "nginx_version": None,
    # https://nginx.org/en/docs/http/ngx_http_core_module.html#var_pid
    # https://nginx.org/en/docs/stream/ngx_stream_core_module.html#var_pid
    "pid": None,
    # https://nginx.org/en/docs/http/ngx_http_core_module.html#var_pipe
    # https://nginx.org/en/docs/http/ngx_http_log_module.html#var_pipe
    "pipe": None,
    # https://nginx.org/en/docs/stream/ngx_stream_core_module.html#var_protocol
    "protocol": None,
    # https://nginx.org/en/docs/http/ngx_http_realip_module.html#var_realip_remote_addr
    # https://nginx.org/en/docs/stream/ngx_stream_realip_module.html#var_realip_remote_addr
    # https://nginx.org/en/docs/http/ngx_http_realip_module.html#var_realip_remote_port
    # https://nginx.org/en/docs/stream/ngx_stream_realip_module.html#var_realip_remote_port
    "realip_remote_port": None,
    # https://nginx.org/en/docs/http/ngx_http_core_module.html#var_remote_addr
    # https://nginx.org/en/docs/stream/ngx_stream_core_module.html#var_remote_addr
    "remote_addr": None,
    # https://nginx.org/en/docs/http/ngx_http_core_module.html#var_remote_port
    # https://nginx.org/en/docs/stream/ngx_stream_core_module.html#var_remote_port
    "remote_port": None,
    # https://nginx.org/en/docs/http/ngx_http_core_module.html#var_request_body_file
    "request_body_file": None,
    # https://nginx.org/en/docs/http/ngx_http_core_module.html#var_request_length
    # https://nginx.org/en/docs/http/ngx_http_log_module.html#var_request_length
    "request_length": None,
    # https://nginx.org/en/docs/http/ngx_http_core_module.html#var_request_method
    "request_method": None,
    # https://nginx.org/en/docs/http/ngx_http_core_module.html#var_request_time
    # https://nginx.org/en/docs/http/ngx_http_log_module.html#var_request_time
    "request_time": None,
    # https://nginx.org/en/docs/http/ngx_http_core_module.html#var_scheme
    "scheme": None,
    # https://nginx.org/en/docs/http/ngx_http_core_module.html#var_server_addr
    # https://nginx.org/en/docs/stream/ngx_stream_core_module.html#var_server_addr
    "server_addr": None,
    # https://nginx.org/en/docs/http/ngx_http_core_module.html#var_server_port
    # https://nginx.org/en/docs/stream/ngx_stream_core_module.html#var_server_port
    "server_port": None,
    # https://nginx.org/en/docs/http/ngx_http_core_module.html#var_server_protocol
    "server_protocol": None,
    # https://nginx.org/en/docs/http/ngx_http_session_log_module.html#var_session_log_binary_id
    "session_log_binary_id": None,
    # https://nginx.org/en/docs/http/ngx_http_session_log_module.html#var_session_log_id
    "session_log_id": None,
    # https://nginx.org/en/docs/stream/ngx_stream_core_module.html#var_session_time
    "session_time": None,
    # https://nginx.org/en/docs/http/ngx_http_spdy_module.html#var_spdy
    "spdy": None,
    # https://nginx.org/en/docs/http/ngx_http_spdy_module.html#var_spdy_request_priority
    "spdy_request_priority": None,
    # https://nginx.org/en/docs/http/ngx_http_ssl_module.html
    # https://nginx.org/en/docs/stream/ngx_stream_ssl_module.html
    "ssl_": None,
    # https://nginx.org/en/docs/http/ngx_http_core_module.html#var_status
    # https://nginx.org/en/docs/http/ngx_http_log_module.html#var_status
    # https://nginx.org/en/docs/stream/ngx_stream_core_module.html#var_status
    "status": None,
    # https://nginx.org/en/docs/http/ngx_http_core_module.html
    "tcpinfo_": None,
    # https://nginx.org/en/docs/http/ngx_http_core_module.html
    # https://nginx.org/en/docs/http/ngx_http_log_module.html
    # https://nginx.org/en/docs/stream/ngx_stream_core_module.html
    "time_iso8601": None,
    # https://nginx.org/en/docs/http/ngx_http_core_module.html
    # https://nginx.org/en/docs/http/ngx_http_log_module.html
    # https://nginx.org/en/docs/stream/ngx_stream_core_module.html
    "time_local": None,
    # https://nginx.org/en/docs/http/ngx_http_userid_module.html#var_uid_got
    "uid_got": None,
    # https://nginx.org/en/docs/http/ngx_http_userid_module.html#var_uid_reset
    "uid_reset": None,
    # https://nginx.org/en/docs/http/ngx_http_userid_module.html#var_uid_set
    "uid_set": None,
    # https://nginx.org/en/docs/http/ngx_http_upstream_module.html#var_upstream_addr
    # https://nginx.org/en/docs/stream/ngx_stream_upstream_module.html#var_upstream_addr
    "upstream_addr": None,
    # https://nginx.org/en/docs/http/ngx_http_upstream_module.html#var_upstream_bytes_received
    # https://nginx.org/en/docs/stream/ngx_stream_upstream_module.html#var_upstream_bytes_received
    "upstream_bytes_received": None,
    # https://nginx.org/en/docs/stream/ngx_stream_upstream_module.html#var_upstream_bytes_sent
    "upstream_bytes_sent": None,
    # https://nginx.org/en/docs/http/ngx_http_upstream_module.html#var_upstream_cache_status
    "upstream_cache_status": None,
    # https://nginx.org/en/docs/http/ngx_http_upstream_module.html#var_upstream_connect_time
    # https://nginx.org/en/docs/stream/ngx_stream_upstream_module.html#var_upstream_connect_time
    "upstream_connect_time": None,
    # https://nginx.org/en/docs/stream/ngx_stream_upstream_module.html#var_upstream_first_byte_time
    "upstream_first_byte_time": None,
    # https://nginx.org/en/docs/http/ngx_http_upstream_module.html#var_upstream_header_time
    "upstream_header_time": None,
    # https://nginx.org/en/docs/http/ngx_http_upstream_module.html#var_upstream_response_length
    "upstream_response_length": None,
    # https://nginx.org/en/docs/http/ngx_http_upstream_module.html#var_upstream_response_time
    "upstream_response_time": None,
    # https://nginx.org/en/docs/stream/ngx_stream_upstream_module.html#var_upstream_session_time
    "upstream_session_time": None,
    # https://nginx.org/en/docs/http/ngx_http_upstream_module.html#var_upstream_status
    "upstream_status": None,
}


# Additional variables loaded from drop-in configuration files
EXTRA_VARIABLES = {}


def clear_custom_variables():
    """Clear variables loaded from drop-in files (useful for tests)."""
    EXTRA_VARIABLES.clear()


def _normalize_value_token(token):
    """Parse a token from a drop-in variable file into a usable value.

    Supported forms:
    - "" or '' -> empty string (treated as not user-controlled)
    - r'...'/r"..." -> regex pattern string
    - '...'/"..." -> literal string
    - none/null (case-insensitive) -> None
    - empty/missing value -> empty string
    Trailing commas are tolerated.
    """
    if token is None:
        return ""

    token = token.strip().rstrip(",").strip()
    if token.lower() in ("none", "null"):
        return None

    # Strip possible raw prefix
    raw_prefix = False
    if len(token) > 2 and token[0] in ("r", "R") and token[1] in ("'", '"'):
        raw_prefix = True
        token = token[1:]

    # Strip quotes
    quoted = False
    if len(token) >= 2 and token[0] == token[-1] and token[0] in ("'", '"'):
        quoted = True
        token = token[1:-1]

    # If it was quoted without a raw prefix, treat as a literal string (not regex).
    # Raw-prefixed quoted values (r"..." / r'...') continue to mean "regex pattern".
    if quoted and not raw_prefix:
        return re.escape(token)

    # Otherwise treat as a regex pattern (backward compatible for unquoted tokens).
    return token


def _parse_dropin_file(file_path):
    """Parse a single drop-in file and return a dict of variables.

    Each non-empty, non-comment line should be of the form:
        name <value>
    where value follows _normalize_value_token rules.
    """
    result = {}
    try:
        with open(file_path, "r") as fh:
            for raw_line in fh:
                line = raw_line.strip()
                if not line or line.startswith("#") or line.startswith(";"):
                    continue

                # Fast-path parse: find first whitespace after a valid identifier
                i = 0
                n = len(line)
                # identifier start
                c0 = line[0]
                if not (c0.isalpha() or c0 == "_"):
                    LOG.info(
                        "Skip malformed custom variable line in %s: %r",
                        file_path,
                        raw_line.rstrip("\n"),
                    )
                    continue
                i = 1
                while i < n and (line[i].isalnum() or line[i] == "_"):
                    i += 1
                name = line[:i]
                # skip spaces between name and value
                j = i
                while j < n and line[j].isspace():
                    j += 1
                value_token = line[j:]
                # Allow optional separator characters between name and value
                # If the line used name = value or name: value, drop the first char
                if value_token[:1] in ("=", ":"):
                    value_token = value_token[1:].strip()
                result[name] = _normalize_value_token(value_token)
    except Exception as e:
        LOG.warning("Failed to load custom variables from %s: %s", file_path, e)
    return result


def load_custom_variables_from_dirs(paths):
    """Load additional variables from provided directories.

    - Reads all files with extensions .cfg or .conf
    - Merges into EXTRA_VARIABLES (later files override earlier ones)
    """
    if not paths:
        return
    for base in paths:
        if not base:
            continue
        expanded = os.path.expanduser(base)
        if not os.path.isdir(expanded):
            continue
        try:
            entries = sorted(os.listdir(expanded))
        except OSError:
            continue
        for fname in entries:
            if not (fname.endswith(".cfg") or fname.endswith(".conf")):
                continue
            fpath = os.path.join(expanded, fname)
            if not os.path.isfile(fpath):
                continue
            parsed = _parse_dropin_file(fpath)
            if parsed:
                EXTRA_VARIABLES.update(parsed)


def _iter_all_variable_items():
    # EXTRA overrides BUILTIN on duplicates
    # Preserve prefix variables (ending with '_') semantics
    # Order: EXTRA first, then BUILTIN
    for k, v in EXTRA_VARIABLES.items():
        yield k, v
    for k, v in BUILTIN_VARIABLES.items():
        if k not in EXTRA_VARIABLES:
            yield k, v


def is_builtin(name):
    if isinstance(name, int):
        # Indexed variables can't be builtin
        return False
    for builtin, _ in _iter_all_variable_items():
        if builtin.endswith("_"):
            if name.startswith(builtin):
                return True
        elif name == builtin:
            return True
    return False


def builtin_var(name):
    for builtin, regexp in _iter_all_variable_items():
        if builtin.endswith("_"):
            if not name.startswith(builtin):
                continue
        elif name != builtin:
            continue

        if regexp:
            return Variable(
                name=name, value=Regexp(regexp, strict=True, case_sensitive=False)
            )
        return Variable(name=name, value="builtin", have_script=False)
    return None


def fake_var(name):
    return Variable(name=name, value=name, have_script=False)
