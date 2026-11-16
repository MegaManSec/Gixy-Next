import re
import string

import gixy
import gixy.core.sre_parse.sre_parse as sre_parse
from gixy.core.regexp import PARSE_ERRORS, Regexp, RegexpTooComplex
from gixy.core.utils import (
    PASS_DIRECTIVES,
    default_listens,
    parse_listen_key_and_default,
    pins_registrable_domain,
    resolve_inherited_single,
)
from gixy.core.variable import compile_hash_entry, compile_script
from gixy.plugins.plugin import Plugin


HOST_NAME_CHARS = string.ascii_lowercase + string.digits + "-."


def _is_catch_all_name(name):
    """A `server_name` regex that pins no character, such as `~.` or `~^.*$`, matches any Host."""
    if not name.startswith("~"):
        return False
    pattern = name[1:]
    if pattern.startswith("*"):
        pattern = pattern[1:]
    try:
        regexp = Regexp(pattern)
        return not any(regexp.must_contain(char) for char in HOST_NAME_CHARS)
    except PARSE_ERRORS:
        return False


def _is_open_suffix_name(name):
    """A `server_name` such as `example.*`, `~^api\\.` or `~^(.+)\\.co\\.uk$` that also matches names under a
    domain the client registers."""
    if not name.startswith("~"):
        return name.endswith(".*")
    try:
        return not pins_registrable_domain(name[1:])
    except (*PARSE_ERRORS, RegexpTooComplex):
        return False


def _hash_values(var):
    """The scripts a map or geo variable resolves to, plus an empty one when it has no `default`."""
    values = [compile_hash_entry(entry) or [] for entry in var.value]
    if not any(entry.provider.src_val == "default" for entry in var.value):
        values.append([])
    return values


def _depends_on_host(var):
    if var.name == "host":
        return True
    if isinstance(var.value, list):
        return any(_depends_on_host(dep) for parts in _hash_values(var) for dep in parts)
    return any(_depends_on_host(dep) for dep in var.depends or var.alternatives or ())


def _literal_start(location):
    if not location.is_regex:
        return location.path
    try:
        seq = list(Regexp(location.path).parsed)
    except PARSE_ERRORS:
        return ""
    if not seq or seq[0] != (sre_parse.AT, sre_parse.AT_BEGINNING):
        return ""
    start = ""
    for op, av in seq[1:]:
        if op != sre_parse.LITERAL:
            break
        start += chr(av)
    return start.lower() if location.modifier == "~*" else start


def _reached_by_rewrite(location):
    server = next((parent for parent in location.parents if parent.name == "server"), None)
    if server is None:
        return False
    start = _literal_start(location)
    for rewrite in server.find_recursive("rewrite"):
        if rewrite.flag not in (None, "last") or rewrite.redirects or "$" not in rewrite.replace:
            continue
        prefix = rewrite.replace.split("$", 1)[0]
        if location.modifier == "~*":
            prefix = prefix.lower()
        if start.startswith(prefix) or prefix.startswith(start):
            return True
    return False


class ssrf(Plugin):
    """
    Insecure examples:
        location ~ /proxy/(.*)/(.*)/(.*)$ {
            set $scheme $1;
            set $host $2;
            set $path $3;
            proxy_pass $scheme://$host/$path;
        }

        location /proxy/ {
            proxy_pass $arg_some;
        }
    """

    summary = "Possible SSRF (Server Side Request Forgery) vulnerability."
    severity = gixy.severity.HIGH
    description = "The configuration may allow an attacker to make arbitrary requests from the vulnerable server."
    help_url = "https://gixy.io/plugins/ssrf/"
    directives = PASS_DIRECTIVES

    def __init__(self, config):
        super(ssrf, self).__init__(config)
        self.parse_uri_re = re.compile(r"(?P<scheme>[^?#/)]+://)?(?P<host>[^?#/)]+)")
        self._defaults = {}
        self._host_explanation = None

    def audit(self, directive):
        # proxy_pass and friends require an upstream argument; its absence is
        # malformed input (handled gracefully), not a crash.
        value = directive.arg(0)
        if not value:
            return

        locations = [block for block in directive.parents if block.name == "location"]
        if any(location.is_internal for location in locations) and not _reached_by_rewrite(locations[0]):
            return

        parsed = self.parse_uri_re.match(value)
        if not parsed:
            return

        self._host_explanation = self._host_header_explanation(directive)
        res = self._check_script(parsed.group("scheme"), directive)
        if not res:
            self._check_script(parsed.group("host"), directive)

    def _check_script(self, script, directive):
        for var in compile_script(script):
            tainted = self._host_tainted(var)
            if tainted is None:
                # Skip variable checks
                return False
            if tainted:
                # Yay! Our variable can contain any symbols!
                reason = "Variable `${var}` can contain untrusted user input.".format(
                    var=var.name
                )
                if self._host_explanation and _depends_on_host(var):
                    reason += " " + self._host_explanation
                self.add_issue(directive=[directive] + var.providers, reason=reason)

                return True
        return False

    def _host_tainted(self, var):
        """True if the host part of `var` can carry user input, None if the
        variable ends the host part with a mandatory `/` before any such
        input, False otherwise."""
        if var.name == "host":
            return bool(self._host_explanation)
        if var.alternatives:
            return self._any_tainted(self._host_tainted(option) for option in var.options)
        if isinstance(var.value, list):
            return self._any_tainted(self._parts_tainted(parts) for parts in _hash_values(var))
        if var.depends:
            return self._parts_tainted(var.depends)
        if var.must_contain("/"):
            return None
        return bool(var.can_contain("."))

    def _parts_tainted(self, parts):
        for part in parts:
            result = self._host_tainted(part)
            if result is not False:
                return result
        return False

    @staticmethod
    def _any_tainted(results):
        results = list(results)
        if any(results):
            return True
        if results and all(result is None for result in results):
            return None
        return False

    def _host_header_explanation(self, directive):
        """Why `$host` is attacker-chosen for `directive`, or None when the server only sees the
        host names it declares. Needs the full configuration: without an `http` block the other
        servers on the socket are unknown."""
        server = next((block for block in directive.parents if block.name == "server"), None)
        http = next((block for block in directive.parents if block.name == "http"), None)
        if server is None or http is None:
            return None
        if id(http) not in self._defaults:
            self._defaults[id(http)] = default_listens(list(http.find_all_contexts_of_type("server")))
        listens = self._defaults[id(http)].get(server)
        if listens:
            sockets = sorted({parse_listen_key_and_default(listen.args)[0] for listen in listens})
            return (
                "`$host` is taken from the request: this is the default server for {sockets}, "
                "so a request for any host name reaches it."
            ).format(sockets=", ".join("`{0}`".format(socket) for socket in sockets))
        names = [name for sn in server.find("server_name") for name in sn.args]
        if any(_is_catch_all_name(name) for name in names):
            return (
                "`$host` is taken from the request: `server_name` has a catch-all regular expression, "
                "so a request for any host name reaches this server."
            )
        if not resolve_inherited_single(directive.parent, "resolver"):
            return None
        open_name = next((name for name in names if _is_open_suffix_name(name)), None)
        if open_name:
            return (
                "`$host` is taken from the request: `server_name {name}` also matches names under any domain, "
                "and the `resolver` lets the client's own DNS point that name at any address."
            ).format(name=open_name)
        return None
