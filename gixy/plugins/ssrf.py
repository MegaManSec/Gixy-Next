import re
import string

import gixy
import gixy.core.sre_parse.sre_parse as sre_parse
from gixy.core.context import get_context
from gixy.core.regexp import Regexp
from gixy.core.utils import default_listens, parse_listen_key_and_default
from gixy.core.variable import compile_script
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
    except (sre_parse.error, OverflowError, RecursionError):
        return False


def _depends_on_host(var):
    if var.name == "host" and var.value == "builtin":
        return True
    return any(_depends_on_host(dep) for dep in var.depends or var.alternatives or ())


def _literal_start(location):
    if not location.is_regex:
        return location.path
    try:
        seq = list(Regexp(location.path).parsed)
    except (sre_parse.error, OverflowError, RecursionError):
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
        if len(rewrite.args) < 2 or rewrite.args[2:] not in ([], ["last"]):
            continue
        replacement = rewrite.args[1]
        if "$" not in replacement or replacement.startswith(("http://", "https://", "$scheme")):
            continue
        prefix = replacement.split("$", 1)[0]
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
    directives = ["proxy_pass", "fastcgi_pass", "uwsgi_pass", "scgi_pass", "grpc_pass"]

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

        context = get_context()
        if context.block.name == "location" and context.block.is_internal and not _reached_by_rewrite(context.block):
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
        if var.name == "host" and var.value == "builtin":
            return bool(self._host_explanation)
        if var.alternatives:
            results = [self._host_tainted(option) for option in var.options]
            if any(results):
                return True
            if results and all(result is None for result in results):
                return None
            return False
        if var.depends:
            for dep in var.depends:
                result = self._host_tainted(dep)
                if result is not False:
                    return result
            return False
        if var.must_contain("/"):
            return None
        return bool(var.can_contain("."))

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
            sockets = sorted({parse_listen_key_and_default(listen.args)[0] or listen.args[0] for listen in listens})
            return (
                "`$host` is taken from the request: this is the default server for {sockets}, "
                "so a request for any host name reaches it."
            ).format(sockets=", ".join("`{0}`".format(socket) for socket in sockets))
        if any(_is_catch_all_name(name) for sn in server.find("server_name") for name in sn.args):
            return (
                "`$host` is taken from the request: `server_name` has a catch-all regular expression, "
                "so a request for any host name reaches this server."
            )
        return None
