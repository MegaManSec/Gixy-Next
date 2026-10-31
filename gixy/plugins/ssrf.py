import re

import gixy
import gixy.core.sre_parse.sre_parse as sre_parse
from gixy.core.context import get_context
from gixy.core.regexp import Regexp
from gixy.core.variable import compile_script
from gixy.plugins.plugin import Plugin


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

        res = self._check_script(parsed.group("scheme"), directive)
        if not res:
            self._check_script(parsed.group("host"), directive)

    def _check_script(self, script, directive):
        for var in compile_script(script):
            if var.must_contain("/"):
                # Skip variable checks
                return False
            if any(option.can_contain(".") and not option.must_contain("/") for option in var.options):
                # Yay! Our variable can contain any symbols!
                reason = "Variable `${var}` can contain untrusted user input.".format(
                    var=var.name
                )
                self.add_issue(directive=[directive] + var.providers, reason=reason)

                return True
        return False
