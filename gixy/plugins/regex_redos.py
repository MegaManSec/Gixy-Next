try:
    import requests

    _REQUESTS_AVAILABLE = True
except Exception:
    requests = None  # requests is optional; plugin will auto-skip without it
    _REQUESTS_AVAILABLE = False
import gixy
from gixy.directives.directive import MapDirective
from gixy.plugins.plugin import Plugin


class regex_redos(Plugin):
    r"""
    This plugin checks regular expressions used by nginx directives for
    patterns that may be vulnerable to ReDoS (Regular Expression Denial of
    Service). Each crafted request can make the worker backtrack until
    PCRE2's match limit stops it.

    nginx runs regexes from many directives through its PCRE engine, so this
    plugin inspects every regex-bearing source: location/if matches,
    server_name, rewrite, map keys, gzip_disable, valid_referers and
    fastcgi_split_path_info.

    Example of a vulnerable directive:
        location ~ ^/(a|aa|aaa|aaaa)+$

    Accessing the above location with a path such as
    /aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaab
    makes PCRE2 backtrack until its match limit, about 0.1 s of worker CPU,
    and fails the request with 500.

    This plugin relies on an external, public API to determine vulnerability.
    Because of this network-dependence, and the fact that potentially private
    expressions are sent over the network, usage of this plugin requires
    the --regex-redos-url flag. This flag must specify the full URL to a
    service which can be queried with expressions, responding with a report
    matching the https://github.com/makenowjust-labs/recheck format.

    An implementation of a compatible server:
    https://github.com/MegaManSec/recheck-http-api
    """

    summary = "Regular expression denial of service (ReDoS)."
    severity = gixy.severity.MEDIUM
    description = (
        "A regular expression that can backtrack catastrophically lets each crafted "
        "request burn worker CPU until PCRE2's match limit stops it (ReDoS)."
    )
    help_url = "https://gixy.io/plugins/regex_redos/"
    directives = [
        "location",
        "if",
        "server_name",
        "rewrite",
        "map",
        "gzip_disable",
        "valid_referers",
        "fastcgi_split_path_info",
    ]
    options = {"url": ""}
    options_help = {
        "url": "URL pointing to a server running a compatible ReDoS checking server (e.g. MegaManSec/recheck-http-api.)"
    }

    skip_test = True

    def __init__(self, config):
        super(regex_redos, self).__init__(config)
        self.redos_server = self.config.get("url")

    @staticmethod
    def _regexes(directive):
        """Yield (pattern, modifier) for every regex a directive carries.

        `modifier` is "i" for case-insensitive matches (~*, !~*) and "" otherwise,
        matching the recheck request format.
        """
        name = directive.name
        if name == "location":
            if directive.modifier in ("~", "~*"):
                yield directive.path, "i" if directive.modifier == "~*" else ""
        elif name == "if":
            if directive.operand in ("~", "~*", "!~", "!~*") and directive.value:
                yield directive.value, "i" if directive.operand in ("~*", "!~*") else ""
        elif name == "rewrite":
            if directive.args:
                yield directive.args[0], ""
        elif name == "server_name":
            args = directive.args
            i = 0
            while i < len(args):
                arg = args[i]
                if arg in ("~", "~*"):  # "~* regex" — prefix split from the pattern
                    if i + 1 < len(args):
                        yield args[i + 1], "i" if arg == "~*" else ""
                    i += 2
                    continue
                if arg.startswith("~*"):  # "~*regex" — prefix attached
                    yield arg[2:], "i"
                elif arg.startswith("~"):
                    yield arg[1:], ""
                i += 1
        elif name == "map":
            for child in directive.gather_map_directives(directive.children):
                if not isinstance(child, MapDirective) or not child.is_regex:
                    continue
                src = child.src_val
                if src.startswith("~*"):
                    yield src[2:], "i"
                elif src.startswith("~"):
                    yield src[1:], ""
        elif name == "gzip_disable":
            for arg in directive.args:
                if arg not in ("msie6", "degradation"):
                    yield arg, "i"
        elif name == "valid_referers":
            for arg in directive.args:
                if arg.startswith("~"):
                    yield arg[1:], "i"
        elif name == "fastcgi_split_path_info":
            if directive.args:
                yield directive.args[0], ""

    def audit(self, directive):
        # If requests is not available, skip.
        if not _REQUESTS_AVAILABLE:
            return
        # If we have no ReDoS check URL, skip.
        if not self.redos_server:
            return

        for pattern, modifier in self._regexes(directive):
            self._recheck(directive, pattern, modifier)

    def _recheck(self, directive, regex_pattern, modifier):
        json_data = {"1": {"pattern": regex_pattern, "modifier": modifier}}

        # Attempt to contact the ReDoS check server.
        try:
            response = requests.post(
                self.redos_server,
                json=json_data,
                headers={"Content-Type": "application/json"},
                timeout=60,
            )
        except Exception:
            return

        # If we get a non-200 response, skip.
        if response.status_code != 200:
            return

        # Attempt to parse the JSON response.
        try:
            response_json = response.json()
        except ValueError:
            return

        # Ensure the expected data structure is present and matches the pattern.
        if (
            "1" not in response_json
            or response_json["1"] is None
            or "source" not in response_json["1"]
            or response_json["1"]["source"] != regex_pattern
        ):
            return

        recheck = response_json["1"]
        status = recheck.get("status")

        # If status is neither 'vulnerable' nor 'unknown', the expression is safe.
        if status not in ("vulnerable", "unknown"):
            return

        if status == "unknown":
            return

        # Status is 'vulnerable' here. Report as a high-severity issue.
        complexity_summary = recheck.get("complexity", {}).get("summary", "unknown")
        reason = f"Regex is vulnerable to {complexity_summary} ReDoS: {regex_pattern}."
        self.add_issue(directive=directive, reason=reason, severity=self.severity)
