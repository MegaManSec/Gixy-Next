import re
import string

import gixy
import gixy.core.sre_parse.sre_parse as sre_parse
from gixy.core.regexp import (
    AtToken,
    BranchToken,
    GroupRefToken,
    InternalSubpatternToken,
    LiteralToken,
    MaxRepeatToken,
    MinRepeatToken,
    Regexp,
    RegexpTooComplex,
    SubpatternToken,
)
from gixy.core.utils import default_listens, parse_listen_key_and_default, resolve_inherited_single
from gixy.core.variable import compile_script
from gixy.plugins.plugin import Plugin


HOST_NAME_CHARS = string.ascii_lowercase + string.digits + "-."
LABEL_CHARS = HOST_NAME_CHARS.replace(".", "")
END_ANCHOR_RE = re.compile(r"(?<!\\)((?:\\\\)*)\\[zZ]")


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


def _flatten(tokens):
    """Every way to read `tokens` as a list of literal characters and other tokens."""
    results = [[]]
    for token in tokens:
        if isinstance(token, LiteralToken):
            options = [[token.char.lower()]]
        elif isinstance(token, (SubpatternToken, InternalSubpatternToken)):
            options = _flatten(token.childs)
        elif isinstance(token, BranchToken):
            options = [items for child in token.childs for items in _flatten(child.childs or [])]
        else:
            options = [[token]]
        results = [done + items for done in results for items in options]
        if len(results) > 256:
            raise RegexpTooComplex()
    return results


def _can_contain(token, char):
    return token.can_contain(char, skip_literal=False) or token.can_contain(char.upper(), skip_literal=False)


def _walk(items, labels):
    """Which labels, counted from the end of the name, the text left of `items` can belong to when
    `items` is read right to left from `labels`; True once the label before the last can be chosen by
    the client."""
    for item in items:
        if isinstance(item, AtToken):
            if item.begin:
                return set()
            continue
        if isinstance(item, (MaxRepeatToken, MinRepeatToken, GroupRefToken)):
            labels = _repeat(item, labels)
        else:
            if isinstance(item, str):
                dot, label, fixed = item == ".", item != ".", True
            else:
                dot = _can_contain(item, ".")
                label = any(_can_contain(item, char) for char in LABEL_CHARS)
                fixed = False
            if not dot and not label:
                continue
            if label and not fixed and 2 in labels:
                return True
            following = {2} if dot and 1 in labels else set()
            if label:
                following |= labels
            labels = following
        if labels is True or not labels:
            return labels
    return labels


def _repeat(token, labels):
    if isinstance(token, GroupRefToken):
        options, low, high = _flatten(token.group.root.childs), 1, 1
    else:
        options, low, high = _flatten(token.childs), token.min, token.max
    result = labels if low == 0 else set()
    for count in range(1, min(high, low + 4) + 1):
        following = set()
        for items in options:
            step = _walk(reversed(items), labels)
            if step is True:
                return True
            following |= step
        labels = following
        if count >= low:
            result |= labels
        if not labels:
            break
    return result


def _open_tail(items):
    """True if a name matched by `items` can end in a domain the client registers: one where the label
    before the last is not fixed."""
    if not items or not (isinstance(items[-1], AtToken) and items[-1].end):
        return True
    labels = _walk(reversed(items[:-1]), {1})
    return labels is True or bool(labels)


def _is_open_suffix_name(name):
    """A `server_name` such as `example.*`, `~^api\\.` or `~^api\\.(.+)$` that also matches names under a domain
    the client registers."""
    if not name.startswith("~"):
        return name.endswith(".*")
    try:
        regexp = Regexp(END_ANCHOR_RE.sub(r"\1$", name[1:]), case_sensitive=False)
        return any(_open_tail(items) for items in _flatten(regexp.root.childs))
    except (sre_parse.error, OverflowError, RecursionError, RegexpTooComplex):
        return False


def _depends_on_host(var):
    if var.name == "host":
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
