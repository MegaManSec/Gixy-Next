from urllib.parse import urlparse

import gixy
import gixy.core.sre_parse.sre_parse as sre_parse
from gixy.core.regexp import Regexp
from gixy.core.variable import compile_script, memoize_query
from gixy.directives.directive import RewriteDirective
from gixy.plugins.plugin import Plugin

DECODED_PATH_VARS = frozenset({"uri", "document_uri"})


def _matches_every_uri(pattern, prefix):
    """True if `pattern` matches every URI starting with `prefix`, as `^`, `^(.*)` and `^/api(.*)` do for `/api`."""
    try:
        seq = list(Regexp(pattern).parsed)
    except (sre_parse.error, OverflowError, RecursionError):
        return False
    if not seq or seq[0] != (sre_parse.AT, sre_parse.AT_BEGINNING):
        return False
    literal = ""
    rest = seq[1:]
    while rest and rest[0][0] == sre_parse.LITERAL:
        literal += chr(rest[0][1])
        rest = rest[1:]
    anchored = bool(rest) and rest[-1] == (sre_parse.AT, sre_parse.AT_END)
    if anchored:
        rest = rest[:-1]
        if not rest:
            return False
    if len(rest) == 1 and rest[0][0] == sre_parse.SUBPATTERN:
        rest = list(rest[0][1][-1])
    any_char = (sre_parse.ANY_ALL,) if anchored else (sre_parse.ANY, sre_parse.ANY_ALL)
    return prefix.startswith(literal) and all(
        op in (sre_parse.MAX_REPEAT, sre_parse.MIN_REPEAT)
        and av[:2] == (0, sre_parse.MAXREPEAT)
        and len(av[2]) == 1
        and av[2][0][0] in any_char
        for op, av in rest
    )


class proxy_pass_normalized(Plugin):
    r"""
    Insecure examples:
        location /api {
            proxy_pass http://backend/v1/;
        }

        location ~ ^/img/(.*\.png)$ {
            proxy_pass http://backend/$1;
        }

        location /1/ {
            rewrite ^ $request_uri;
            rewrite ^/1(/.*) $1 break;
            return 400;
            proxy_pass http://backend;
        }
    """

    summary = "proxy_pass can send an unintended path upstream."
    severity = gixy.severity.MEDIUM
    description = (
        "The path `proxy_pass` sends upstream can differ from the one NGINX matched when the location and "
        "the `proxy_pass` URI disagree on a trailing slash, when `$uri` or a regex capture is sent decoded "
        "and unescaped, or when a raw path from `rewrite ^ $request_uri` is escaped twice."
    )
    help_url = "https://gixy.io/plugins/proxy_pass_normalized/"
    directives = ["proxy_pass"]

    @classmethod
    @memoize_query
    def _carries_decoded_path(cls, var):
        if var.alternatives:
            return any(cls._carries_decoded_path(option) for option in var.alternatives)
        provider = var.provider
        if provider is None:
            return var.name in DECODED_PATH_VARS
        if provider.name in ("location", "rewrite"):
            return True
        if provider.name == "if":
            return provider.variable.lstrip("$") in DECODED_PATH_VARS
        if provider.name == "map":
            return provider.source.lstrip("$") in DECODED_PATH_VARS
        if provider.name == "set":
            # nginx re-escapes numbered captures copied by `set`, but not named ones
            return any(
                cls._carries_decoded_path(dep)
                for dep in var.depends or ()
                if not isinstance(dep.name, int)
            )
        return False

    @classmethod
    def _sends_decoded_path(cls, var):
        return cls._carries_decoded_path(var) and any(
            var.can_contain(c) for c in "?#%"
        )

    @staticmethod
    def _is_conditional(rewrite, directive):
        scopes = list(directive.parents)
        for parent in rewrite.parents:
            if parent.self_context:
                return False
            if parent.name == "if" and parent not in scopes:
                return True
        return False

    def audit(self, directive):
        parent = directive.parent

        if not parent:
            return

        # Only analyze HTTP context: inside location, or inside if/limit_except within location.
        # This avoids false positives for the stream module, where proxy_pass has different semantics.
        effective_location = None
        if parent.name == "location":
            effective_location = parent
        elif parent.name in ["limit_except", "if"]:
            grandparent = parent.parent
            if grandparent and grandparent.name == "location":
                effective_location = grandparent

        if not effective_location:
            # Not in HTTP location context -> skip
            return

        # Skip exact-match locations where normalization concerns do not apply
        if effective_location.modifier == "=":
            return

        # proxy_pass requires an upstream argument; its absence is malformed
        # input (handled gracefully), not a crash.
        proxy_pass_arg = directive.arg(0)

        if proxy_pass_arg.startswith("$") and "/" not in proxy_pass_arg:
            # If proxy pass destination is defined by only a variable, it is not
            # possible to check for path normalization issues
            return

        parsed = urlparse(proxy_pass_arg)

        host = parsed.netloc
        path = parsed.path
        if host == "unix:":
            path_parts = path.split(":", 1)
            host = path_parts[0]
            path = path_parts[1] if len(path_parts) > 1 else ""

        path_vars = [v for v in compile_script(path) if v.name]
        host_vars = [v for v in compile_script(host) if v.name]
        decoded = any(self._sends_decoded_path(v) for v in path_vars) or any(
            self._sends_decoded_path(v) and v.can_contain("/") for v in host_vars
        )

        rewritten = None

        for rewrite in directive.find_declarative_directives_in_scope("rewrite"):
            if rewrite.pattern == "^" and rewrite.replace.lower() == "$request_uri":
                if self._is_conditional(rewrite, directive):
                    rewritten = rewritten or rewrite
                    continue
                if decoded:
                    return
                rewritten = rewrite
                break

        self._report(directive, effective_location, path, host_vars, decoded, rewritten)

    def _report(self, directive, location, path, host_vars, decoded, rewritten):
        issue_directives = [directive] + ([rewritten] if rewritten is not None else [])
        if decoded:
            self.add_issue(
                directive=issue_directives,
                severity=gixy.severity.MEDIUM,
                reason=(
                    "The `proxy_pass` URI is built from the decoded request path, which is sent "
                    "without being escaped again, so `%3F` reaches the upstream as `?`."
                ),
            )
        elif rewritten is not None:
            if "$" not in path and not any(v.can_contain("/") for v in host_vars):
                self.add_issue(
                    directive=issue_directives,
                    severity=gixy.severity.LOW,
                    reason=(
                        "`rewrite ^ $request_uri` sets the URI to the raw request path, which "
                        "`proxy_pass` escapes again, so `%2F` reaches the upstream as `%252F`."
                    ),
                )
        elif path and "$" not in directive.arg(0) and directive.parent is location:
            self._audit_uri_part(directive, location, path)

    @staticmethod
    def _rewritten_in_place(location):
        """True if every request goes through an unconditional `rewrite ... break`, or a `rewrite` and then `break`,
        in the location or its server, which make NGINX ignore the URI part of `proxy_pass`."""
        scopes = [location] + [parent for parent in location.parents if parent.name == "server"][:1]
        for scope in scopes:
            for i, child in enumerate(scope.children):
                rewrite = isinstance(child, RewriteDirective)
                if rewrite and _matches_every_uri(child.pattern, location.path):
                    if child.flag == "break":
                        return True
                    if child.flag is None and any(later.name == "break" for later in scope.children[i + 1:]):
                        return True
                if child.name in ("break", "return", "if") or (rewrite and child.flag):
                    break
        return False

    def _audit_uri_part(self, directive, location, uri):
        if location.modifier not in (None, "^~") or location.path.startswith("@"):
            return
        if location.path.endswith("/") == uri.endswith("/"):
            return
        if self._rewritten_in_place(location):
            return

        if uri.endswith("/"):
            severity = gixy.severity.MEDIUM
            reason = (
                "Location `{loc}` has no trailing slash but the `proxy_pass` URI `{uri}` does, "
                "so `{loc}../x` is sent upstream as `{uri}../x`."
            )
        else:
            severity = gixy.severity.LOW
            reason = (
                "Location `{loc}` ends with a slash but the `proxy_pass` URI `{uri}` does not, "
                "so `{loc}x` is sent upstream as `{uri}x`."
            )
        self.add_issue(
            directive=directive,
            severity=severity,
            reason=reason.format(loc=location.path, uri=uri),
        )
