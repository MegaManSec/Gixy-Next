from itertools import takewhile
from urllib.parse import urlparse

import gixy
import gixy.core.sre_parse.sre_parse as sre_parse
from gixy.core.regexp import PARSE_ERRORS, Regexp
from gixy.core.utils import PASS_DIRECTIVES
from gixy.core.variable import compile_hash_entry, compile_script, memoize_query
from gixy.directives.directive import MapDirective, RewriteDirective
from gixy.plugins.plugin import Plugin

DECODED_PATH_VARS = frozenset({"uri", "document_uri"})


def _flatten(seq, group=None):
    for op, av in seq:
        if op == sre_parse.SUBPATTERN:
            yield from _flatten(av[-1], group if av[0] is None else av[0])
        else:
            yield op, av, group


def _is_literal(token):
    """A literal, or an optional one such as `/?`."""
    op, av, _ = token
    return op == sre_parse.LITERAL or (
        op == sre_parse.MAX_REPEAT and av[:2] == (0, 1) and all(o == sre_parse.LITERAL for o, _ in av[2])
    )


def _is_rest(token, end_anchored):
    """`.*` or `.*?`; before a `$` only `[\\s\\S]*`, as `.` stops at a decoded `%0A`."""
    op, av, _ = token
    return (
        op in (sre_parse.MAX_REPEAT, sre_parse.MIN_REPEAT)
        and av[:2] == (0, sre_parse.MAXREPEAT)
        and len(av[2]) == 1
        and av[2][0][0] in ((sre_parse.ANY_ALL,) if end_anchored else (sre_parse.ANY, sre_parse.ANY_ALL))
    )


def _rest_capture(pattern, prefix):
    """For a `rewrite` regex that matches every URI under `prefix`, the literal it matches, the group capturing the
    rest and the literal that capture starts with: ("/api", 1, "") for `^/api(.*)`, ("/api/", 1, "/") for
    `^/api(/.*)`, ("", None, "") for `^`; otherwise None."""
    try:
        seq = list(_flatten(Regexp(pattern).parsed))
    except PARSE_ERRORS:
        return None
    anchored = bool(seq) and seq[0][:2] == (sre_parse.AT, sre_parse.AT_BEGINNING)
    end_anchored = bool(seq) and seq[-1][:2] == (sre_parse.AT, sre_parse.AT_END)
    seq = seq[anchored:len(seq) - end_anchored]
    head = list(takewhile(_is_literal, seq))
    rest = seq[len(head):]
    if (end_anchored and not rest) or not all(_is_rest(token, end_anchored) for token in rest):
        return None
    literal = "".join(chr(av) for op, av, _ in head if op == sre_parse.LITERAL)
    if not (prefix.startswith(literal) if anchored else literal in prefix):
        return None
    group = rest[0][2] if rest else None
    inner = "".join(chr(av) for op, av, g in head if op == sre_parse.LITERAL and g == group)
    return literal, group, inner


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

        location /api {
            rewrite ^/api(.*) /$1 break;
            fastcgi_pass 127.0.0.1:9000;
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
    directives = PASS_DIRECTIVES

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
        if isinstance(provider, MapDirective):
            return provider.block.source.lstrip("$") in DECODED_PATH_VARS
        if isinstance(var.value, list):
            return any(
                cls._carries_decoded_path(dep) for entry in var.value for dep in compile_hash_entry(entry) or ()
            )
        if provider.name == "set":
            return any(
                cls._carries_decoded_path(dep)
                for dep in var.depends or ()
                if not (isinstance(dep.name, int) and provider.escapes_captures)
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

        if directive.name != "proxy_pass":
            self._audit_uri_part(directive, effective_location, None)
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

    @staticmethod
    def _host_has_uri(host_vars):
        return any(v.can_contain("/") or v.must_contain("/") for v in host_vars)

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
            if "$" not in path and not self._host_has_uri(host_vars):
                self.add_issue(
                    directive=issue_directives,
                    severity=gixy.severity.LOW,
                    reason=(
                        "`rewrite ^ $request_uri` sets the URI to the raw request path, which "
                        "`proxy_pass` escapes again, so `%2F` reaches the upstream as `%252F`."
                    ),
                )
        elif ("$" not in directive.arg(0) or not path) and not self._host_has_uri(host_vars):
            self._audit_uri_part(directive, location, path or None)

    @staticmethod
    def _rewritten_in_place(location):
        """The unconditional `rewrite ... break` (or `rewrite` and later `break`) in the location or its server that
        makes NGINX send the rewritten URI upstream and ignore the URI part of `proxy_pass`, with its rest capture,
        or None."""
        scopes = [location] + [parent for parent in location.parents if parent.name == "server"][:1]
        for scope in scopes:
            for i, child in enumerate(scope.children):
                if isinstance(child, RewriteDirective) and child.flag in (None, "break"):
                    if child.redirects:
                        break
                    capture = _rest_capture(child.pattern, location.path)
                    if capture and (
                        child.flag == "break" or any(later.name == "break" for later in scope.children[i + 1:])
                    ):
                        return child, capture
                if child.name in ("break", "return") or (
                    child.name == "if" and any(inner.name == "break" for inner in child.children)
                ):
                    break
        return None

    def _audit_uri_part(self, directive, location, uri):
        if location.modifier not in (None, "^~") or location.path.startswith("@") or directive.parent is not location:
            return
        directives, what = [directive], "`proxy_pass` URI"
        rewritten = self._rewritten_in_place(location)
        if rewritten is not None:
            rewrite, (literal, group, inner) = rewritten
            uri, sep, _ = rewrite.replace.partition("$%s" % group)
            if group is None or not sep or "$" in uri or not location.path.endswith(literal):
                return
            if rewrite.parent is not location and not uri.startswith(location.path):
                return
            uri += inner
            directives.append(rewrite)
            what = "`rewrite` replacement"
        if uri is None or location.path.endswith("/") == uri.endswith("/"):
            return

        if uri.endswith("/"):
            severity = gixy.severity.MEDIUM
            reason = (
                "Location `{loc}` has no trailing slash but the {what} `{uri}` does, "
                "so `{name}` sends `{loc}../x` upstream as `{uri}../x`."
            )
        else:
            severity = gixy.severity.LOW
            reason = (
                "Location `{loc}` ends with a slash but the {what} `{uri}` does not, "
                "so `{name}` sends `{loc}x` upstream as `{uri}x`."
            )
        self.add_issue(
            directive=directives,
            severity=severity,
            reason=reason.format(loc=location.path, what=what, uri=uri, name=directive.name),
        )
