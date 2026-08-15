from urllib.parse import urlparse

import gixy
from gixy.core.variable import EXTRACT_RE
from gixy.plugins.plugin import Plugin

MITIGATION_VARS = frozenset({"uri", "1", "2", "3", "4", "5", "6", "7", "8", "9"})


class proxy_pass_normalized(Plugin):
    r"""
    This plugin detects if there is any path component (slash or more)
    after the host in a proxy_pass directive.
    Example flagged directives:
        proxy_pass http://backend/;
        proxy_pass http://backend/foo/bar;
    """

    summary = "proxy_pass path normalization issues."
    severity = gixy.severity.MEDIUM
    description = "A path (beginning with a slash) after the host in proxy_pass leads to unexpected encoding."
    help_url = "https://gixy.io/plugins/proxy_pass_normalized/"
    directives = ["proxy_pass"]

    @staticmethod
    def _has_mitigation_variable(script):
        return any(
            name.strip("{}").lower() in MITIGATION_VARS
            for name in EXTRACT_RE.findall(script)
        )

    @staticmethod
    def _is_conditional(rewrite):
        for parent in rewrite.parents:
            if parent.self_context:
                return False
            if parent.name == "if":
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

        proxy_pass_args = directive.args

        if proxy_pass_args[0].startswith("$") and "/" not in proxy_pass_args[0]:
            # If proxy pass destination is defined by only a variable, it is not possible to check for path normalization issues
            return

        parsed = urlparse(proxy_pass_args[0])

        host = parsed.netloc
        path = parsed.path
        if host == "unix:":
            path_parts = path.split(":", 1)
            host = path_parts[0]
            path = path_parts[1] if len(path_parts) > 1 else ""

        rewritten = None

        for rewrite in directive.find_declarative_directives_in_scope("rewrite"):
            if self._is_conditional(rewrite):
                continue
            if rewrite.pattern == "^" and rewrite.replace.lower() == "$request_uri":
                # Check for $uri or any numbered variable in the path.
                if self._has_mitigation_variable(path if path else host):
                    return
                rewritten = rewrite
                break

        if not path and not rewritten:
            return

        self.add_issue(
            directive=[directive] + ([rewritten] if rewritten is not None else []),
            reason=(
                "A path is present after the host in `proxy_pass` without using `$request_uri` and a variable (for example, `$1` or `$uri`). "
                "This can lead to path decoding or double-encoding issues."
            ),
        )
