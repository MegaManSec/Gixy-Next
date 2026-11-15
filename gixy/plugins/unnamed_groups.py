import re

import gixy
from gixy.core.regexp import Regexp
from gixy.plugins.plugin import Plugin


class unnamed_groups(Plugin):
    r"""
    Insecure example:
        location / {
            rewrite ^(.*) /new?c=1;
            set $myvar $1;
        }
    """

    summary = (
        "Rewrite with '?' followed by set/if/rewrite reading $N causes heap "
        "overflow (CVE-2026-42945)."
    )
    severity = gixy.severity.INFORMATION
    description = (
        "On nginx before 1.30.1/1.31.0, a `rewrite` with `?` in its replacement leaves argument "
        "escaping on, so a later `set`, `if` or `rewrite` that reads `$N` overflows a heap buffer "
        "(CVE-2026-42945). Upgrade nginx, or read a named capture (`$name`) instead of `$N`; this is "
        "INFORMATION because the nginx version is unknown."
    )
    help_url = "https://gixy.io/plugins/unnamed_groups/"
    directives = ["rewrite"]

    _TERMINATING_FLAGS = frozenset(("last", "break", "redirect", "permanent"))
    _REDIRECT_FLAGS = frozenset(("redirect", "permanent"))
    # An `http://` / `https://` / `$scheme` prefix on the replacement is
    # an implicit redirect, which halts the engine on match.
    _REDIRECT_PREFIXES = ("http://", "https://", "$scheme")
    _IF_FILE_OPS = frozenset(("-f", "-d", "-e", "-x", "!-f", "!-d", "!-e", "!-x"))
    _REGEX_OPERATORS = frozenset(("~", "~*", "!~", "!~*"))
    # nginx parses only single-digit `$1`..`$9`.
    _NUMERIC_CAPTURE = re.compile(r"\$([1-9])")
    _NGINX_VARIABLE = re.compile(r"\$[A-Za-z_]\w*|\$\{[^}]+\}")

    def audit(self, directive):
        if len(directive.args) < 2 or "?" not in self._replacement(directive):
            return

        # A rewrite that halts on match cannot be followed by an
        # observable `set`/`if` execution.
        if self._rewrite_is_terminator(directive):
            return

        groups = self._groups(directive.args[0])
        node = directive
        parent = node.parent
        while parent:
            past_self = False
            for sibling in parent.children:
                if sibling is node:
                    past_self = True
                    continue
                if not past_self:
                    continue
                # `return` and standalone `break;` unconditionally halt
                # the rewrite-phase engine; nothing after them runs.
                if self._unconditional_terminator(sibling):
                    return
                if self._has_vulnerable_complex_value(sibling, groups):
                    self.add_issue(
                        directive=directive,
                        reason=(
                            "A `rewrite` with `?` in its replacement is followed "
                            "by a `set`, `if` or `rewrite` directive that reads "
                            "a numeric capture group. On unpatched nginx "
                            "(< 1.30.1/1.31.0) this causes a heap buffer overflow "
                            "(CVE-2026-42945)."
                        ),
                    )
                    return
                groups = self._groups_after(sibling, groups)
            # Walk outward through grouping blocks (if/include/map/geo)
            # but stop at real scope boundaries. The args flag persists
            # across an if-block exit, so a `set $N` placed after the
            # enclosing if-block is still affected.
            if not parent.is_block or parent.self_context:
                break
            node = parent
            parent = parent.parent

    def _rewrite_is_terminator(self, directive):
        if len(directive.args) > 2 and directive.args[2].lower() in self._TERMINATING_FLAGS:
            return True
        return directive.args[1].startswith(self._REDIRECT_PREFIXES)

    def _rewrite_redirects(self, directive):
        if len(directive.args) > 2 and directive.args[2].lower() in self._REDIRECT_FLAGS:
            return True
        return directive.args[1].startswith(self._REDIRECT_PREFIXES)

    @staticmethod
    def _replacement(directive):
        replacement = directive.args[1]
        return replacement[:-1] if replacement.endswith("?") else replacement

    @staticmethod
    def _groups(pattern):
        try:
            return {group for group in Regexp(pattern).groups if isinstance(group, int)}
        except Exception:
            return None

    def _is_regex_if(self, node):
        return node.name == "if" and len(node.args) == 3 and node.args[1] in self._REGEX_OPERATORS

    def _groups_after(self, node, groups):
        if node.name == "rewrite":
            return set() if len(node.args) >= 2 and self._rewrite_is_terminator(node) else None
        if self._is_regex_if(node):
            return None
        if node.is_block and not node.self_context:
            inner = groups
            for child in node.children:
                inner = self._groups_after(child, inner)
            return None if groups is None or inner is None else groups | inner
        return groups

    def _unconditional_terminator(self, node):
        if node.name == "return":
            return True
        return node.name == "break" and not node.is_block

    def _has_vulnerable_complex_value(self, node, groups):
        if self._direct_complex_value(node, groups):
            return True
        if node.is_block and not node.self_context:
            if self._is_regex_if(node):
                groups = None
            for child in node.children:
                if self._has_vulnerable_complex_value(child, groups):
                    return True
                groups = self._groups_after(child, groups)
        return False

    def _reads_capture(self, value, groups):
        refs = {int(ref) for ref in self._NUMERIC_CAPTURE.findall(value)}
        return bool(refs) and (groups is None or bool(refs & groups))

    def _direct_complex_value(self, node, groups):
        if node.name == "set" and len(node.args) >= 2:
            return self._reads_capture(node.args[1], groups)
        if node.name == "if":
            if len(node.args) >= 3 and node.args[1] in ("=", "!="):
                return self._reads_capture(node.args[2], groups)
            if len(node.args) >= 2 and node.args[0] in self._IF_FILE_OPS:
                return self._reads_capture(node.args[1], groups)
        if node.name == "rewrite" and len(node.args) >= 2 and not self._rewrite_redirects(node):
            replacement = self._replacement(node)
            refs = self._NUMERIC_CAPTURE.findall(replacement)
            if self._NGINX_VARIABLE.search(replacement) or len(refs) != len(set(refs)):
                return self._reads_capture(replacement.split("?", 1)[0], self._groups(node.args[0]))
        return False
