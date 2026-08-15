import re

import gixy
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
        "Rewrite with '?' followed by set/if referencing $N causes heap "
        "overflow (CVE-2026-42945)."
    )
    severity = gixy.severity.INFORMATION
    description = (
        "CVE-2026-42945 is a bug in nginx itself: a `rewrite` replacement containing "
        "`?` sets an args-escaping flag on the script engine that is not cleared "
        "afterwards. On unpatched nginx (< 1.30.1/1.31.0), a subsequent `set $var $N` "
        "or `if` that reads a numeric capture ($1, $2, ...) allocates a buffer sized "
        "for raw bytes but writes URI-escaped bytes, causing a heap buffer overflow. "
        "The only real fix is upgrading nginx. As a workaround, remove the `$N` "
        "reference from the affected `set` or `if`: convert the regex's unnamed "
        "capture to a named one (`(?<name>...)`) and reference it by `$name`. PCRE "
        "numbers named captures alongside unnamed ones, so renaming the regex group "
        "alone is not enough. Because Gixy-Next cannot determine the nginx version "
        "from the configuration, any matching pattern is reported as INFORMATION. "
        "If you are already on a patched version, no action is required."
    )
    help_url = "https://gixy.io/plugins/unnamed_groups/"
    directives = ["rewrite"]

    _TERMINATING_FLAGS = frozenset(("last", "break", "redirect", "permanent"))
    # An `http://` / `https://` / `$scheme` prefix on the replacement is
    # an implicit redirect, which halts the engine on match.
    _REDIRECT_PREFIXES = ("http://", "https://", "$scheme")
    _IF_FILE_OPS = frozenset(("-f", "-d", "-e", "-x", "!-f", "!-d", "!-e", "!-x"))
    # nginx parses only single-digit `$1`..`$9`.
    _NUMERIC_CAPTURE = re.compile(r"\$[1-9]")

    def audit(self, directive):
        if len(directive.args) < 2 or "?" not in directive.args[1]:
            return

        # A rewrite that halts on match cannot be followed by an
        # observable `set`/`if` execution.
        if self._rewrite_is_terminator(directive):
            return

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
                if self._has_vulnerable_complex_value(sibling):
                    self.add_issue(
                        directive=directive,
                        reason=(
                            "A `rewrite` with `?` in its replacement is followed "
                            "by a `set` or `if` directive whose value references "
                            "a numeric capture group. On unpatched nginx "
                            "(< 1.30.1/1.31.0) this causes a heap buffer overflow "
                            "(CVE-2026-42945)."
                        ),
                    )
                    return
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

    def _unconditional_terminator(self, node):
        if node.name == "return":
            return True
        return node.name == "break" and not node.is_block

    def _has_vulnerable_complex_value(self, node):
        if self._direct_complex_value(node):
            return True
        if node.is_block and not node.self_context:
            return any(self._has_vulnerable_complex_value(child) for child in node.children)
        return False

    def _direct_complex_value(self, node):
        if node.name == "set" and len(node.args) >= 2:
            return bool(self._NUMERIC_CAPTURE.search(node.args[1]))
        if node.name == "if":
            if node.args and self._NUMERIC_CAPTURE.search(node.args[0]):
                return True
            if len(node.args) >= 3 and node.args[1] in ("=", "!="):
                return bool(self._NUMERIC_CAPTURE.search(node.args[2]))
            if len(node.args) >= 2 and node.args[0] in self._IF_FILE_OPS:
                return bool(self._NUMERIC_CAPTURE.search(node.args[1]))
        return False
