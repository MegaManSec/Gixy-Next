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
        "Rewrite with '?' followed by set/if referencing $N — heap overflow "
        "(CVE-2026-42945)."
    )
    severity = gixy.severity.INFORMATION
    description = (
        "CVE-2026-42945 is a bug in nginx itself: a `rewrite` replacement containing "
        "`?` sets an args-escaping flag on the script engine that is not cleared "
        "afterwards. On unpatched nginx (< 1.30.1/1.31.0), a subsequent `set $var $N` "
        "or `if` that reads a numeric capture ($1, $2, …) allocates a buffer sized "
        "for raw bytes but writes URI-escaped bytes, causing a heap buffer overflow. "
        "The only real fix is upgrading nginx. As a workaround, remove the `$N` "
        "reference from the affected `set` or `if`: convert the regex's unnamed "
        "capture to a named one (`(?<name>...)`) and reference it by `$name`. PCRE "
        "numbers named captures alongside unnamed ones, so renaming the regex group "
        "alone is not enough. Because Gixy-Next cannot determine the nginx version "
        "from the configuration, any matching pattern is reported as INFORMATION — "
        "if you are already on a patched version, no action is required."
    )
    help_url = "https://gixy.io/plugins/unnamed_groups/"
    directives = ["rewrite"]

    _TERMINATING_FLAGS = frozenset(("last", "break", "redirect", "permanent"))
    # A replacement starting with one of these triggers an implicit redirect
    # (regex->redirect = 1, last = 1) in ngx_http_rewrite_module.c:354-361,
    # which appends a NULL opcode after the rewrite — the engine halts on match.
    _REDIRECT_PREFIXES = ("http://", "https://", "$scheme")
    # File-test operators that take a complex value (compiled via
    # ngx_http_rewrite_value → complex_value_code at line 801).
    _IF_FILE_OPS = frozenset(("-f", "-d", "-e", "-x", "!-f", "!-d", "!-e", "!-x"))
    # nginx only parses single-digit `$1`..`$9` (ngx_http_script.c:480-485).
    _NUMERIC_CAPTURE = re.compile(r"\$[1-9]")

    def audit(self, directive):
        if len(directive.args) < 2 or "?" not in directive.args[1]:
            return

        # If the rewrite itself halts on match (explicit terminating flag or
        # an implicit redirect via http:// / https:// / $scheme prefix), the
        # NULL opcode appended after `regex_end_code` stops the engine before
        # any subsequent directive in this codes array can execute.
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
                # `return` and standalone `break;` write
                # `e->ip = ngx_http_script_exit` unconditionally —
                # everything after them in the bytecode never runs.
                if self._unconditional_terminator(sibling):
                    return
                if self._has_vulnerable_complex_value(sibling):
                    self.add_issue(
                        directive=directive,
                        reason=(
                            "A `rewrite` with `?` in its replacement is followed "
                            "by a `set` or `if` directive whose value references "
                            "a numeric capture group — on unpatched nginx "
                            "(< 1.30.1/1.31.0) this causes a heap buffer overflow "
                            "(CVE-2026-42945)."
                        ),
                    )
                    return
            # Walk outward through grouping blocks (if / include / map / geo,
            # all `self_context = False`) but stop at real scope boundaries.
            # The script engine's args flag persists across `if` exit, so a
            # `set $N` placed after the enclosing if-block is still affected.
            if not getattr(parent, "is_block", False) or getattr(parent, "self_context", True):
                break
            node = parent
            parent = parent.parent

    @classmethod
    def _rewrite_is_terminator(cls, directive):
        """The rewrite halts the engine on match: explicit flag, or an
        implicit redirect from `http://` / `https://` / `$scheme` prefix
        on the replacement (ngx_http_rewrite_module.c:354-361 / 425-432)."""
        if len(directive.args) > 2 and directive.args[2].lower() in cls._TERMINATING_FLAGS:
            return True
        return directive.args[1].startswith(cls._REDIRECT_PREFIXES)

    @staticmethod
    def _unconditional_terminator(node):
        """Halts the rewrite-phase engine on every execution, regardless of
        any condition. Used to stop the sibling walk — anything after one
        of these never runs.

        A subsequent `rewrite` with a terminating flag or implicit redirect
        is intentionally NOT included here: its halt is conditional on the
        regex matching, which can't be reasoned about statically.
        """
        if node.name == "return":
            return True
        if node.name == "break" and not getattr(node, "is_block", False):
            return True
        return False

    @classmethod
    def _has_vulnerable_complex_value(cls, node):
        """True if this node (or, in a grouping block, any descendant) emits
        a `ngx_http_script_complex_value_code` whose source contains a
        numeric capture reference — that opcode is the runtime trigger of
        CVE-2026-42945, generated by:

        * `set $var VALUE`                         (rewrite_module.c:934)
        * `if ($var = VALUE)` / `if ($var != VALUE)`  (lines 718, 735)
        * `if (-f VALUE)` and other file operators (line 801)
        """
        if cls._direct_complex_value(node):
            return True
        if getattr(node, "is_block", False) and not getattr(node, "self_context", True):
            return any(cls._has_vulnerable_complex_value(child) for child in node.children)
        return False

    @classmethod
    def _direct_complex_value(cls, node):
        if node.name == "set" and len(node.args) >= 2:
            return bool(cls._NUMERIC_CAPTURE.search(node.args[1]))
        if node.name == "if":
            if len(node.args) >= 3 and node.args[1] in ("=", "!="):
                return bool(cls._NUMERIC_CAPTURE.search(node.args[2]))
            if len(node.args) >= 2 and node.args[0] in cls._IF_FILE_OPS:
                return bool(cls._NUMERIC_CAPTURE.search(node.args[1]))
        return False
