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

    summary = "Rewrite with '?' followed by set $N — heap overflow (CVE-2026-42945)."
    severity = gixy.severity.INFORMATION
    description = (
        "CVE-2026-42945 is a bug in nginx itself: a `rewrite` replacement containing `?` sets "
        "an args-escaping flag on the script engine that is not cleared afterwards. On unpatched "
        "nginx (< 1.30.1/1.31.0), a subsequent `set` referencing a numeric capture ($1, $2, …) "
        "then allocates a buffer sized for raw bytes but writes URI-escaped bytes, causing a heap "
        "buffer overflow. The only real fix is upgrading nginx. Replacing numeric captures with "
        "named captures (`(?<name>...)`) works around the CVE on unpatched versions and is also "
        "clearer to read and maintain. Because Gixy-Next cannot determine the nginx version from "
        "the configuration, any matching pattern is reported as INFORMATION — if you are already "
        "on a patched version, no action is required."
    )
    help_url = "https://gixy.io/plugins/unnamed_groups/"
    directives = ["rewrite"]

    _TERMINATING_FLAGS = frozenset(("last", "break", "redirect", "permanent"))
    _NUMERIC_CAPTURE = re.compile(r"\$[1-9]\d*")

    def audit(self, directive):
        if len(directive.args) < 2 or "?" not in directive.args[1]:
            return

        # last/break/redirect/permanent insert a NULL opcode terminator after
        # regex_end_code, so the engine halts there — subsequent set directives
        # in the same block are never executed when the rewrite matches.
        if len(directive.args) > 2 and directive.args[2].lower() in self._TERMINATING_FLAGS:
            return

        # Walk outward through grouping blocks (if/include/map/geo) so that a
        # `set $N` placed after the enclosing if-block — or any other non-scope
        # boundary — is still detected. The script-engine args flag persists
        # across the if exit, so the canonical trigger fires there too.
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
                if self._has_set_with_capture(sibling):
                    self.add_issue(
                        directive=directive,
                        reason=(
                            "A `rewrite` with `?` in its replacement is followed by a `set` "
                            "directive referencing a numeric capture group — on unpatched nginx "
                            "(< 1.30.1/1.31.0) this causes a heap buffer overflow (CVE-2026-42945)."
                        ),
                    )
                    return
            if not getattr(parent, "is_block", False) or getattr(parent, "self_context", True):
                break
            node = parent
            parent = parent.parent

    def _has_set_with_capture(self, node):
        if node.name == "set" and len(node.args) >= 2:
            return bool(self._NUMERIC_CAPTURE.search(node.args[1]))
        if getattr(node, "is_block", False) and not getattr(node, "self_context", True):
            return any(self._has_set_with_capture(child) for child in node.children)
        return False
