import re

import gixy
from gixy.plugins.plugin import Plugin


class overlapping_captures(Plugin):
    r"""
    Insecure example:
        location / {
            rewrite ^/((.*))$ http://127.0.0.1:8080/$1$2 redirect;
        }
    """

    summary = (
        "Rewrite with overlapping captures in redirect/args context — heap overflow "
        "(CVE-2026-9256)."
    )
    severity = gixy.severity.INFORMATION
    description = (
        "CVE-2026-9256 is a bug in nginx itself: when a `rewrite` regex contains overlapping "
        "(nested) unnamed captures and its replacement references multiple of those captures "
        "by `$N` in a redirect or arguments context, nginx allocates a buffer sized for the "
        "raw capture bytes but writes URI-escaped bytes — which can be several times longer "
        "— overflowing the buffer. On unpatched nginx (< 1.30.2/1.31.1) a crafted request "
        "triggers a heap buffer overflow in the worker process. The only real fix is "
        "upgrading nginx. Replacing the unnamed captures with named captures "
        "(`(?<name>...)`) removes the vulnerable pattern and is also clearer to read and "
        "maintain. Because Gixy-Next cannot determine the nginx version from the "
        "configuration, any matching pattern is reported as INFORMATION — if you are already "
        "on a patched version, no action is required."
    )
    help_url = "https://gixy.io/plugins/overlapping_captures/"
    directives = ["rewrite"]

    _REDIRECT_FLAGS = frozenset(("redirect", "permanent"))
    _NUMERIC_CAPTURE = re.compile(r"\$(\d+)")
    # nginx variable refs ($name / ${name}) — never a numeric capture, since
    # the unbraced form requires a non-digit first character.
    _NGINX_VARIABLE = re.compile(r"\$[A-Za-z_]\w*|\$\{[^}]+\}")

    def audit(self, directive):
        if len(directive.args) < 2:
            return

        regex = directive.args[0]
        replacement = directive.args[1]
        flag = directive.args[2].lower() if len(directive.args) > 2 else ""

        # The vulnerable code path is only reached when the replacement causes
        # nginx to enter args/redirect mode — either a `?` somewhere in the
        # replacement, or an external-redirect flag.
        if "?" not in replacement and flag not in self._REDIRECT_FLAGS:
            return

        # A replacement containing any nginx variable ($host, ${uri}, …) takes
        # a different length-calc path (code->lengths != NULL) that was not
        # affected by the overflow.
        if self._NGINX_VARIABLE.search(replacement):
            return

        # The bug needs at least two distinct numeric capture references in
        # the replacement — that is what makes the overlapping captures bite.
        distinct = set(self._NUMERIC_CAPTURE.findall(replacement))
        if len(distinct) < 2:
            return

        # And the regex itself must actually contain overlapping captures —
        # one unnamed group nested inside another.
        if not self._has_nested_unnamed_captures(regex):
            return

        self.add_issue(
            directive=directive,
            reason=(
                "A `rewrite` regex with nested unnamed captures and a replacement that "
                "references multiple `$N` captures runs in redirect or arguments context — "
                "on unpatched nginx (< 1.30.2/1.31.1) this causes a heap buffer overflow "
                "(CVE-2026-9256)."
            ),
        )

    @staticmethod
    def _has_nested_unnamed_captures(regex):
        """Return True if any unnamed capture group is nested inside another.

        Walks the regex string tracking paren kind — an unnamed-capturing `(`
        versus anything that starts with `(?` (non-capturing, named,
        lookaround, …). The CVE only triggers on overlapping *unnamed*
        captures, since named captures are referenced by name (not `$N`).
        """
        stack = []  # entries: True iff that '(' opened an unnamed capture
        open_unnamed = 0
        i = 0
        n = len(regex)
        while i < n:
            c = regex[i]
            if c == "\\":
                # Skip the escape and the escaped character
                i += 2
                continue
            if c == "[":
                # Skip a character class, honoring internal escapes
                i += 1
                while i < n:
                    if regex[i] == "\\":
                        i += 2
                        continue
                    if regex[i] == "]":
                        i += 1
                        break
                    i += 1
                continue
            if c == "(":
                is_unnamed = not (i + 1 < n and regex[i + 1] == "?")
                stack.append(is_unnamed)
                if is_unnamed:
                    open_unnamed += 1
                    if open_unnamed >= 2:
                        return True
            elif c == ")":
                if stack and stack.pop():
                    open_unnamed -= 1
            i += 1
        return False
