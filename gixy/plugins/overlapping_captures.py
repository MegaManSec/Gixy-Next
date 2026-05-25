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
        "(nested) captures and its replacement references multiple of those captures by "
        "`$N` in a redirect or arguments context, nginx allocates a buffer sized for the "
        "raw capture bytes but writes URI-escaped bytes — which can be several times "
        "longer — overflowing the buffer. On unpatched nginx (< 1.30.2/1.31.1) a crafted "
        "request triggers a heap buffer overflow in the worker process. The only real fix "
        "is upgrading nginx. As a workaround, remove the `$N` references from the "
        "replacement: convert the captures to named ones (`(?<name>...)`) and reference "
        "them by `$name` instead of `$N`. PCRE numbers named captures alongside unnamed "
        "ones, so switching the regex syntax alone is not enough — the replacement must "
        "stop using `$N`. Because Gixy-Next cannot determine the nginx version from the "
        "configuration, any matching pattern is reported as INFORMATION — if you are "
        "already on a patched version, no action is required."
    )
    help_url = "https://gixy.io/plugins/overlapping_captures/"
    directives = ["rewrite"]

    _REDIRECT_FLAGS = frozenset(("redirect", "permanent"))
    # A replacement starting with one of these prefixes triggers an implicit
    # redirect (regex->redirect = 1) without any explicit redirect/permanent
    # flag — see ngx_http_rewrite_module.c:354-361. `$scheme://` also does,
    # but a `$scheme` reference is a variable and we already bail out then.
    _IMPLICIT_REDIRECT_PREFIXES = ("http://", "https://")
    # nginx only parses single-digit `$1`..`$9` (ngx_http_script.c:480-485);
    # `$10` is `$1` followed by literal `0`.
    _NUMERIC_CAPTURE = re.compile(r"\$([1-9])")
    # nginx variable refs (`$name` / `${name}`) — never a numeric capture,
    # since the unbraced form requires a non-digit first character.
    _NGINX_VARIABLE = re.compile(r"\$[A-Za-z_]\w*|\$\{[^}]+\}")

    def audit(self, directive):
        if len(directive.args) < 2:
            return

        regex = directive.args[0]
        replacement = directive.args[1]
        flag = directive.args[2].lower() if len(directive.args) > 2 else ""

        # nginx strips a sole trailing `?` from the replacement (it means
        # "drop the original arguments"), so a trailing-only `?` never
        # enters runtime args mode — see ngx_http_rewrite_module.c:343-346.
        if replacement.endswith("?"):
            replacement = replacement[:-1]

        # A replacement that contains any `$name` / `${name}` variable goes
        # through nginx's lengths != NULL length-calc path, which uses
        # per-capture length code that is not vulnerable.
        if self._NGINX_VARIABLE.search(replacement):
            return

        # Redirect mode (e->quote = 1 at runtime) is entered either by an
        # explicit `redirect`/`permanent` flag, or implicitly when the
        # replacement starts with `http://` or `https://`. Either path
        # causes every `$N` in the replacement to be URI-escaped on output.
        is_redirect = (
            flag in self._REDIRECT_FLAGS
            or replacement.startswith(self._IMPLICIT_REDIRECT_PREFIXES)
        )

        # A duplicate `$N` reference anywhere in the replacement sets
        # sc.dup_capture = 1, which forces nginx onto its safe length-calc
        # path (ngx_http_script.c:486-488; ngx_http_rewrite_module.c:408).
        all_refs = self._NUMERIC_CAPTURE.findall(replacement)
        if len(all_refs) != len(set(all_refs)):
            return

        # Which `$N` references actually run in escape mode?
        #   - redirect:  every `$N` (e->quote = 1 covers the whole buffer).
        #   - non-redirect: only `$N`s after the first `?`, where
        #     ngx_http_script_start_args_code sets e->is_args = 1. Refs
        #     before the `?` are written raw and cannot overflow on their
        #     own — a single-escaped capture stays within the buggy
        #     `escape(URI)` budget.
        if is_redirect:
            escaped_refs = all_refs
        else:
            q_idx = replacement.find("?")
            if q_idx < 0:
                return
            escaped_refs = self._NUMERIC_CAPTURE.findall(replacement[q_idx + 1:])

        referenced = {int(n) for n in escaped_refs}
        if len(referenced) < 2:
            return

        if not self._referenced_captures_overlap(regex, referenced):
            return

        self.add_issue(
            directive=directive,
            reason=(
                "A `rewrite` regex with overlapping captures and a replacement that "
                "references multiple `$N` captures runs in redirect or arguments "
                "context — on unpatched nginx (< 1.30.2/1.31.1) this causes a heap "
                "buffer overflow (CVE-2026-9256)."
            ),
        )

    @classmethod
    def _referenced_captures_overlap(cls, regex, referenced):
        """Return True iff any pair of *referenced* capture groups is
        syntactically nested (one is an ancestor of the other).

        PCRE numbers named and unnamed captures into the same sequence,
        so `$1` works for `(?<name>...)` just as for `(...)`. Sibling
        capture pairs (e.g. `((.*))/((.*))` with `$1$3`) are not
        reported — their byte ranges do not overlap.
        """
        parent, total = cls._capture_parent_map(regex)
        ancestors = {g: cls._chain_ancestors(parent, g) for g in parent}
        refs = sorted(g for g in referenced if g <= total)
        for idx, g1 in enumerate(refs):
            anc1 = ancestors.get(g1, set())
            for g2 in refs[idx + 1:]:
                if g1 in ancestors.get(g2, set()) or g2 in anc1:
                    return True
        return False

    @staticmethod
    def _chain_ancestors(parent, g):
        chain = set()
        p = parent.get(g)
        while p is not None:
            chain.add(p)
            p = parent.get(p)
        return chain

    @classmethod
    def _capture_parent_map(cls, regex):
        """Walk `regex` once and return (parent, total) where parent maps
        each capturing group number to its nearest capturing ancestor (or
        None at top level), and total is the number of capturing groups.
        Captures are numbered in declaration order, named or unnamed.
        """
        parent = {}
        stack = []   # cap_num if capturing else None
        cap = 0
        i = 0
        n = len(regex)
        while i < n:
            c = regex[i]
            if c == "\\":
                i += 2
                continue
            if c == "[":
                i = cls._skip_char_class(regex, i)
                continue
            if c == "(":
                if cls._is_capturing_paren(regex, i):
                    cap += 1
                    parent[cap] = next(
                        (x for x in reversed(stack) if x is not None), None
                    )
                    stack.append(cap)
                else:
                    stack.append(None)
            elif c == ")" and stack:
                stack.pop()
            i += 1
        return parent, cap

    @staticmethod
    def _skip_char_class(regex, i):
        """Advance past a `[...]` character class, honoring internal escapes."""
        n = len(regex)
        i += 1
        while i < n:
            if regex[i] == "\\":
                i += 2
                continue
            if regex[i] == "]":
                return i + 1
            i += 1
        return i

    @staticmethod
    def _is_capturing_paren(regex, i):
        """Return True iff regex[i] starts a capturing group (named or
        unnamed). Non-capturing groups, lookarounds, atomic groups, inline
        flags, comments, and backreferences/recursion return False.
        """
        n = len(regex)
        if i + 1 >= n or regex[i + 1] != "?":
            return True  # plain `(` — unnamed capture
        if i + 2 >= n:
            return False
        c2 = regex[i + 2]
        if c2 == "<":
            # `(?<name>...)` named; `(?<=...)` / `(?<!...)` lookbehind.
            return not (i + 3 < n and regex[i + 3] in "=!")
        if c2 == "'":
            return True  # `(?'name'...)` named capture
        if c2 == "P":
            # `(?P<name>...)` named; `(?P=name)` backref; `(?P>name)` recursion.
            return i + 3 < n and regex[i + 3] == "<"
        # `(?:`, `(?=`, `(?!`, `(?>`, `(?#`, `(?i)`, `(?i:`, etc.
        return False
