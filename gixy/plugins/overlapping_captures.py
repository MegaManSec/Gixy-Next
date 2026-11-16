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
        "Rewrite with overlapping captures in redirect/args context causes "
        "heap overflow (CVE-2026-9256)."
    )
    severity = gixy.severity.INFORMATION
    description = (
        "On nginx before 1.30.2/1.31.1, a `rewrite` that escapes two overlapping captures by `$N` "
        "(in a redirect or after `?`) overflows a heap buffer (CVE-2026-9256). Upgrade nginx, or "
        "reference named captures (`$name`) instead of `$N`; this is INFORMATION because the nginx "
        "version is unknown."
    )
    help_url = "https://gixy.io/plugins/overlapping_captures/"
    directives = ["rewrite"]

    # nginx parses only single-digit `$1`..`$9`; `$10` is `$1` followed
    # by literal `0`.
    _NUMERIC_CAPTURE = re.compile(r"\$([1-9])")
    # nginx variable refs (`$name` / `${name}`); never a numeric capture
    # since the unbraced form requires a non-digit first character.
    _NGINX_VARIABLE = re.compile(r"\$[A-Za-z_]\w*|\$\{[^}]+\}")

    def audit(self, directive):
        if len(directive.args) < 2:
            return

        regex = directive.args[0]
        replacement = directive.args[1]

        # nginx strips a sole trailing `?` from the replacement (it
        # means "drop the original arguments"), so a trailing-only `?`
        # never enters runtime args mode.
        if replacement.endswith("?"):
            replacement = replacement[:-1]

        # A replacement containing any `$name` / `${name}` variable
        # routes through the safe per-capture length-calc path.
        if self._NGINX_VARIABLE.search(replacement):
            return

        # A duplicate `$N` reference anywhere in the replacement forces
        # nginx onto its safe length-calc path.
        all_refs = self._NUMERIC_CAPTURE.findall(replacement)
        if len(all_refs) != len(set(all_refs)):
            return

        # Which `$N` references run in escape mode? On a redirect, all
        # of them. Otherwise only those after the first `?`; refs before
        # are written raw and a lone escaped capture stays within the
        # buggy length budget.
        if directive.redirects:
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
                "context. On unpatched nginx (< 1.30.2/1.31.1) this causes a heap "
                "buffer overflow (CVE-2026-9256)."
            ),
        )

    def _referenced_captures_overlap(self, regex, referenced):
        # True iff any pair of referenced groups is syntactically nested
        # (one is an ancestor of the other), or one sits in a positive
        # lookahead and the other follows it, or one sits in a positive
        # lookbehind and the other precedes it. Sibling pairs like
        # `((.*))/((.*))` with `$1$3` are not reported.
        parent, total, lookarounds = self._capture_parent_map(regex)
        ancestors = {g: self._chain_ancestors(parent, g) for g in parent}
        refs = sorted(g for g in referenced if g <= total)
        for idx, g1 in enumerate(refs):
            anc1 = ancestors.get(g1, set())
            for g2 in refs[idx + 1:]:
                if g1 in ancestors.get(g2, set()) or g2 in anc1:
                    return True
                if any(self._looks_across(look, g1, g2) for look in lookarounds):
                    return True
        return False

    @staticmethod
    def _looks_across(lookaround, low, high):
        kind, first, last = lookaround
        if kind == "ahead":
            return first <= low <= last < high
        return low < first <= high <= last

    def _chain_ancestors(self, parent, g):
        chain = set()
        p = parent.get(g)
        while p is not None:
            chain.add(p)
            p = parent.get(p)
        return chain

    def _capture_parent_map(self, regex):
        # Walk `regex` once. Return (parent, total, lookarounds) where
        # parent maps each capturing group number to its nearest capturing
        # ancestor (or None at top level), total is the number of capturing
        # groups, and lookarounds lists (kind, first, last) for every
        # positive lookahead/lookbehind holding captures first..last.
        # Groups are numbered in declaration order, named or unnamed.
        parent = {}
        lookarounds = []
        stack = []   # (cap_num if capturing else None, lookaround frame)
        cap = 0
        i = 0
        n = len(regex)
        while i < n:
            c = regex[i]
            if c == "\\":
                i += 2
                continue
            if c == "[":
                i = self._skip_char_class(regex, i)
                continue
            if c == "(":
                if self._is_capturing_paren(regex, i):
                    cap += 1
                    parent[cap] = next(
                        (x for x, _ in reversed(stack) if x is not None), None
                    )
                    stack.append((cap, None))
                else:
                    kind = self._lookaround_kind(regex, i)
                    stack.append((None, [kind, cap + 1] if kind else None))
            elif c == ")" and stack:
                _, frame = stack.pop()
                if frame and cap >= frame[1]:
                    lookarounds.append((frame[0], frame[1], cap))
            i += 1
        return parent, cap, lookarounds

    @staticmethod
    def _lookaround_kind(regex, i):
        if regex.startswith("(?=", i):
            return "ahead"
        if regex.startswith("(?<=", i):
            return "behind"
        return None

    def _skip_char_class(self, regex, i):
        # Advance past a `[...]` character class, honoring escapes.
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

    def _is_capturing_paren(self, regex, i):
        # True iff regex[i] starts a capturing group (named or unnamed).
        # Non-capturing groups, lookarounds, atomic groups, inline flags,
        # comments, named backreferences/recursion, and PCRE verbs return
        # False.
        n = len(regex)
        if i + 1 >= n:
            return True
        nxt = regex[i + 1]
        if nxt == "*":
            return False  # PCRE verb: `(*UTF)`, `(*MARK:name)`, `(*COMMIT)`, etc.
        if nxt != "?":
            return True  # plain `(`: unnamed capture
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
