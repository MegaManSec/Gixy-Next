import re

import gixy
import gixy.core.sre_parse.sre_parse as sre_parse
from gixy.core.regexp import PARSE_ERRORS, Regexp
from gixy.plugins.plugin import Plugin


def _subpatterns(av):
    if isinstance(av, sre_parse.SubPattern):
        return [av]
    if isinstance(av, (tuple, list)):
        return [body for item in av for body in _subpatterns(item)]
    return []


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
        regex = directive.pattern
        replacement = directive.replace

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
        try:
            parsed = Regexp(regex).parsed
        except PARSE_ERRORS:
            return False
        ancestors, lookarounds = {}, []
        self._walk(parsed, frozenset(), ancestors, lookarounds)
        refs = sorted(g for g in referenced if g in ancestors)
        for idx, low in enumerate(refs):
            for high in refs[idx + 1:]:
                if low in ancestors[high] or any(self._looks_across(look, low, high) for look in lookarounds):
                    return True
        return False

    @staticmethod
    def _looks_across(lookaround, low, high):
        kind, first, last = lookaround
        if kind == "ahead":
            return first <= low <= last < high
        return low < first <= high <= last

    def _walk(self, seq, chain, ancestors, lookarounds):
        # Map every capturing group to its capturing ancestors and record
        # (kind, first, last) for every positive lookahead/lookbehind
        # holding captures first..last.
        for op, av in seq:
            inner = chain
            if op == sre_parse.SUBPATTERN and av[0]:
                ancestors[av[0]] = chain
                inner = chain | {av[0]}
            known = set(ancestors)
            for body in _subpatterns(av):
                self._walk(body, inner, ancestors, lookarounds)
            if op == sre_parse.ASSERT and len(ancestors) > len(known):
                inside = ancestors.keys() - known
                lookarounds.append(("ahead" if av[0] > 0 else "behind", min(inside), max(inside)))
