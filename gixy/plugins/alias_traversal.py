import gixy
import gixy.core.sre_parse.sre_parse as sre_parse
from gixy.core.regexp import Regexp
from gixy.core.variable import compile_script
from gixy.plugins.plugin import Plugin

_PATTERN_START = (sre_parse.AT, sre_parse.AT_BEGINNING)
_NOT_FOUND = object()


class alias_traversal(Plugin):
    r"""
    Insecure examples:

    location /files {
        alias /home/;
    }

    location ~ /site/(l\.)(.*) {
        alias /lol$1/$2;
    }
    """

    summary = "Path traversal via misconfigured alias."
    severity = gixy.severity.HIGH
    description = (
        "Using alias in a prefixed location that doesn't end with a directory "
        "separator could lead to path traversal vulnerability."
    )
    help_url = "https://gixy.io/plugins/alias_traversal/"
    directives = ["alias"]

    def audit(self, directive):
        for location in directive.parents:
            if location.name != "location":
                continue

            if location.modifier in ("~", "~*"):
                self.check_regex_location(directive, location)
            elif not location.modifier or location.modifier == "^~":
                self.check_prefix_location(directive, location)

            return

    def check_prefix_location(self, directive, location):
        if not location.path.endswith("/"):
            severity = (
                gixy.severity.HIGH
                if directive.path.endswith("/")
                else gixy.severity.MEDIUM
            )
            self.report_issue(directive, location, severity)

    def check_regex_location(self, directive, location):
        alias_parts = compile_script(directive.path)

        prev_part = None

        for part in alias_parts:
            if not getattr(part, "regexp", False):
                prev_part = part
                continue

            location_has_slash_before = part.must_startswith("/") or (
                self._literal_before_capture(location, part) == "/"
            )

            if prev_part is None:
                self.report_issue(directive, location, gixy.severity.HIGH)
            elif str(prev_part.value).endswith("/"):
                # location /bar(.*) ~ { alias /foo/$1; }
                # only dangerous if the captured part can start with "."
                if not location_has_slash_before and part.can_startswith("."):
                    if part.can_contain("/"):
                        # location /site(.*) ~ { alias /lol/$1; }
                        self.report_issue(directive, location, gixy.severity.HIGH)
                    else:
                        # location /site([^/]*) ~ { alias /lol/$1; }
                        self.report_issue(directive, location, gixy.severity.MEDIUM)
            elif not part.must_startswith("/"):
                # location /site/(.*) ~ { alias /lol$1; }
                self.report_issue(directive, location, gixy.severity.MEDIUM)

            prev_part = part

    @classmethod
    def _literal_before_capture(cls, location, part):
        """The literal just before the capture `part` refers to in the location
        regex, "" at the pattern start, None when it cannot be determined."""
        if part.provider is not location:
            return None

        parsed = Regexp(location.path).parsed
        group = part.name
        if not isinstance(group, int):
            names = {name.lower(): gid for name, gid in parsed.pattern.groupdict.items()}
            group = names.get(group)

        token = cls._token_before_group(parsed, group, _PATTERN_START)
        if token is _NOT_FOUND:
            return None
        op, av = token
        if (op, av) == _PATTERN_START:
            return ""
        if op == sre_parse.LITERAL:
            return chr(av)
        return None

    @classmethod
    def _token_before_group(cls, tokens, group, before):
        for index, (op, av) in enumerate(tokens):
            if op != sre_parse.SUBPATTERN:
                continue
            prev = before if index == 0 else tokens[index - 1]
            if av[0] == group:
                return prev
            prev = cls._token_before_group(av[1], group, prev)
            if prev is not _NOT_FOUND:
                return prev
        return _NOT_FOUND

    def report_issue(self, directive, location, severity):
        self.add_issue(
            severity=severity,
            directive=directive,
        )
