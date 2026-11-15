import gixy
import gixy.core.sre_parse.sre_parse as sre_parse
from gixy.core.regexp import Regexp, RegexpTooComplex
from gixy.core.utils import resolve_inherited_single
from gixy.core.variable import EXTRACT_RE, compile_script
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
        severities = list(self._variable_severities(directive, location))
        if not location.path.endswith("/"):
            severities.append(
                gixy.severity.HIGH
                if directive.path.endswith("/")
                else gixy.severity.MEDIUM
            )
        elif not directive.path.endswith("/") and EXTRACT_RE.split(directive.path)[-1]:
            severities.append(gixy.severity.MEDIUM)
        if severities:
            self.report_issue(directive, location, max(severities, key=gixy.severity.ALL.index))

    def check_regex_location(self, directive, location):
        for severity in self._variable_severities(directive, location):
            self.report_issue(directive, location, severity)

    def _variable_severities(self, directive, location):
        alias_parts = compile_script(directive.path)

        prev_part = None

        for part in alias_parts:
            if not getattr(part, "regexp", False) or (
                part.name == "remote_user" and self._basic_auth_enforced(directive)
            ):
                prev_part = part
                continue

            location_has_slash_before = part.must_startswith("/") or (
                self._literal_before_capture(location, part) == "/"
            )

            if prev_part is None:
                yield gixy.severity.HIGH
            elif str(prev_part.value).endswith("/"):
                # location /bar(.*) ~ { alias /foo/$1; }
                # only dangerous if the captured part can start with "."
                if not location_has_slash_before and part.can_startswith(".") and not self._from_host(part):
                    if part.can_contain("/"):
                        # location /site(.*) ~ { alias /lol/$1; }
                        yield gixy.severity.HIGH
                    elif self._can_be_parent_dir(part):
                        # location /site([^/]*) ~ { alias /lol/$1; }
                        yield gixy.severity.MEDIUM
            elif not part.must_startswith("/"):
                # location /site/(.*) ~ { alias /lol$1; }
                yield gixy.severity.MEDIUM

            prev_part = part

    @staticmethod
    def _basic_auth_enforced(directive):
        """True when ngx_http_auth_basic_module rejects every request whose user
        is not in the password file: realm and file set, and no `satisfy any`."""
        scope = directive.parent
        auth = resolve_inherited_single(scope, "auth_basic")
        if auth is None or auth.args[0].lower() == "off":
            return False
        if resolve_inherited_single(scope, "auth_basic_user_file") is None:
            return False
        satisfy = resolve_inherited_single(scope, "satisfy")
        return satisfy is None or satisfy.args[0].lower() == "all"

    @staticmethod
    def _from_host(part):
        """True for values nginx takes from the validated Host, which never
        contain `/` or `..`."""
        return part.name == "http_host" or getattr(part.provider, "name", None) == "server"

    @staticmethod
    def _can_be_parent_dir(part):
        try:
            return ".." in part.regexp.generate(".", max_repeat=2)
        except RegexpTooComplex:
            return True

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
