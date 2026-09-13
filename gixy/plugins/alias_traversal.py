import re

import gixy
from gixy.core.variable import compile_script
from gixy.plugins.plugin import Plugin


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

        # "\." -> "."
        location_pattern = re.sub(r"\\(.)", r"\1", location.path)

        search_pos = 0
        prev_part = None

        for part in alias_parts:
            if not getattr(part, "regexp", False):
                prev_part = part
                continue

            capture_group = "(" + str(part.value) + ")"
            group_pos = location_pattern.find(capture_group, search_pos)

            if group_pos < 0:
                prev_part = part
                continue

            search_pos = group_pos

            location_has_slash_before = (
                group_pos == 0 and part.must_startswith("/")
            ) or (
                group_pos > 0
                and (
                    location_pattern[group_pos - 1] == "/" or part.must_startswith("/")
                )
            )

            if prev_part is None:
                self.report_issue(directive, location, gixy.severity.HIGH)
            elif not location_has_slash_before:
                alias_has_slash_before = str(prev_part.value).endswith("/")

                if alias_has_slash_before:
                    # location /bar(.*) ~ { alias /foo/$1; }
                    # only dangerous if the captured part can start with "."
                    if part.can_startswith("."):
                        if part.can_contain("/"):
                            # location /site(.*) ~ { alias /lol/$1; }
                            self.report_issue(directive, location, gixy.severity.HIGH)
                        else:
                            # location /site([^/]*) ~ { alias /lol/$1; }
                            self.report_issue(directive, location, gixy.severity.MEDIUM)
                else:
                    alias_has_slash_before = str(prev_part.value).endswith("/")

                    if not alias_has_slash_before and not part.must_startswith("/"):
                        # location /site/(.*) ~ { alias /lol$1; }
                        self.report_issue(directive, location, gixy.severity.MEDIUM)

            else:
                alias_has_slash_before = str(prev_part.value).endswith("/")

                if not alias_has_slash_before and not part.must_startswith("/"):
                    # location /site/(.*) ~ { alias /lol$1; }
                    self.report_issue(directive, location, gixy.severity.MEDIUM)

            prev_part = part

    def report_issue(self, directive, location, severity):
        self.add_issue(
            severity=severity,
            directive=directive,
        )
