import re

import gixy
from gixy.core.regexp import Regexp
from gixy.plugins.plugin import Plugin


class invalid_regex(Plugin):
    """
    Detects when a directive references a regex capture group ($1, $2, etc.)
    that doesn't exist in the associated regex pattern.

    Insecure examples:
        rewrite "(?i)/" $1 break;  # (?i) is a non-capturing flag, no groups exist
        rewrite "^/path" $1 redirect;  # No capturing groups in pattern
        if ($uri ~ "^/test") { set $x $1; }  # No capturing groups in pattern
    """

    summary = "Using a nonexistent regex capture group."
    severity = gixy.severity.MEDIUM
    description = "Referencing a capture group (like $1, $2) that does not exist in the regex pattern will result in an empty value."
    help_url = "https://gixy.io/plugins/invalid_regex/"
    directives = ["rewrite", "set"]

    # Pattern to find $1, $2, etc. references in strings
    CAPTURE_GROUP_REF = re.compile(r"\$([1-9]\d*)")

    def audit(self, directive):
        if directive.name == "rewrite":
            self._audit_rewrite(directive)
        elif directive.name == "set":
            self._audit_set(directive)

    def _audit_rewrite(self, directive):
        """Audit rewrite directives for invalid group references."""
        if len(directive.args) < 2:
            return

        pattern = directive.args[0]
        replacement = directive.args[1]

        # Find all referenced capture groups in the replacement string
        referenced_groups = set()
        for match in self.CAPTURE_GROUP_REF.finditer(replacement):
            referenced_groups.add(int(match.group(1)))

        if not referenced_groups:
            return

        # Parse the regex to determine available groups
        try:
            regexp = Regexp(pattern, case_sensitive=True)
            available_groups = set(regexp.groups.keys())
            # Remove group 0 (the full match) from available groups
            available_groups.discard(0)
        except Exception:
            # If we can't parse the regex, skip this check
            return

        # Check for referenced groups that don't exist
        invalid_groups = referenced_groups - available_groups

        if invalid_groups:
            invalid_list = ", ".join(f"${g}" for g in sorted(invalid_groups))
            if len(available_groups) == 0:
                reason = (
                    f"The replacement string references capture group(s) {invalid_list}, "
                    f'but the pattern "{pattern}" has no capturing groups.'
                )
            else:
                available_list = ", ".join(f"${g}" for g in sorted(available_groups))
                reason = (
                    f"The replacement string references capture group(s) {invalid_list}, "
                    f'but the pattern "{pattern}" only has {available_list}.'
                )

            self.add_issue(directive=directive, reason=reason)

    def _audit_set(self, directive):
        """Audit set directives that may reference regex groups from parent if blocks."""
        if len(directive.args) < 2:
            return

        value = directive.args[1]

        # Find all referenced capture groups
        referenced_groups = set()
        for match in self.CAPTURE_GROUP_REF.finditer(value):
            referenced_groups.add(int(match.group(1)))

        if not referenced_groups:
            return

        # Check if this set is inside an if block with a regex
        parent = directive.parent
        if_directive = None

        while parent and not if_directive:
            if hasattr(parent, "name") and parent.name == "if":
                if_directive = parent
                break
            parent = getattr(parent, "parent", None)

        if not if_directive:
            # Not in an if block, can't determine regex context
            return

        # Check if the if condition has a regex operator
        if not hasattr(if_directive, "args") or len(if_directive.args) < 3:
            return

        operator = if_directive.args[1]
        if operator not in ["~", "~*", "!~", "!~*"]:
            return

        pattern = if_directive.args[2]

        # Parse the regex to determine available groups
        try:
            regexp = Regexp(pattern, case_sensitive=(operator in ["~", "!~"]))
            available_groups = set(regexp.groups.keys())
            available_groups.discard(0)
        except Exception:
            return

        # Check for referenced groups that don't exist
        invalid_groups = referenced_groups - available_groups

        if invalid_groups:
            invalid_list = ", ".join(f"${g}" for g in sorted(invalid_groups))
            if len(available_groups) == 0:
                reason = (
                    f"The set directive references capture group(s) {invalid_list}, "
                    f'but the if condition pattern "{pattern}" has no capturing groups.'
                )
            else:
                available_list = ", ".join(f"${g}" for g in sorted(available_groups))
                reason = (
                    f"The set directive references capture group(s) {invalid_list}, "
                    f'but the if condition pattern "{pattern}" only has {available_list}.'
                )

            self.add_issue(directive=directive, reason=reason)
