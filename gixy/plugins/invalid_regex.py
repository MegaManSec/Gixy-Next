import re

import gixy
from gixy.core.regexp import Regexp
from gixy.directives.directive import MapDirective
from gixy.plugins.plugin import Plugin


class invalid_regex(Plugin):
    """
    Detects when a directive references a regex capture group ($1, $2, etc.)
    that doesn't exist in the associated regex pattern.

    Insecure examples:
        rewrite "(?i)/" $1 break;  # (?i) is a non-capturing flag, no groups exist
        rewrite "^/path" $1 redirect;  # No capturing groups in pattern
        if ($uri ~ "^/test") { set $x $1; }  # No capturing groups in pattern
        map $uri $dest { ~^/old/ $1; }  # No capturing groups in pattern
        location ~ ^/static/ { return 301 /$1; }  # No groups anywhere in scope
    """

    summary = "Using a nonexistent regex capture group."
    severity = gixy.severity.MEDIUM
    description = "Referencing a capture group (like $1, $2) that does not exist in the regex pattern will result in an empty value."
    help_url = "https://gixy.io/plugins/invalid_regex/"
    directives = [
        "rewrite",
        "set",
        "return",
        "proxy_pass",
        "add_header",
        "more_set_headers",
        "try_files",
        "map",
    ]

    # Pattern to find $1..$9 references in strings. nginx reads exactly one
    # digit after `$` (ngx_http_script_compile), so `$12` is capture $1
    # followed by a literal "2" and `$10`-style references don't exist.
    CAPTURE_GROUP_REF = re.compile(r"\$([1-9])")

    REGEX_OPERATORS = ("~", "~*", "!~", "!~*")

    def __init__(self, config):
        super(invalid_regex, self).__init__(config)
        self._scope_groups_cache = {}

    def audit(self, directive):
        if directive.name == "rewrite":
            self._audit_rewrite(directive)
        elif directive.name == "map":
            self._audit_map(directive)
        elif directive.name == "set":
            if not self._audit_set(directive):
                # Not in an `if` with a regex condition: fall back to the
                # conservative whole-scope check.
                if len(directive.args) >= 2:
                    self._audit_scope(directive, directive.args[1:2])
        else:
            self._audit_scope(directive, directive.args)

    @staticmethod
    def _regexp_groups(regexp):
        """Available capture group numbers of a Regexp, or None if it cannot
        be parsed (PCRE-only syntax and the like)."""
        try:
            available = {g for g in regexp.groups if isinstance(g, int)}
            available.discard(0)
            return available
        except Exception:
            return None

    @classmethod
    def _regex_groups(cls, pattern, case_sensitive=True):
        """Available capture group numbers of `pattern`, or None if it cannot
        be parsed (PCRE-only syntax and the like)."""
        return cls._regexp_groups(Regexp(pattern, case_sensitive=case_sensitive))

    def _find_refs(self, strings):
        refs = set()
        for value in strings:
            for match in self.CAPTURE_GROUP_REF.finditer(value):
                refs.add(int(match.group(1)))
        return refs

    def _audit_rewrite(self, directive):
        """Audit rewrite directives for invalid group references."""
        if len(directive.args) < 2:
            return

        pattern = directive.args[0]
        replacement = directive.args[1]

        # Find all referenced capture groups in the replacement string
        referenced_groups = self._find_refs([replacement])
        if not referenced_groups:
            return

        # Parse the regex to determine available groups
        available_groups = self._regex_groups(pattern, case_sensitive=True)
        if available_groups is None:
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

    def _audit_map(self, directive):
        """Audit regex entries of map blocks.

        When a map regex matches (or fails to match), it resets the request's
        numbered captures, so `$N` in an entry's value can only refer to that
        entry's own pattern.
        """
        gather = getattr(directive, "gather_map_directives", None)
        if gather is None:
            # Not the map block but an entry: entries carry their *key* as
            # `.name`, so one whose key is literally "map" (geo entries use
            # the same class) can be dispatched here too.
            return

        for child in gather(directive.children):
            # MapDirective parses regex keys into `.regex`; static keys
            # (and `default`) carry None and run no regex of their own.
            regex = getattr(child, "regex", None)
            if regex is None:
                continue

            value = child.dest_val
            if not value:
                continue

            referenced_groups = self._find_refs([value])
            if not referenced_groups:
                continue

            available_groups = self._regexp_groups(regex)
            if available_groups is None:
                continue

            invalid_groups = referenced_groups - available_groups
            if invalid_groups:
                invalid_list = ", ".join(f"${g}" for g in sorted(invalid_groups))
                self.add_issue(
                    directive=child,
                    reason=(
                        f"The map value references capture group(s) {invalid_list}, "
                        f'but the pattern "{regex.source}" does not define them; '
                        f"the reference is always empty."
                    ),
                )

    def _audit_set(self, directive):
        """Audit set directives inside if blocks with regex conditions.

        Returns True when the directive was handled here (it sits inside an
        `if` with a regex operator), False otherwise.
        """
        if len(directive.args) < 2:
            return False

        value = directive.args[1]

        # Find all referenced capture groups
        referenced_groups = self._find_refs([value])

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
            return False

        # Check if the if condition has a regex operator
        if not hasattr(if_directive, "args") or len(if_directive.args) < 3:
            return False

        operator = if_directive.args[1]
        if operator not in self.REGEX_OPERATORS:
            return False

        if not referenced_groups:
            return True

        pattern = if_directive.args[2]

        # Parse the regex to determine available groups
        available_groups = self._regex_groups(
            pattern, case_sensitive=(operator in ["~", "!~"])
        )
        if available_groups is None:
            return True

        # For negative match operators the block only executes when the regex did NOT
        # match, so any capture groups from this pattern are never populated here.
        if operator in ("!~", "!~*"):
            never_set = referenced_groups & available_groups
            if never_set:
                refs = ", ".join(f"${g}" for g in sorted(never_set))
                self.add_issue(
                    directive=directive,
                    reason=(
                        f"The set directive references capture group(s) {refs} inside a "
                        f"!~ block. The block only executes when the regex did not match, "
                        f"so these captures are never set by this condition and will be "
                        f"empty or carry a stale value from a previous match."
                    ),
                )

        # Check for referenced groups that don't exist in the pattern at all
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

        return True

    def _audit_scope(self, directive, strings):
        """Conservative whole-scope check for any other directive.

        nginx's `$N` always refers to the most recent regex evaluation, which
        cannot be pinned down statically. But when *no* regex that could
        possibly run for the request defines group N, the reference is
        guaranteed empty — only that case is reported.
        """
        referenced_groups = self._find_refs(strings)
        if not referenced_groups:
            return

        available_groups = self._collect_scope_groups(directive)
        if available_groups is None:
            # An unparseable provider regex could define anything: stay quiet.
            return

        invalid_groups = referenced_groups - available_groups
        if invalid_groups:
            invalid_list = ", ".join(f"${g}" for g in sorted(invalid_groups))
            self.add_issue(
                directive=directive,
                reason=(
                    f"The directive references capture group(s) {invalid_list}, "
                    f"but no regex in the enclosing configuration (location, if, "
                    f"rewrite, server_name, or map) defines them; the reference "
                    f"is always empty."
                ),
            )

    def _collect_scope_groups(self, directive):
        """Union of capture groups defined by every regex that could populate
        `$N` for a request handled in this directive's scope: the enclosing
        server's location/if/rewrite/server_name patterns plus any map regex
        keys in the whole config (maps evaluate lazily). Returns None when a
        provider pattern cannot be parsed."""
        server = None
        root = None
        node = directive.parent
        while node:
            if getattr(node, "name", None) == "server" and server is None:
                server = node
            root = node
            node = getattr(node, "parent", None)

        base = server or root
        if base is None:
            return set()

        cache_key = id(base)
        if cache_key in self._scope_groups_cache:
            return self._scope_groups_cache[cache_key]

        groups = set()
        for pattern, case_sensitive in self._provider_patterns(base):
            provided = self._regex_groups(pattern, case_sensitive)
            if provided is None:
                groups = None
                break
            groups |= provided

        if groups is not None and root is not None:
            for regexp in self._map_patterns(root):
                provided = self._regexp_groups(regexp)
                if provided is None:
                    groups = None
                    break
                groups |= provided

        self._scope_groups_cache[cache_key] = groups
        return groups

    def _provider_patterns(self, block):
        """Yield (pattern, case_sensitive) for every capture provider under
        `block`: regex locations, regex if conditions, rewrites and regex
        server_names."""
        for child in getattr(block, "children", []):
            if isinstance(child, MapDirective):
                # map/geo entries carry arbitrary key strings as `.name`,
                # which may collide with the directive names matched below;
                # regex map keys are collected by _map_patterns instead.
                continue

            name = (getattr(child, "name", None) or "").lower()
            args = getattr(child, "args", None) or []

            if name == "location" and len(args) == 2 and args[0] in ("~", "~*"):
                yield args[1], args[0] == "~"
            elif name == "if" and len(args) == 3 and args[1] in self.REGEX_OPERATORS:
                yield args[2], args[1] in ("~", "!~")
            elif name == "rewrite" and args:
                yield args[0], True
            elif name == "server_name":
                for arg in args:
                    if arg.startswith("~*"):
                        yield arg[2:], False
                    elif arg.startswith("~"):
                        yield arg[1:], True

            if getattr(child, "is_block", False):
                yield from self._provider_patterns(child)

    def _map_patterns(self, root):
        """Yield the parsed Regexp of every regex map key in the config."""
        for child in getattr(root, "children", []):
            gather = getattr(child, "gather_map_directives", None)
            if gather is not None:
                for entry in gather(child.children):
                    regex = getattr(entry, "regex", None)
                    if regex is not None:
                        yield regex
            if getattr(child, "is_block", False):
                yield from self._map_patterns(child)
