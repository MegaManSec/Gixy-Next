import gixy
from gixy.plugins.plugin import Plugin


class return_bypasses_allow_deny(Plugin):
    """
    Insecure example:
        location / {
            allow 127.0.0.1;
            deny all;
            return 200 "hi";
        }
    """

    summary = "Return directive bypasses allow/deny restrictions in the same context."
    severity = gixy.severity.HIGH
    description = "The return directive is executed before allow/deny take effect in the same context. Consider using a named location and try_files, or restructure access control."
    help_url = "https://gixy.io/plugins/return_bypasses_allow_deny/"
    directives = ["allow", "deny"]

    def __init__(self, config):
        super(return_bypasses_allow_deny, self).__init__(config)
        self._reported_parents = set()

    @staticmethod
    def _is_internal_only_location(node):
        """True for locations only reachable via internal redirect.

        Named locations (`location @name`) and locations carrying the
        `internal` directive cannot be hit by an external request, so a
        `return` inside them does not bypass the parent's allow/deny: any
        client that ever reaches the return has already passed the access
        phase of the originating location.
        """
        if getattr(node, "name", None) != "location":
            return False
        if getattr(node, "path", "").startswith("@"):
            return True
        return bool(getattr(node, "is_internal", False))

    def _find_descendants_excluding_internal_locations(self, node, name):
        result = []
        for child in node.children:
            if self._is_internal_only_location(child):
                continue
            if child.name == name:
                result.append(child)
            if getattr(child, "is_block", False):
                result.extend(
                    self._find_descendants_excluding_internal_locations(child, name)
                )
        return result

    def audit(self, directive):
        parent = directive.parent

        if not parent:
            return

        key = id(parent)
        if key in self._reported_parents:
            return
        self._reported_parents.add(key)

        # `return` and `rewrite ... permanent|redirect` both emit their response
        # during the rewrite phase, before the access phase where allow/deny run.
        # (`rewrite ... last|break` keep processing, so they do not bypass.)
        bypassing = self._find_descendants_excluding_internal_locations(
            parent, "return"
        )
        bypassing += [
            d
            for d in self._find_descendants_excluding_internal_locations(
                parent, "rewrite"
            )
            if len(d.args) >= 3 and d.args[-1].lower() in ("permanent", "redirect")
        ]
        if bypassing:
            all_allow_directives = self._find_descendants_excluding_internal_locations(
                parent, "allow"
            )
            all_deny_directives = self._find_descendants_excluding_internal_locations(
                parent, "deny"
            )
            self.add_issue(
                directive=[directive]
                + bypassing
                + all_allow_directives
                + all_deny_directives,
                reason="`allow`/`deny` do not restrict responses produced by `return` or `rewrite ... permanent|redirect` in the same scope.",
            )
