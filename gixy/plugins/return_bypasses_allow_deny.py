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

    REDIRECT_FLAGS = ("permanent", "redirect")
    # nginx also redirects whenever the replacement is an absolute URL,
    # regardless of flag; its prefix check is case-sensitive (ngx_http_rewrite).
    REDIRECT_PREFIXES = ("http://", "https://", "$scheme")

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

    @classmethod
    def _rewrite_emits_redirect(cls, directive):
        """True when this rewrite responds with a redirect from the rewrite
        phase: it carries a `permanent`/`redirect` flag, or its replacement
        is an absolute URL — the latter redirects whatever the flag, `last`
        and `break` included."""
        args = directive.args
        if len(args) >= 3 and args[-1].lower() in cls.REDIRECT_FLAGS:
            return True
        return len(args) >= 2 and args[1].startswith(cls.REDIRECT_PREFIXES)

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

        # `return` and any redirecting rewrite emit their response during the
        # rewrite phase, before the access phase where allow/deny run.
        # (`rewrite ... last|break` with a plain URI replacement keeps
        # processing, so it does not bypass.)
        bypassing = self._find_descendants_excluding_internal_locations(
            parent, "return"
        )
        bypassing += [
            d
            for d in self._find_descendants_excluding_internal_locations(
                parent, "rewrite"
            )
            if self._rewrite_emits_redirect(d)
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
                reason="`allow`/`deny` do not restrict responses produced by `return` or by a redirecting `rewrite` in the same scope.",
            )
