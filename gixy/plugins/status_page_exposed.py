import gixy
from gixy.plugins.plugin import Plugin


class status_page_exposed(Plugin):
    """Flag stub_status endpoints without IP allow/deny restrictions."""

    summary = "stub_status is exposed without IP restrictions."
    severity = gixy.severity.MEDIUM
    description = (
        "stub_status exposes NGINX connection and request metrics. "
        "If not IP-restricted, it is accessible to anyone and useful for reconnaissance."
    )
    directives = ["stub_status"]
    help_url = "https://gixy.io/plugins/status_page_exposed/"

    def _server_uses_only_unix_sockets(self, directive):
        """True if the enclosing server listens only on unix: sockets."""
        for parent in directive.parents:
            if parent.name == "server":
                listen_directives = parent.find("listen")
                if not listen_directives:
                    return False
                return all(
                    d.args and d.args[0].lower().startswith("unix:")
                    for d in listen_directives
                )
        return False

    @staticmethod
    def _resolve_inherited(scope, name):
        """Return the effective value of an inheritable single-value directive.

        Walks up from `scope` to the root. The first scope that declares the
        directive wins (closest scope), matching nginx inheritance. If a scope
        declares the directive more than once, the last occurrence is used.
        Returns None when the directive is unset anywhere up the chain.
        """
        current = scope
        while current:
            matches = [
                c
                for c in current.children
                if (c.name or "").lower() == name and c.args
            ]
            if matches:
                return matches[-1].args[0].lower()
            current = current.parent
        return None

    def _has_inherited_auth(self, directive):
        """True if auth_request or auth_basic is enabled at or above this scope."""
        for name in ("auth_request", "auth_basic"):
            value = self._resolve_inherited(directive.parent, name)
            if value is not None and value != "off":
                return True
        return False

    @staticmethod
    def _location_is_internal_only(directive):
        """True if the directive is inside a `location` carrying `internal`."""
        for parent in directive.parents:
            if parent.name == "location":
                return bool(getattr(parent, "is_internal", False))
        return False

    def audit(self, directive):
        if self._server_uses_only_unix_sockets(directive):
            return

        if self._location_is_internal_only(directive):
            return

        if self._has_inherited_auth(directive):
            return

        parent = directive.parent
        if not parent:
            return

        has_allow = False
        has_deny_all = False

        for child in parent.children:
            name = (child.name or "").lower()
            args = [a.lower() for a in (child.args or [])]

            if name == "allow":
                # "allow all" is NOT a whitelist, so don't count it
                if args and args[0] != "all":
                    has_allow = True
            elif name == "deny":
                if args and args[0] == "all":
                    has_deny_all = True

        if not has_allow or not has_deny_all:
            reasons = []
            if not has_allow:
                reasons.append("no allow directive to whitelist trusted IPs")
            if not has_deny_all:
                reasons.append("no 'deny all' to block unauthorized access")

            self.add_issue(
                directive=directive,
                reason="stub_status exposed: " + "; ".join(reasons),
            )
