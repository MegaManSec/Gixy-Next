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

    @staticmethod
    def _effective_access(directive):
        """Resolve effective (has_allow, has_deny_all) for this scope.

        allow/deny are inherited from the nearest ancestor scope that declares
        any of them, all-or-nothing (ngx_http_access_module): once a scope sets
        its own allow/deny, the parent's are not inherited. So we evaluate the
        closest scope that declares either and stop there.
        """
        scope = directive.parent
        while scope:
            allow_deny = [
                c for c in scope.children if (c.name or "").lower() in ("allow", "deny")
            ]
            if allow_deny:
                has_allow = any(
                    (c.name or "").lower() == "allow"
                    and c.args
                    and c.args[0].lower() != "all"  # "allow all" is not a whitelist
                    for c in allow_deny
                )
                has_deny_all = any(
                    (c.name or "").lower() == "deny"
                    and c.args
                    and c.args[0].lower() == "all"
                    for c in allow_deny
                )
                return has_allow, has_deny_all
            scope = scope.parent
        return False, False

    def audit(self, directive):
        if self._server_uses_only_unix_sockets(directive):
            return

        if self._location_is_internal_only(directive):
            return

        if self._has_inherited_auth(directive):
            return

        if not directive.parent:
            return

        has_allow, has_deny_all = self._effective_access(directive)

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
