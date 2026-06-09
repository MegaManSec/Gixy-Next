import gixy
from gixy.core.utils import resolve_inherited_single
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

    def _has_inherited_auth(self, directive):
        """True if auth_request or auth_basic is enabled at or above this scope."""
        for name in ("auth_request", "auth_basic"):
            match = resolve_inherited_single(directive.parent, name)
            if match is not None and match.args[0].lower() != "off":
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
