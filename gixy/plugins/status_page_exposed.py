import gixy
from gixy.core.utils import AUTH_DIRECTIVES, resolve_inherited_single
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

    UNIVERSAL_ADDRESSES = ("all", "0.0.0.0/0", "::/0")

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
        """True if an authentication module is enabled at or above this scope."""
        for name in AUTH_DIRECTIVES:
            match = resolve_inherited_single(directive.parent, name)
            if match is not None and match.args[0].lower() != "off":
                return True
        return False

    @staticmethod
    def _access_rules(directive):
        """The allow/deny rules that apply to this scope, in declaration order.

        allow/deny are inherited from the nearest ancestor scope that declares
        any of them, all-or-nothing (ngx_http_access_module): once a scope sets
        its own allow/deny, the parent's are not inherited. So we take the
        closest scope that declares either and stop there.
        """
        scope = directive.parent
        while scope:
            rules = [
                c
                for c in scope.children
                if (c.name or "").lower() in ("allow", "deny") and c.args
            ]
            if rules:
                return rules
            scope = scope.parent
        return []

    @classmethod
    def _first_universal_rule(cls, rules):
        """"allow"/"deny" of the first rule matching every address, else None.

        ngx_http_access_inet() stops at the first matching rule, so this one
        decides the fate of every address no earlier rule matched.
        """
        for rule in rules:
            if rule.args[0].lower() in cls.UNIVERSAL_ADDRESSES:
                return (rule.name or "").lower()
        return None

    @classmethod
    def _satisfy_any_allows_all(cls, directive):
        """True if `satisfy any` applies and the first universal access rule is an allow."""
        satisfy = resolve_inherited_single(directive.parent, "satisfy")
        if satisfy is None or satisfy.args[0].lower() != "any":
            return False
        return cls._first_universal_rule(cls._access_rules(directive)) == "allow"

    @staticmethod
    def _location_is_internal_only(directive):
        """True if the directive is inside a `location` carrying `internal`."""
        for parent in directive.parents:
            if parent.name == "location":
                return bool(getattr(parent, "is_internal", False))
        return False

    @classmethod
    def _effective_access(cls, directive):
        """Resolve effective (has_allow, has_deny_all) for this scope."""
        rules = cls._access_rules(directive)
        has_allow = any(
            (c.name or "").lower() == "allow"
            and c.args[0].lower() not in cls.UNIVERSAL_ADDRESSES
            for c in rules
        )
        return has_allow, cls._first_universal_rule(rules) == "deny"

    def audit(self, directive):
        if self._server_uses_only_unix_sockets(directive):
            return

        if self._location_is_internal_only(directive):
            return

        has_auth = self._has_inherited_auth(directive)

        if has_auth and not self._satisfy_any_allows_all(directive):
            return

        if not directive.parent:
            return

        has_allow, has_deny_all = self._effective_access(directive)

        if not has_allow or not has_deny_all:
            reasons = []
            if has_auth:
                reasons.append(
                    "under `satisfy any` an `allow` covering every address lets "
                    "clients through before the configured authentication runs"
                )
            if not has_allow:
                reasons.append("no allow directive to whitelist trusted IPs")
            if not has_deny_all:
                reasons.append("no 'deny all' to block unauthorized access")

            self.add_issue(
                directive=directive,
                reason="stub_status exposed: " + "; ".join(reasons),
            )
