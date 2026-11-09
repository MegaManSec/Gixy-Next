import ipaddress

import gixy
from gixy.core.utils import AUTH_DIRECTIVES, resolve_inherited_single
from gixy.plugins.plugin import Plugin

ALL_RULE = "all"
ALLOW_ALL_RULES = frozenset((ALL_RULE, "0.0.0.0/0", "::/0"))


class allow_without_deny(Plugin):
    """
    Warn when the 'allow' directives in a context are not paired with a 'deny'
    (usually 'deny all;') that covers any of the allowed addresses.
    """

    summary = "Allow directives without a deny restriction."
    severity = gixy.severity.HIGH
    description = (
        "Allow directives should typically be paired with a restrictive deny rule "
        "(for example, deny all;) in the same context."
    )
    help_url = "https://gixy.io/plugins/allow_without_deny/"
    directives = ["allow"]

    def __init__(self, config):
        super(allow_without_deny, self).__init__(config)
        self._reported_parents = set()

    def _is_satisfy_any_with_auth(self, scope):
        """True for the intended 'IP allowlist OR authentication' pattern.

        Under `satisfy any`, clients outside the allow list get NGX_DECLINED
        from the access module and fall through to the auth modules, so a
        missing `deny all` changes nothing: they still must authenticate.
        Without an auth module the allow list is decorative and the warning
        stands.
        """
        satisfy = resolve_inherited_single(scope, "satisfy")
        if satisfy is None or satisfy.args[0].lower() != "any":
            return False
        for name in AUTH_DIRECTIVES:
            auth = resolve_inherited_single(scope, name)
            if auth is not None and auth.args[0].lower() != "off":
                return True
        return False

    @staticmethod
    def _rule_range(directive):
        """ip_network for an address rule; the raw argument for `all`, `unix:`
        and anything ipaddress cannot parse."""
        value = directive.args[0]
        if value in (ALL_RULE, "unix:"):
            return value
        try:
            return ipaddress.ip_network(value, strict=False)
        except ValueError:
            return value

    @classmethod
    def _deny_covers(cls, deny, allow):
        """True if some client matched by `allow` would be rejected by `deny`.

        ngx_http_access_handler() takes the first matching rule, so an allow
        only does something when a deny would otherwise catch one of its
        addresses. `deny all` covers everything; unix: is its own family;
        IPv4 and IPv6 ranges, `0.0.0.0/0` and `::/0` included, never overlap
        each other.
        """
        deny_range = cls._rule_range(deny)
        allow_range = cls._rule_range(allow)
        if deny_range == ALL_RULE:
            return True
        if isinstance(deny_range, str) or isinstance(allow_range, str):
            return deny_range == allow_range
        return deny_range.version == allow_range.version and deny_range.overlaps(allow_range)

    def audit(self, directive):
        parent = directive.parent
        if not parent or not directive.args:
            return
        if directive.args[0] in ALLOW_ALL_RULES:
            # for example, "allow all" in a nested location which allows access to otherwise forbidden parent location
            return
        if self._is_satisfy_any_with_auth(parent):
            return

        key = id(parent)
        if key in self._reported_parents:
            return
        self._reported_parents.add(key)

        allows = [
            child
            for child in parent.find("allow")
            if child.args and child.args[0] not in ALLOW_ALL_RULES
        ]
        denies = [child for child in parent.find("deny") if child.args]

        if any(self._deny_covers(deny, allow) for deny in denies for allow in allows):
            return

        if denies:
            reason = (
                "No `deny` rule in the same context overlaps the allowed addresses, so the `allow` "
                "directives change nothing; add `deny all;` after them."
            )
        else:
            reason = "No deny rule was found in the same context; add `deny all;` after the `allow` directives."
        self.add_issue(
            directive=allows + denies,
            reason=reason,
        )
