import gixy
from gixy.core.utils import resolve_inherited_single
from gixy.plugins.plugin import Plugin


class allow_without_deny(Plugin):
    """
    Warn when an 'allow' directive appears in a context without a corresponding
    'deny all;' (or equivalent restriction) in the same context.
    """

    summary = "Allow directives without a deny restriction."
    severity = gixy.severity.HIGH
    description = "Allow directives should typically be paired with a restrictive deny rule (for example, deny all;) in the same context."
    help_url = "https://gixy.io/plugins/allow_without_deny/"
    directives = ["allow"]

    AUTH_DIRECTIVES = ("auth_basic", "auth_request", "auth_jwt")

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
        for name in self.AUTH_DIRECTIVES:
            auth = resolve_inherited_single(scope, name)
            if auth is not None and auth.args[0].lower() != "off":
                return True
        return False

    def audit(self, directive):
        parent = directive.parent
        if not parent:
            return
        if directive.args == ["all"]:
            # for example, "allow all" in a nested location which allows access to otherwise forbidden parent location
            return
        if self._is_satisfy_any_with_auth(parent):
            return

        key = id(parent)
        if key in self._reported_parents:
            return
        self._reported_parents.add(key)

        deny_found = False
        for child in parent.children:
            if child.name == "deny":
                deny_found = True
                break

        if not deny_found:
            reason = "No deny rule was found in the same context; add `deny all;` after the `allow` directives."
            self.add_issue(
                directive=[directive] + list(parent.find_recursive("allow")),
                reason=reason,
            )
