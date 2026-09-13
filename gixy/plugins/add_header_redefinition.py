import gixy
from gixy.plugins.plugin import Plugin

FIELD_FAMILIES = (
    ("add_header", "add_header_inherit", "header"),
    ("add_trailer", "add_trailer_inherit", "trailer"),
)


class add_header_redefinition(Plugin):
    """
    Insecure example (prior to nginx 1.29.3):
        server {
            add_header X-Content-Type-Options nosniff;
            location / {
                add_header X-Frame-Options DENY;
            }
        }

    Secure example (from nginx 1.29.3):
        server {
            add_header X-Content-Type-Options nosniff;
            location / {
                add_header_inherit merge;
                add_header X-Frame-Options DENY;
            }
        }
    """

    summary = 'Nested "add_header" drops parent headers.'
    severity = gixy.severity.LOW
    description = (
        '"add_header" and "add_trailer" at a nested level replace inherited fields '
        "unless `add_header_inherit merge` / `add_trailer_inherit merge` is in effect "
        "(nginx 1.29.3+)."
    )
    help_url = "https://gixy.io/plugins/add_header_redefinition/"
    directives = ["server", "location", "if"]
    options = {"headers": set(), "merge_reported_headers": True}
    options_help = {
        "headers": (
            "Only report dropped fields from this allowlist. Case-insensitive. "
            'Comma-separated list, e.g. "x-frame-options,content-security-policy".'
        ),
        "merge_reported_headers": (
            "Report fields declared in higher scopes that are not inherited "
            "(but were dropped at an intermediate level)."
        ),
    }

    def __init__(self, config):
        super(add_header_redefinition, self).__init__(config)
        raw_headers = self.config.get("headers")
        # Normalize configured headers to lowercase set for case-insensitive matching
        if isinstance(raw_headers, (list, tuple, set)):
            self.interesting_headers = set(
                h.lower().strip() for h in raw_headers if h and isinstance(h, str)
            )
        else:
            self.interesting_headers = set()
        # Define secure headers that should escalate severity
        self.secure_headers = [
            "cache-control",
            "content-security-policy",
            "content-security-policy-report-only",
            "cross-origin-embedder-policy",
            "cross-origin-opener-policy",
            "cross-origin-resource-policy",
            "permissions-policy",
            "referrer-policy",
            "strict-transport-security",
            "x-content-type-options",
            "x-frame-options",
            "x-xss-protection",
            "x-permitted-cross-domain-policies",
            "expect-ct",
            "pragma",
            "expires",
            "content-disposition",
        ]
        self.merge_reported_headers = self.config.get("merge_reported_headers")

    def audit(self, directive):
        if not directive.is_block:
            # Skip all not block directives
            return

        for field_directive, inherit_directive, kind in FIELD_FAMILIES:
            self._audit_family(directive, field_directive, inherit_directive, kind)

    def _audit_family(self, directive, field_directive, inherit_directive, kind):
        current_fields = self.get_fields(directive, field_directive)
        if not current_fields:
            return

        mode = self.effective_inherit_mode(directive, inherit_directive)
        # 'merge', parent fields are appended.
        # 'off', inheritance is explicitly cancelled.
        if mode in ("merge", "off"):
            return

        parent = getattr(directive, "parent", None)
        if not parent:
            return

        parent_effective = self.effective_fields(parent, field_directive, inherit_directive)
        if not parent_effective:
            return

        if self.merge_reported_headers:
            # fields declared in ancestors (not including this directive)
            declared_above = self.get_fields(parent, field_directive, inherited=True)
            # fields actually effective here
            current_effective = self.effective_fields(directive, field_directive, inherit_directive)
            diff = declared_above - current_effective
        else:
            diff = parent_effective - current_fields

        if self.interesting_headers:
            diff = diff & self.interesting_headers

        if diff:
            self._report_issue(directive, parent, diff, field_directive, inherit_directive, kind)

    def _report_issue(self, current, parent, diff, field_directive, inherit_directive, kind):
        directives = []
        # Use the parent's scope so we pick up server-level fields and includes.
        scope_fields = parent.find_imperative_directives_in_scope(field_directive)
        directives.extend(
            d for d in scope_fields if self.field_name(d) in diff
        )
        # and always include the fields at the current and parent level
        directives.extend(current.find(field_directive))
        directives.extend(parent.find(field_directive))

        directives.extend(parent.find(inherit_directive))
        directives.extend(current.find(inherit_directive))

        is_secure_header_dropped = kind == "header" and any(
            h in self.secure_headers for h in diff
        )
        issue_severity = (
            gixy.severity.MEDIUM if is_secure_header_dropped else self.severity
        )

        summary = None
        if kind == "trailer":
            summary = 'Nested "add_trailer" drops parent trailers.'

        if self.merge_reported_headers:
            reason = "{kind}s declared in higher scopes `{fields}` are not effective here.".format(
                kind=kind.capitalize(), fields="`, `".join(sorted(diff))
            )
        else:
            reason = "Parent {kind}s `{fields}` were dropped at this level.".format(
                kind=kind, fields="`, `".join(sorted(diff))
            )

        self.add_issue(
            directive=directives, summary=summary, reason=reason, severity=issue_severity
        )

    @staticmethod
    def field_name(directive):
        header = getattr(directive, "header", None)
        if header is not None:
            return header
        if directive.args:
            return directive.args[0].lower()
        return None

    def get_fields(self, directive, field_directive, inherited=False):
        """
        Fields defined at this level.
        If inherited=True, also include fields declared in the current scope (ancestors + current)
        """
        fields = []
        if inherited:
            fields.extend(directive.find_imperative_directives_in_scope(field_directive))
        fields.extend(directive.find(field_directive))

        if not fields:
            return set()
        return {self.field_name(d) for d in fields if self.field_name(d)}

    def effective_inherit_mode(self, directive, inherit_directive):
        """
        The inherit directive itself is inherited "normally" (nearest definition wins).
        """
        node = directive
        while node is not None:
            inherit_directives = node.find(inherit_directive)
            mode = None
            # If multiple are present at the same level, the last valid one wins.
            for d in inherit_directives:
                if getattr(d, "args", None):
                    v = d.args[0].lower()
                    if v in ("on", "off", "merge"):
                        mode = v
            if mode is not None:
                return mode
            node = getattr(node, "parent", None)
        return "on"

    def effective_fields(self, directive, field_directive, inherit_directive):
        """
        Effective field names at this level, respecting the inherit mode:
          - on    : standard behavior (if any fields here, they replace inherited; else inherit)
          - merge : inherit + append current
          - off   : cancel inheritance entirely (only current fields apply)
        """
        if directive is None:
            return set()

        mode = self.effective_inherit_mode(directive, inherit_directive)
        own = self.get_fields(directive, field_directive, inherited=False)
        parent = getattr(directive, "parent", None)
        inherited = (
            self.effective_fields(parent, field_directive, inherit_directive)
            if parent is not None
            else set()
        )

        if mode == "off":
            return set(own)
        if mode == "merge":
            return set(inherited) | set(own)
        # mode == 'on'
        return set(own) if own else set(inherited)
