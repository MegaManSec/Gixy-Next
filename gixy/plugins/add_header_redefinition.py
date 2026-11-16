import gixy
from gixy.core.utils import resolve_inherited_list, resolve_inherited_single
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
        current_fields = self.field_names(directive.find(field_directive))
        inherit = resolve_inherited_single(directive, inherit_directive)
        mode = inherit.arg(0).lower() if inherit else "on"
        if mode == "off" and inherit.parent is not directive:
            self._audit_inherited_off(directive, current_fields, field_directive, inherit_directive, kind, inherit)
            return

        if not current_fields:
            return

        # 'merge', parent fields are appended.
        # 'off', inheritance is explicitly cancelled.
        if mode in ("merge", "off"):
            return

        parent = directive.parent
        parent_effective = self.effective_fields(parent, field_directive, inherit_directive)
        if not parent_effective:
            return

        if self.merge_reported_headers:
            # fields declared in ancestors (not including this directive)
            diff = self.field_names(directive.find_imperative_directives_in_scope(field_directive)) - current_fields
        else:
            diff = parent_effective - current_fields

        if self.interesting_headers:
            diff = diff & self.interesting_headers

        if diff:
            self._report_issue(directive, parent, diff, field_directive, inherit_directive, kind)

    def _audit_inherited_off(self, directive, current_fields, field_directive, inherit_directive, kind, inherit):
        parent = directive.parent
        diff = self.effective_fields(parent, field_directive, inherit_directive) - current_fields
        if self.interesting_headers:
            diff = diff & self.interesting_headers

        if diff:
            reason = "{kind}s `{fields}` from the level above are dropped here.".format(
                kind=kind.capitalize(), fields="`, `".join(sorted(diff))
            )
            summary = 'Inherited "{inherit} off" drops parent {kind}s.'.format(inherit=inherit_directive, kind=kind)
            self._report_issue(
                directive, parent, diff, field_directive, inherit_directive, kind,
                reason=reason, extra=[inherit, directive], summary=summary,
            )

    def _report_issue(
        self, current, parent, diff, field_directive, inherit_directive, kind, reason=None, extra=(), summary=None
    ):
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
        directives.extend(d for d in extra if d not in directives)

        is_secure_header_dropped = kind == "header" and any(
            h in self.secure_headers for h in diff
        )
        issue_severity = (
            gixy.severity.MEDIUM if is_secure_header_dropped else self.severity
        )

        if summary is None and kind == "trailer":
            summary = 'Nested "add_trailer" drops parent trailers.'

        if reason is None and self.merge_reported_headers:
            reason = "{kind}s declared in higher scopes `{fields}` are not effective here.".format(
                kind=kind.capitalize(), fields="`, `".join(sorted(diff))
            )
        elif reason is None:
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

    @classmethod
    def field_names(cls, directives):
        return {cls.field_name(d) for d in directives if cls.field_name(d)}

    def effective_fields(self, directive, field_directive, inherit_directive):
        """Field names in effect at this level"""
        return self.field_names(resolve_inherited_list(directive, field_directive, inherit_directive))
