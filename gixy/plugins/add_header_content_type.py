import gixy
from gixy.plugins.plugin import Plugin

UPSTREAM_FAMILIES = ("proxy", "fastcgi", "uwsgi", "scgi", "grpc")


class add_header_content_type(Plugin):
    """
    Bad example: add_header Content-Type text/plain;
    Good example: default_type text/plain;
    """

    summary = "Setting Content-Type via add_header."
    severity = gixy.severity.LOW
    description = "Do not set Content-Type using add_header; use default_type instead."
    help_url = "https://gixy.io/plugins/add_header_content_type/"
    directives = ["add_header"]

    def audit(self, directive):
        ct_value = next(
            (v for h, v in directive.headers.items() if h.lower() == "content-type"),
            None,
        )
        if ct_value is None:
            return

        if self._upstream_hides_content_type(directive):
            return

        reason = "Use `default_type {default_type};` instead of `add_header` to set Content-Type.".format(
            default_type=ct_value
        )
        self.add_issue(directive=directive, reason=reason)

    def _upstream_hides_content_type(self, directive):
        families = self._upstream_families(directive)
        if families is None:
            return any(self._hides_content_type(directive, family) for family in UPSTREAM_FAMILIES)
        return all(self._hides_content_type(directive, family) for family in families)

    @staticmethod
    def _upstream_families(directive):
        """`*_pass` families in effect for the block declaring `directive`, or None when there are none"""
        for block in directive.parents:
            families = {
                family for family in UPSTREAM_FAMILIES if block.find("{0}_pass".format(family), flat=True)
            }
            if families:
                return families
            if block.self_context:
                return None
        return None

    @staticmethod
    def _nearest_header_list(directive, name):
        """Lowercased header names of the nearest `name` directives in scope; empty when none declares it"""
        for block in directive.parents:
            declared = block.find(name, flat=True)
            if declared:
                return {h.arg(0, "").lower() for h in declared}
        return set()

    @classmethod
    def _hides_content_type(cls, directive, family):
        """Whether the `<family>_hide_header` list in effect hides Content-Type, net of `<family>_pass_header`"""
        hidden = cls._nearest_header_list(directive, "{0}_hide_header".format(family))
        passed = cls._nearest_header_list(directive, "{0}_pass_header".format(family))
        return "content-type" in hidden and "content-type" not in passed
