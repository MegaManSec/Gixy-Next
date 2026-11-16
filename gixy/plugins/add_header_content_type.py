import gixy
from gixy.core.utils import resolve_inherited_list
from gixy.directives.directive import quote_arg
from gixy.plugins.plugin import Plugin

UPSTREAM_FAMILIES = ("proxy", "fastcgi", "uwsgi", "scgi", "grpc")
TYPED_RETURN_STATUSES = ("200", "201", "206", "301", "302", "303", "304", "307", "308")


class add_header_content_type(Plugin):
    """
    Bad example: add_header Content-Type text/plain;
    Good example: types {} default_type text/plain;
    """

    summary = "Setting Content-Type via add_header."
    severity = gixy.severity.LOW
    description = (
        "Do not set Content-Type using add_header; use an empty types block with default_type, "
        "or hide the upstream Content-Type first."
    )
    help_url = "https://gixy.io/plugins/add_header_content_type/"
    directives = ["add_header"]

    def audit(self, directive):
        ct_value = next(
            (v for h, v in directive.headers.items() if h.lower() == "content-type"),
            None,
        )
        if ct_value is None:
            return

        families = self._upstream_families(directive)
        if families is not None:
            families = {family for family in families if not self._hides_content_type(directive, family)}
            if not families:
                return
        else:
            blocks = list(self._inheriting_blocks(directive, directive.parent))
            families = {
                family
                for block in blocks
                for family, pass_directive in self._passes(block)
                if not self._hides_content_type(pass_directive, family)
            }
            hidden = any(self._hides_content_type(directive, family) for family in UPSTREAM_FAMILIES)
            if hidden and not families and not any(self._answers_locally(block) for block in blocks):
                return

        if families:
            hide = " / ".join("`{0}_hide_header Content-Type;`".format(family) for family in sorted(families))
            reason = (
                "Also hide the upstream header with {hide}, or the response carries two Content-Type headers."
            ).format(hide=hide)
        elif "$" in ct_value:
            reason = (
                "`add_header` sends a second Content-Type header, and `default_type` does not expand variables; "
                "map the type with a `types` block instead."
            )
        else:
            reason = (
                "Use `types {{}} default_type {default_type};` instead of `add_header` to set Content-Type."
            ).format(default_type=quote_arg(ct_value))
        self.add_issue(directive=directive, reason=reason)

    @staticmethod
    def _passes(block):
        """(family, `*_pass`) pairs declared in `block`"""
        for family in UPSTREAM_FAMILIES:
            for pass_directive in block.find("{0}_pass".format(family), flat=True):
                yield family, pass_directive

    @classmethod
    def _upstream_families(cls, directive):
        """`*_pass` families in effect for the block declaring `directive`, or None when there are none"""
        for block in directive.parents:
            families = {family for family, _ in cls._passes(block)}
            if families:
                return families
            if block.self_context:
                return None
        return None

    @classmethod
    def _inheriting_blocks(cls, directive, block):
        """`block` and the nested server/location blocks whose `add_header` list still contains `directive`"""
        yield block
        for child in block.children:
            if child.name in ("server", "location") and directive in resolve_inherited_list(
                child, "add_header", "add_header_inherit"
            ):
                yield from cls._inheriting_blocks(directive, child)

    @staticmethod
    def _answers_locally(block):
        """Whether `block` builds a typed response itself that `add_header` is applied to"""
        if block.find("empty_gif", flat=True) or block.find("stub_status", flat=True):
            return True
        return any(
            not r.arg(0, "").isdigit() or r.arg(0) in TYPED_RETURN_STATUSES for r in block.find("return", flat=True)
        )

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
