import gixy
from gixy.core.exceptions import MalformedDirective
from gixy.directives.block import GeoBlock
from gixy.plugins.plugin import Plugin


class hash_without_default(Plugin):
    summary = "Missing default value in hash blocks (map/geo)."
    severity = gixy.severity.LOW
    description = (
        "A hash block without a default value yields an empty string for unmatched input, "
        "which may bypass security controls when the safe fallback is non-empty."
    )
    help_url = "https://gixy.io/plugins/hash_without_default/"
    directives = ["map", "geo"]

    def audit(self, directive):
        if not directive.is_block:
            raise MalformedDirective(
                "'{0}' must be a block.".format(directive.name), directive=directive
            )

        entries = directive.entries
        keys = {entry.src_val for entry in entries}
        if "default" in keys:
            return
        if isinstance(directive, GeoBlock):
            if {"0.0.0.0/0", "::/0"} <= keys:
                return
        elif len(entries) <= 1:
            return

        self.add_issue(
            directive=[directive] + directive.children,
            reason="Missing `default` entry in `{0}` for variable `${1}`.".format(
                directive.name, directive.variable
            ),
        )
