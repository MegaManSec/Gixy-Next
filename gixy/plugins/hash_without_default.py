import gixy
from gixy.core.exceptions import MalformedDirective
from gixy.directives.block import GeoBlock, MapBlock
from gixy.directives.directive import MapDirective
from gixy.plugins.plugin import Plugin


class hash_without_default(Plugin):
    summary = "Missing default value in hash blocks (map/geo)."
    severity = gixy.severity.MEDIUM
    description = "A hash block without a default value may allow the bypassing of security controls."
    help_url = "https://gixy.io/plugins/hash_without_default/"
    directives = ["map", "geo"]

    def audit(self, directive):
        # Collect entries from this block, following includes when present
        if isinstance(directive, MapBlock):
            entries = list(directive.gather_map_directives(directive.children))
        elif isinstance(directive, GeoBlock):
            entries = list(directive.gather_geo_directives(directive.children))
        elif not directive.is_block:
            raise MalformedDirective(
                "'{0}' must be a block.".format(directive.name), directive=directive
            )
        else:
            entries = directive.children

        found_default = False
        for child in entries:
            if (
                isinstance(child, MapDirective)
                and child.src_val == "default"
                and child.dest_val is not None
            ):
                found_default = True
                break

        if found_default:
            return

        # Special-case: for map blocks, a single mapping entry without an explicit default
        # is commonly used to intentionally yield an empty string for all other cases.
        # This is especially useful with limit_req/limit_conn where empty keys disable limits.
        # In that scenario, requiring an explicit default creates noise. Therefore, only warn
        # for map when there are two or more mapping entries and no explicit default.
        if directive.name == "map":
            entries_count = 0
            for child in entries:
                if not isinstance(child, MapDirective):
                    continue
                if child.src_val == "default":
                    continue
                entries_count += 1

            # Do not warn for single-entry maps without default
            if entries_count <= 1:
                return

        # geo continues to require an explicit default regardless of entries count
        self.add_issue(
            directive=[directive] + directive.children,
            reason="Missing `default` entry in `{0}` for variable `${1}`.".format(
                directive.name, directive.variable
            ),
        )
