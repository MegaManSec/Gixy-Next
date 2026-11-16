import re

import gixy
from gixy.core.utils import REGEX_ARGUMENT_DIRECTIVES
from gixy.directives.block import GeoBlock, MapBlock
from gixy.directives.directive import MapDirective
from gixy.plugins.plugin import Plugin

# nginx parses only single-digit `$1`..`$9`.
REFERENCE_RE = re.compile(r"\$(?:([1-9])|([A-Za-z_][A-Za-z0-9_]*)|\{([A-Za-z0-9_]+)\})")
IF_FILE_OPERATORS = frozenset(("-f", "!-f", "-d", "!-d", "-e", "!-e", "-x", "!-x"))


class capture_before_map(Plugin):
    r"""
    Insecure example:
        map $uri $section {
            ~^/([^/]+)/ $1;
        }
        location ~ ^/(.)/ {
            return 200 "$1$section";
        }
    """

    summary = "A $N capture followed by a regex map variable in one value causes heap overflow (CVE-2026-42533)."
    severity = gixy.severity.INFORMATION
    description = (
        "On nginx before 1.30.4/1.31.3, reading $N before a regex `map` variable in one value "
        "overflows a heap buffer (CVE-2026-42533). Upgrade, or use a named capture."
    )
    help_url = "https://gixy.io/plugins/capture_before_map/"
    directives = []

    def __init__(self, config):
        super().__init__(config)
        self._map_groups = {}

    def audit(self, directive):
        values = self._values(directive)
        if not values:
            return
        maps = self._regex_map_groups(directive)
        if not maps:
            return
        for value in values:
            captures = set()
            for match in REFERENCE_RE.finditer(value):
                if match.group(1):
                    captures.add(int(match.group(1)))
                    continue
                groups = maps.get((match.group(2) or match.group(3)).lower(), False)
                if captures and groups is not False and (groups is None or captures & groups):
                    self.add_issue(
                        directive=directive,
                        reason=(
                            "`$N` is read before the regex map variable `${0}`, which overflows "
                            "a heap buffer on nginx before 1.30.4/1.31.3 (CVE-2026-42533)."
                        ).format(match.group(2) or match.group(3)),
                    )
                    return

    @staticmethod
    def _values(directive):
        args = directive.args
        if isinstance(directive, MapDirective):
            parent = directive.parent
            while parent is not None and not isinstance(parent, (MapBlock, GeoBlock)):
                parent = parent.parent
            return args if isinstance(parent, MapBlock) else []
        if directive.name == "if":
            if len(args) == 3 and args[1] in ("=", "!="):
                return args[2:]
            if len(args) == 2 and args[0] in IF_FILE_OPERATORS:
                return args[1:]
            return []
        if directive.is_block or directive.name in REGEX_ARGUMENT_DIRECTIVES:
            return []
        if directive.name == "rewrite":
            return args[1:2]
        return args

    def _regex_map_groups(self, directive):
        root = directive
        while root.parent is not None:
            root = root.parent
        if id(root) not in self._map_groups:
            maps = {}
            for block in root.find_recursive("map"):
                if not isinstance(block, MapBlock):
                    continue
                for entry in block.gather_map_directives(block.children):
                    if entry.regex is None:
                        continue
                    groups = maps.get(block.variable, set())
                    if groups is None:
                        continue
                    try:
                        maps[block.variable] = groups | {
                            group for group in entry.regex.groups if isinstance(group, int) and group
                        }
                    except Exception:
                        maps[block.variable] = None
            self._map_groups[id(root)] = maps
        return self._map_groups[id(root)]
