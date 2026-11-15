import posixpath

import gixy
from gixy.core.variable import compile_script
from gixy.plugins.plugin import Plugin


class filesystem_root_exposure(Plugin):
    """
    Insecure examples:
        root /;

        location /files/ {
            alias /;
        }
    """

    summary = "Filesystem root used as a document root."
    severity = gixy.severity.HIGH
    description = (
        "A `root` or `alias` that resolves to `/` maps request paths onto the whole filesystem, "
        "so any file the worker processes can read, such as `/etc/passwd`, can be requested."
    )
    help_url = "https://gixy.io/plugins/filesystem_root_exposure/"
    directives = ["root", "alias"]

    def audit(self, directive):
        path = directive.path
        if "$" in path:
            if directive.name != "alias" or not self._capture_after_root(directive):
                return
        else:
            if directive.name == "alias":
                location = self._prefix_location(directive)
                if not location or (location.path.endswith("/") and not path.endswith("/")):
                    return
            if posixpath.normpath(path).strip("/"):
                return

        self.add_issue(
            directive=directive,
            reason="`{name} {path};` maps request paths onto the filesystem root.".format(
                name=directive.name, path=path
            ),
        )

    @staticmethod
    def _capture_after_root(directive):
        location = next((parent for parent in directive.parents if parent.name == "location"), None)
        if not location or not location.is_regex:
            return False
        literal = ""
        for part in compile_script(directive.path):
            if part.name is None:
                literal += part.value
                continue
            return (
                literal.endswith("/")
                and not posixpath.normpath(literal).strip("/")
                and part.provider is location
                and part.can_contain("/")
            )
        return False

    @staticmethod
    def _prefix_location(directive):
        for location in directive.parents:
            if location.name == "location":
                if not location.modifier or location.modifier == "^~":
                    return location
                return None
        return None
