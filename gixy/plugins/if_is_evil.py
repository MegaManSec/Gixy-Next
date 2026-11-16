import gixy
from gixy.plugins.plugin import Plugin


class if_is_evil(Plugin):
    """
    Insecure example:
        location / {
            if ($request_method = POST) {
                add_header X-Debug 1;
            }
            proxy_pass http://backend;
        }
    """

    summary = "If is evil when used in location context."
    severity = gixy.severity.MEDIUM
    description = (
        "The if directive has pitfalls in location context: in some cases it does not do what you expect, "
        "but something completely different. In some cases it can even segfault. Avoid it where possible."
    )
    help_url = "https://gixy.io/plugins/if_is_evil/"
    directives = []

    def audit(self, directive):
        if directive.name == "if" and not directive.children:
            location = directive.parent
            if location and location.name == "location" and location.some("try_files", flat=False):
                self.add_issue(
                    directive=[directive, location.some("try_files", flat=False)],
                    reason="An empty `if` within a `location` that uses `try_files` still replaces the location's "
                    "configuration when it matches, so `try_files` does not run.",
                )
            return

        parent = directive.parent
        # if immediate parent is not "if" break out
        if not parent or parent.name != "if":
            return

        # "rewrite ... last", "rewrite ... redirect", "rewrite ... permanent" and a rewrite to an
        # absolute URL (which redirects whatever its flag) are safe
        if directive.name == "rewrite" and (directive.flag == "last" or directive.redirects):
            return

        # "return" is safe too
        if directive.name == "return":
            return

        grandparent = parent.parent

        if grandparent and grandparent.name == "location":
            reason = "Directive `{directive}` is unsafe inside `if` within a `location` block.".format(
                directive=directive.name
            )
            if directive.name == "rewrite":
                reason = (
                    "Directive `rewrite` is only considered safe in `if` within "
                    "`location` when the flag is `last`, `redirect`, or `permanent`, "
                    "or when it redirects to an absolute URL."
                )
            self.add_issue(directive=directive, reason=reason)
