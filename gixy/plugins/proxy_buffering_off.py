import gixy
from gixy.plugins.plugin import Plugin


class proxy_buffering_off(Plugin):
    """
    Insecure example:
        proxy_buffering off;
    """

    summary = "Do not disable `proxy_buffering`."
    severity = gixy.severity.MEDIUM
    description = (
        "Disabling `proxy_buffering` can increase slow-client DoS risk by tying up "
        "upstream connections and workers."
    )
    help_url = "https://gixy.io/plugins/proxy_buffering_off/"
    directives = ["proxy_buffering"]

    def audit(self, directive):
        if not directive.args:
            return

        try:
            value = str(directive.args[0]).strip().lower()
        except (TypeError, IndexError):
            return

        if value == "off":
            self.add_issue(
                directive=directive,
                reason="`proxy_buffering` is set to `off`.",
            )
