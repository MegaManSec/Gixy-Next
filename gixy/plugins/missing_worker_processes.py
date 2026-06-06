import gixy
from gixy.plugins.plugin import Plugin
from gixy.directives.directive import Directive


class missing_worker_processes(Plugin):
    """
    Recommend setting worker_processes to auto if it's unset.

    If worker_processes is explicitly set anywhere, we assume it is deliberate
    and skip the check entirely.
    """

    summary = "Unset worker_processes defaults to single worker process."
    severity = gixy.severity.MEDIUM
    description = (
        "If worker_processes is unset, NGINX defaults to 1. In most cases, "
        "setting worker_processes to auto (one worker per CPU core) is recommended."
    )
    help_url = "https://gixy.io/plugins/missing_worker_processes/"
    directives = ["worker_processes"]
    supports_full_config = True

    def __init__(self, config):
        super(missing_worker_processes, self).__init__(config)
        self.has_directive = False

    def audit(self, directive):
        # Only count worker_processes when it is in the main (root) context.
        # nginx only allows this directive in the main context; if placed inside
        # http{} or server{} nginx -t rejects it, so it must not suppress the warning.
        # The root Block has name=None and parent=None; a main-context directive's
        # parent is that root instance.
        if directive.parent is not None and directive.parent.name is None:
            self.has_directive = True
        return

    def post_audit(self, root):
        if self.has_directive:
            return

        fake = Directive("#", ["worker_processes 1"]) # hacky way to get a directive in the output
        fake.set_parent(root)
        root.children.append(fake)

        self.add_issue(
            directive=fake,
            reason="Missing `worker_processes`. NGINX will only use one process (one CPU) by default.",
        )
