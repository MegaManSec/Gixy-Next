import gixy
from gixy.plugins.plugin import Plugin


class worker_rlimit_nofile_vs_connections(Plugin):
    """
    Insecure example:
        worker_connections 1024;
        worker_rlimit_nofile 1024;  # should be higher than worker_connections
    """

    summary = "worker_rlimit_nofile should be at least twice worker_connections."
    severity = gixy.severity.MEDIUM
    description = (
        "worker_rlimit_nofile should be at least twice the worker_connections value."
    )
    help_url = "https://gixy.io/plugins/worker_rlimit_nofile_vs_connections/"
    directives = ["worker_connections"]
    supports_full_config = True

    DEFAULT_WORKER_CONNECTIONS = 512
    DEFAULT_WORKER_RLIMIT_NOFILE = 1024  # best guess. most Linux distros use 1024.

    def __init__(self, config):
        super(worker_rlimit_nofile_vs_connections, self).__init__(config)
        self.has_directive = False

    def audit(self, directive):
        self.has_directive = True
        # get worker_connections value (a missing or non-numeric value is
        # malformed input)
        worker_connections = directive.int_arg(0)
        worker_rlimit_nofile_directive = directive.find_single_directive_in_scope(
            "worker_rlimit_nofile"
        )
        if worker_rlimit_nofile_directive:
            worker_rlimit_nofile = worker_rlimit_nofile_directive.int_arg(0)
            if worker_rlimit_nofile < worker_connections * 2:
                self.add_issue(
                    directive=[directive, worker_rlimit_nofile_directive],
                    reason="`worker_rlimit_nofile` should be at least twice `worker_connections`.",
                )
        else:
            worker_rlimit_nofile = self.DEFAULT_WORKER_RLIMIT_NOFILE
            if worker_rlimit_nofile < worker_connections * 2:
                self.add_issue(
                    directive=directive,
                    severity=gixy.severity.LOW,
                    reason=(
                        "Missing `worker_rlimit_nofile`, so workers inherit the open-file limit "
                        f"set by the service manager or container (often {worker_rlimit_nofile}). "
                        "Set `worker_rlimit_nofile`, or raise that limit, to at least twice "
                        f"`worker_connections` ({worker_connections * 2})."
                    ),
                )

    def post_audit(self, root):
        if self.has_directive:
            return

        worker_connections = self.DEFAULT_WORKER_CONNECTIONS

        worker_rlimit_nofile_directive = root.some("worker_rlimit_nofile")
        if worker_rlimit_nofile_directive and worker_rlimit_nofile_directive.args:
            worker_rlimit_nofile = worker_rlimit_nofile_directive.int_arg(0)
            if worker_rlimit_nofile < worker_connections * 2:
                self.add_issue(
                    directive=worker_rlimit_nofile_directive,
                    reason=(
                        "`worker_rlimit_nofile` should be at least twice the "
                        f"default `worker_connections` ({worker_connections})."
                    ),
                )
