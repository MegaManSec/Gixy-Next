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
                    reason=(
                        "Missing `worker_rlimit_nofile`. Assuming default "
                        f"({worker_rlimit_nofile}), "
                        "`worker_rlimit_nofile` should be at least twice `worker_connections`."
                    ),
                )

    def post_audit(self, root):
        if self.has_directive:
            return

        # If worker_connections isn't set for some reason, compare against the default value.
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
        else:
            # In the current code, this can never happen, since 1024 < 1024 is always false.
            # We keep this code around just in case we ever want to change the defaults, though.
            worker_rlimit_nofile = self.DEFAULT_WORKER_RLIMIT_NOFILE
            if worker_rlimit_nofile < worker_connections * 2:
                self.add_issue(
                    directive=root,
                    reason=(
                        "Missing `worker_rlimit_nofile` and `worker_connections`. "
                        "Assuming default `worker_rlimit_nofile`="
                        f"{worker_rlimit_nofile}, "
                        "`worker_rlimit_nofile` should be at least twice the "
                        f"default `worker_connections` ({worker_connections})."
                    ),
                )
