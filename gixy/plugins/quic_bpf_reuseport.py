import gixy
from gixy.plugins.plugin import Plugin


class quic_bpf_reuseport(Plugin):
    """Flag quic_bpf + reuseport + multi-worker combinations that silently drop QUIC connections after reload."""

    summary = "quic_bpf with reuseport and multiple workers silently drops QUIC connections after reload."
    severity = gixy.severity.HIGH
    description = (
        "When quic_bpf is enabled alongside reuseport on a QUIC listen socket "
        "and multiple worker processes, NGINX silently drops ~50% of QUIC connections "
        "after every reload due to stale BPF reuseport maps (nginx/nginx#425). "
        "Disable quic_bpf to resolve this."
    )
    help_url = "https://gixy.io/plugins/quic_bpf_reuseport/"
    directives = []
    supports_full_config = True

    def audit(self, directive):
        return

    def post_audit(self, root):
        quic_bpf = root.some("quic_bpf")
        if not quic_bpf or not quic_bpf.args or quic_bpf.args[0] != "on":
            return

        worker_procs = root.some("worker_processes")
        if not worker_procs or not worker_procs.args:
            return
        if worker_procs.args[0] == "1":
            return

        http_block = root.some("http", flat=False)
        if not http_block:
            return

        for server in http_block.find_all_contexts_of_type("server"):
            for listen in server.find("listen"):
                tokens = [t.lower() for t in listen.args]
                if "quic" in tokens and "reuseport" in tokens:
                    self.add_issue(
                        directive=quic_bpf,
                        reason=(
                            "quic_bpf on with reuseport on a QUIC listener and multiple workers "
                            "causes ~50% QUIC connection drops after reload (nginx/nginx#425)."
                        ),
                    )
                    return
