import ipaddress

import gixy
from gixy.plugins.plugin import Plugin


class default_server_flag(Plugin):
    """
    Warn when multiple server blocks share the same listen socket and none is
    explicitly marked as default_server (or default). Explicitly setting
    default_server removes ambiguity.
    """

    summary = "Multiple servers share listen socket without default_server."
    severity = gixy.severity.MEDIUM
    description = (
        "When two or more server blocks listen on the same address:port, one "
        "should be marked with the 'default_server' (or 'default') flag to "
        "avoid ambiguity about which server handles unmatched requests."
    )
    help_url = "https://gixy.io/plugins/default_server_flag/"
    directives = []
    supports_full_config = True

    def audit(self, directive):
        # This plugin performs checks in post_audit over full config
        return

    def post_audit(self, root):
        # Gather all server blocks recursively
        server_blocks = list(root.find_all_contexts_of_type("server"))
        if len(server_blocks) < 2:
            # Single server cannot be ambiguous
            return

        # Map (module, listen socket) -> list of (server_block, listen_directive, is_default)
        listen_groups = {}

        for srv in server_blocks:
            module = self._enclosing_module(srv)
            listens = srv.find("listen")
            if not listens:
                # Only http gives a listen-less server an implicit socket
                if module != "http":
                    continue
                listen_groups.setdefault((module, "*:80"), []).append(
                    (srv, srv, False)
                )
                continue
            for listen in listens:
                key, is_default = self._parse_listen_key_and_default(listen.args)
                if not key:
                    # Could not parse a concrete socket
                    continue
                listen_groups.setdefault((module, key), []).append(
                    (srv, listen, is_default)
                )

        # For each listen group with multiple servers and none marked default_server,
        # raise one issue per group (pointing to the first listen directive).
        for (_, key), entries in listen_groups.items():
            if len(entries) < 2:
                continue
            has_default = any(is_def for (_, _, is_def) in entries)
            if has_default:
                continue
            # Report once per ambiguous listen group
            listen_directives = [listen for (srv, listen, is_def) in entries]
            self.add_issue(
                directive=listen_directives,
                summary=self.summary,
                description=(
                    f"No server marked as default_server for listen {key}. "
                    "Add 'default_server' to one server block listening on this socket."
                ),
                help_url=self.help_url,
            )

    def _enclosing_module(self, server):
        """Return the module context ('http', 'stream', 'mail') holding a server block."""
        for parent in server.parents:
            if parent.name in ("http", "stream", "mail"):
                return parent.name
        return None

    def _parse_listen_key_and_default(self, args):
        """
        Parse a listen directive arguments list into a normalized socket key and
        whether it contains the default flag.

        Returns: (key, is_default) where key is a string like "*:80",
        "127.0.0.1:80", "[::]:443". If parsing fails, key is None.
        """
        if not args:
            return None, False

        params = [a.lower() for a in args[1:]]
        is_default = any(p in ("default_server", "default") for p in params)

        if args[0].lower().startswith("unix:"):
            # Not supported for ambiguity check
            return None, is_default

        address, port = self._split_address_port(args[0])
        if address is None:
            return None, is_default

        return f"{address}:{port}", is_default

    def _split_address_port(self, socket):
        """
        Split a listen socket argument into a normalized address and port.

        nginx accepts "address:port", a bare "address" (port 80 is implied) or
        a bare "port" (the wildcard address is implied).
        """
        if socket.startswith("["):
            address, _, port = socket.partition("]")
            address = self._normalize_address(address[1:])
            port = port[1:] if port.startswith(":") else port
        elif socket.isdigit():
            address, port = "*", socket
        elif socket.count(":") == 1:
            address, _, port = socket.partition(":")
            address = self._normalize_address(address)
        elif ":" in socket:
            return None, None
        else:
            address, port = self._normalize_address(socket), ""

        if not port:
            port = "80"
        if not port.isdigit():
            return None, None
        return address, int(port)

    def _normalize_address(self, address):
        """Collapse the spellings nginx treats as one listen address."""
        if address in ("", "*", "0.0.0.0"):
            return "*"
        try:
            parsed = ipaddress.ip_address(address)
        except ValueError:
            return address
        if parsed.version == 6:
            return f"[{parsed.compressed}]"
        return parsed.compressed
