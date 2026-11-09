import ipaddress

AUTH_DIRECTIVES = ("auth_basic", "auth_request", "auth_jwt", "auth_oidc")


def is_indexed_name(name):
    return isinstance(name, int) or (len(name) == 1 and "1" <= name <= "9")


def resolve_inherited_single(scope, name):
    """Effective directive for an inheritable single-value directive.

    Walks from `scope` up to the root; the nearest scope that declares
    `name` wins, and within a scope the last declaration wins (nginx
    inheritance semantics). Returns the directive, or None when it is
    not set anywhere up the chain.
    """
    current = scope
    while current:
        matches = [
            c
            for c in current.children
            if (c.name or "").lower() == name and c.args
        ]
        if matches:
            return matches[-1]
        current = getattr(current, "parent", None)
    return None


def parse_listen_key_and_default(args):
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

    address, port = split_address_port(args[0])
    if address is None:
        return None, is_default

    key = f"{address}:{port}"
    for datagram in ("udp", "quic"):
        if datagram in params:
            key = f"{key} {datagram}"
            break
    return key, is_default


def split_address_port(socket):
    """
    Split a listen socket argument into a normalized address and port.

    nginx accepts "address:port", a bare "address" (port 80 is implied) or
    a bare "port" (the wildcard address is implied).
    """
    if socket.startswith("["):
        address, _, port = socket.partition("]")
        address = normalize_address(address[1:])
        port = port[1:] if port.startswith(":") else port
    elif socket.isdigit():
        address, port = "*", socket
    elif socket.count(":") == 1:
        address, _, port = socket.partition(":")
        address = normalize_address(address)
    elif ":" in socket:
        return None, None
    else:
        address, port = normalize_address(socket), ""

    if not port:
        port = "80"
    if not port.isdigit():
        return None, None
    return address, int(port)


def normalize_address(address):
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
