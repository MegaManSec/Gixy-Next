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
