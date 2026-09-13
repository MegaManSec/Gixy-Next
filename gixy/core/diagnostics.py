MALFORMED = "malformed"
INTERNAL = "internal"
ALL_KINDS = [MALFORMED, INTERNAL]


class Diagnostic(object):
    """A non-finding problem encountered while parsing or auditing a config.

    ``kind`` is "malformed" (the input is not valid nginx) or "internal" (an
    unexpected failure, i.e. a likely Gixy-Next bug); the CLI maps each to its
    own exit code. ``phase`` is "parse" or "audit". The remaining fields locate
    the problem and are all optional, since a diagnostic may be raised before
    any directive exists.
    """

    def __init__(
        self,
        kind,
        phase,
        message,
        directive=None,
        line=None,
        file=None,
        plugin=None,
        traceback=None,
    ):
        if kind not in ALL_KINDS:
            raise ValueError("Unknown diagnostic kind: {0!r}".format(kind))
        self.kind = kind
        self.phase = phase
        self.message = message
        self.directive = directive
        self.line = line
        self.file = file
        self.plugin = plugin
        self.traceback = traceback

    def __repr__(self):
        return "Diagnostic({0!r}, {1!r}, {2!r}, directive={3!r}, line={4!r}, file={5!r}, plugin={6!r})".format(
            self.kind,
            self.phase,
            self.message,
            self.directive,
            self.line,
            self.file,
            self.plugin,
        )
