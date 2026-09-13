class InvalidConfiguration(Exception):
    """The configuration could not be parsed/analyzed as valid nginx config.

    Raised for input that does not look like valid nginx configuration (e.g. a
    syntax error, or a directive missing a required argument). It signals a
    problem with the *input*, not a bug in Gixy-Next, and is handled gracefully
    by the CLI with a distinct exit code instead of a traceback.
    """

    pass


class MalformedDirective(InvalidConfiguration):
    """A single directive is structurally malformed (e.g. it is missing a
    required positional argument) such that Gixy-Next cannot analyze it.

    This is a kind of :class:`InvalidConfiguration`: it indicates the input is
    not valid nginx, not that Gixy-Next has a bug. Plugins should obtain
    required arguments via ``Directive.arg(index)`` so that a missing argument
    raises this (and is reported as malformed input) rather than crashing with
    an ``IndexError``.
    """

    def __init__(self, message, directive=None):
        super().__init__(message)
        self.directive = directive
