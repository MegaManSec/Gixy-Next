import gixy
from gixy.core.issue import Issue


class Plugin(object):
    summary = ""
    description = ""
    help_url = ""
    severity = gixy.severity.INFORMATION
    directives = []
    options = {}

    # New flag to indicate plugin supports full config analysis
    supports_full_config = False

    def __init__(self, config):
        self._issues = []
        self.config = config

    def add_issue(
        self,
        directive,
        summary=None,
        severity=None,
        description=None,
        reason=None,
        help_url=None,
    ):
        self._issues.append(
            Issue(
                self,
                directives=directive,
                summary=summary,
                severity=severity,
                description=description,
                reason=reason,
                help_url=help_url,
            )
        )

    def audit(self, directive):
        pass

    def post_audit(self, root):
        """Called after all directives have been audited with the full config tree.
        Only called if supports_full_config is True and a full config is detected."""
        pass

    @property
    def issues(self):
        return self._issues

    @property
    def name(self):
        return self.__class__.__name__
