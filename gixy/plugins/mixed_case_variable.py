import re

import gixy
from gixy.plugins.plugin import Plugin

_VAR_RE = re.compile(r"\$([a-z_][a-z0-9_]*|\{[a-z_][a-z0-9_]*\})", re.IGNORECASE)


class mixed_case_variable(Plugin):
    """
    Detects when the same NGINX variable is referenced with different cases
    within the same config.

    Since NGINX normalizes all variable names to lowercase, $My_Var and
    $MY_VAR are the same variable. Using both spellings in one config looks
    like two distinct variables and suggests a typo or oversight.

    Example:
        set $My_Var "hello";
        proxy_pass http://backend/$MY_VAR;  # same variable, different case
    """

    summary = "Same variable referenced with inconsistent case."
    severity = gixy.severity.LOW
    description = (
        "NGINX normalizes all variable names to lowercase. "
        "Referencing the same variable with different cases in one config "
        "is misleading and may indicate a typo."
    )
    help_url = "https://gixy.io/plugins/mixed_case_variable/"
    directives = []  # empty → receives every directive

    def __init__(self, config):
        super().__init__(config)
        # lowercase_name -> {original_case: first directive that used it}
        self._seen = {}
        self._finalized = False

    def audit(self, directive):
        for arg in directive.args:
            for m in _VAR_RE.finditer(arg):
                name = m.group(1).strip("{}")
                entry = self._seen.setdefault(name.lower(), {})
                entry.setdefault(name, directive)

    def _finalize(self):
        if self._finalized:
            return
        self._finalized = True
        for lower_name, cases in self._seen.items():
            if len(cases) <= 1:
                continue
            forms = sorted(cases)
            forms_str = ", ".join(f"`${f}`" for f in forms)
            self.add_issue(
                directive=[cases[f] for f in forms],
                reason=f"`${lower_name}` is used with inconsistent casing: {forms_str}.",
            )

    @property
    def issues(self):
        self._finalize()
        return self._issues
