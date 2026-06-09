import gixy
from gixy.plugins.plugin import Plugin


class try_files_is_evil_too(Plugin):
    """
    Insecure example:
        location / {
            try_files $uri $uri/ /index.php$is_args$args;
        }
    """

    summary = "try_files used without open_file_cache."
    severity = gixy.severity.LOW
    description = "Using try_files without open_file_cache adds extra stat() calls per request and can cause significant performance overhead."
    help_url = "https://gixy.io/plugins/try_files_is_evil_too/"
    directives = ["try_files"]

    def audit(self, directive):
        # search for open_file_cache ...; on the same or higher level
        open_file_cache = directive.find_single_directive_in_scope("open_file_cache")
        if not open_file_cache or open_file_cache.args[0].lower() == "off":
            self.add_issue(
                severity=gixy.severity.LOW,
                directive=[directive]
                + ([open_file_cache] if open_file_cache is not None else []),
                reason="`try_files` introduces extra filesystem lookups without `open_file_cache`.",
            )
