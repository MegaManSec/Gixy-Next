"""Main module for Gixy CLI"""

import argparse
import copy
import logging
import os
import sys

import gixy
from gixy.cli.argparser import create_parser
from gixy.core.config import Config
from gixy.core.exceptions import InvalidConfiguration
from gixy.core.manager import Manager as Gixy
from gixy.core.plugins_manager import PluginsManager
from gixy.formatters import get_all as formatters

LOG = logging.getLogger()

# Directories that are never worth descending into when scanning a repo for configs.
_IGNORED_DIR_NAMES = {".git", ".hg", ".svn", "node_modules", "__pycache__"}


def _collect_nginx_configs(directory):
    """Recursively find *.conf files under a directory, following symlinks.

    Directories and files are deduplicated by their real path, so a symlink
    cycle cannot hang the walk and layouts like sites-enabled/x.conf ->
    sites-available/x.conf yield the file only once.
    """
    found = []
    seen_dirs = set()
    seen_files = set()
    for root, dirs, files in os.walk(directory, followlinks=True):
        real_root = os.path.realpath(root)
        if real_root in seen_dirs:
            dirs[:] = []
            continue
        seen_dirs.add(real_root)
        # Sorted so that dedup by real path is deterministic
        dirs[:] = sorted(
            d for d in dirs if d not in _IGNORED_DIR_NAMES and not d.startswith(".")
        )
        for filename in files:
            if not filename.lower().endswith(".conf"):
                continue
            path = os.path.join(root, filename)
            real_path = os.path.realpath(path)
            if real_path in seen_files:
                continue
            seen_files.add(real_path)
            found.append(path)
    return sorted(found)


def _init_logger(debug=False):
    LOG.handlers = []
    log_level = logging.DEBUG if debug else logging.INFO

    LOG.setLevel(log_level)
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(logging.Formatter("[%(module)s]\t%(levelname)s\t%(message)s"))
    LOG.addHandler(handler)
    LOG.debug("logging initialized")


def _str_to_bool(value):
    """Parse flexible boolean values for plugin CLI options.

    Accepts common forms like true/false, yes/no, on/off, 1/0 (case-insensitive).
    """
    if isinstance(value, bool):
        return value

    text = str(value).strip().lower()
    truthy = {"1", "true", "yes", "y", "on"}
    falsy = {"0", "false", "no", "n", "off"}

    if text in truthy:
        return True
    if text in falsy:
        return False

    raise argparse.ArgumentTypeError(
        "Expected a boolean value (true/false, yes/no, 1/0), got {!r}".format(value)
    )


def _create_plugin_help(plugin_cls, opt_key, option):
    """Build help text for a plugin option, including usage hints and default.

    Attempts to use plugin-provided descriptions via optional
    `options_help` mapping on the plugin class.
    """
    if isinstance(option, (tuple, list, set)):
        seq = sorted(option) if isinstance(option, set) else list(option)
        default = ",".join(map(str, seq))
        usage_hint = "Comma-separated list."
    else:
        default = str(option)
        usage_hint = None

    if isinstance(option, bool):
        usage_hint = "Boolean (true/false, yes/no, 1/0)."

    # Plugin-specific description if provided
    base_desc = ""
    if hasattr(plugin_cls, "options_help"):
        options_help = plugin_cls.options_help
        if isinstance(options_help, dict):
            base_desc = options_help.get(opt_key, "")

    parts = [p for p in [base_desc, usage_hint, "Default: {0}".format(default)] if p]
    return " ".join(parts)


def _get_cli_parser():
    parser = create_parser()
    parser.add_argument(
        "nginx_files",
        nargs="*",
        type=str,
        default=["/etc/nginx/nginx.conf"],
        metavar="nginx.conf",
        help="Path to nginx.conf, e.g. /etc/nginx/nginx.conf, a directory to scan "
        "recursively for *.conf files, or - for stdin",
    )

    parser.add_argument(
        "-v", "--version", action="version", version="Gixy v{0}".format(gixy.version)
    )

    parser.add_argument(
        "-l",
        "--level",
        dest="level",
        action="count",
        default=0,
        help="Report issues of a given severity level or higher (-l for LOW, -ll for MEDIUM, -lll for HIGH)",
    )

    default_formatter = "console" if sys.stdout.isatty() else "text"
    available_formatters = formatters().keys()

    parser.add_argument(
        "-f",
        "--format",
        dest="output_format",
        choices=available_formatters,
        default=default_formatter,
        type=str,
        help="Specify output format",
    )

    parser.add_argument(
        "-o",
        "--output",
        dest="output_file",
        type=str,
        default="",
        help="Write report to file",
    )

    parser.add_argument(
        "-d",
        "--debug",
        dest="debug",
        action="store_true",
        default=False,
        help="Turn on debug mode",
    )

    parser.add_argument(
        "--tests",
        dest="tests",
        type=str,
        default="",
        help="Comma-separated list of tests to exclusively run",
    )

    parser.add_argument(
        "--skips",
        dest="skips",
        type=str,
        default="",
        help="Comma-separated list of tests to exclusively skip",
    )

    parser.add_argument(
        "--disable-includes",
        dest="disable_includes",
        action="store_true",
        default=False,
        help='Disable "include" directive processing',
    )

    parser.add_argument(
        "--vars-dirs",
        dest="vars_dirs",
        type=str,
        default="",
        help="Comma-separated list of directories with custom variable drop-ins",
    )

    group = parser.add_argument_group("plugins options")
    for plugin_cls in PluginsManager().plugins_classes:
        name = plugin_cls.__name__
        if not plugin_cls.options:
            continue

        options = copy.deepcopy(plugin_cls.options)
        for opt_key, opt_val in options.items():
            option_name = "--{plugin}-{key}".format(plugin=name, key=opt_key).replace(
                "_", "-"
            )
            dst_name = "{plugin}:{key}".format(plugin=name, key=opt_key)
            if isinstance(opt_val, (tuple, list, set)):
                opt_type = str
                if isinstance(opt_val, set):
                    default_val = ",".join(map(str, sorted(opt_val)))
                else:
                    default_val = ",".join(map(str, opt_val))
            elif isinstance(opt_val, bool):
                opt_type = _str_to_bool
                default_val = opt_val
            else:
                opt_type = type(opt_val)
                default_val = opt_val

            group.add_argument(
                option_name,
                metavar=opt_key,
                dest=dst_name,
                type=opt_type,
                default=default_val,
                help=_create_plugin_help(plugin_cls, opt_key, opt_val),
            )

    return parser


def main():
    parser = _get_cli_parser()
    args = parser.parse_args()
    _init_logger(args.debug)

    # generate a list of user-expanded absolute paths from the nginx_files input arguments
    nginx_files = []

    for input_path in args.nginx_files:
        if input_path == gixy.STDIN_ARG:
            if len(args.nginx_files) > 1:
                sys.stderr.write("Expected either file paths or stdin, got both.\n")
                sys.exit(1)

            nginx_files.append(gixy.STDIN_ARG)
        else:
            path = os.path.abspath(os.path.expanduser(input_path))

            if not os.path.exists(path):
                sys.stderr.write(
                    "File {path!r} was not found.\nPlease specify correct path to configuration.\n".format(
                        path=path
                    )
                )
                sys.exit(1)

            if os.path.isdir(path):
                found = _collect_nginx_configs(path)
                if not found:
                    sys.stderr.write(
                        "No nginx configuration files (*.conf) were found under directory {path!r}.\n".format(
                            path=path
                        )
                    )
                    sys.exit(1)
                nginx_files.extend(found)
            else:
                nginx_files.append(path)

    try:
        severity = gixy.severity.ALL[args.level]
    except IndexError:
        sys.stderr.write(
            "Too high level filtering. Maximum level: -{0}\n".format(
                "l" * (len(gixy.severity.ALL) - 1)
            )
        )
        sys.exit(1)

    if args.tests:
        tests = [x.strip() for x in args.tests.split(",")]
    else:
        tests = None

    if args.skips:
        skips = [x.strip() for x in args.skips.split(",")]
    else:
        skips = None

    config = Config(
        severity=severity,
        output_format=args.output_format,
        output_file=args.output_file,
        plugins=tests,
        skips=skips,
        allow_includes=not args.disable_includes,
        vars_dirs=[x.strip() for x in args.vars_dirs.split(",")]
        if args.vars_dirs
        else None,
    )

    for plugin_cls in PluginsManager().plugins_classes:
        name = plugin_cls.__name__
        options = copy.deepcopy(plugin_cls.options)
        for opt_key, opt_val in options.items():
            option_name = "{name}:{key}".format(name=name, key=opt_key)
            if option_name not in vars(args):
                continue

            val = getattr(args, option_name)
            if val is None:
                continue

            if isinstance(opt_val, (tuple, list, set)):
                if isinstance(val, str) and not val.strip():
                    if isinstance(opt_val, tuple):
                        val = ()
                    elif isinstance(opt_val, set):
                        val = set()
                    else:
                        val = []
                    options[opt_key] = val
                    continue

            if isinstance(opt_val, tuple):
                val = tuple([x.strip() for x in val.split(",")])
            elif isinstance(opt_val, set):
                val = set([x.strip() for x in val.split(",")])
            elif isinstance(opt_val, list):
                val = [x.strip() for x in val.split(",")]
            options[opt_key] = val
        config.set_for(name, options)

    formatter = formatters()[config.output_format]()
    failed = False
    for path in nginx_files:
        with Gixy(config=config) as yoda:
            try:
                if path == gixy.STDIN_ARG:
                    with os.fdopen(sys.stdin.fileno(), "rb") as fdata:
                        yoda.audit(gixy.STDIN_NAME, fdata, is_stdin=True)
                else:
                    with open(path, mode="rb") as fdata:
                        yoda.audit(path, fdata, is_stdin=False)
            except InvalidConfiguration:
                failed = True
            formatter.feed(path, yoda)
            failed = failed or sum(yoda.stats.values()) > 0

    if args.output_file:
        with open(config.output_file, "w") as f:
            f.write(formatter.flush())
    else:
        print(formatter.flush())

    if failed:
        # If something found - exit code must be 1, otherwise 0
        sys.exit(1)
    sys.exit(0)


if (
    __name__ == "__main__"
):  # pragma: no cover - invoked only via `python -m gixy.cli.main`
    main()
