import contextlib
import re

import crossplane
from crossplane.errors import NgxParserBaseException
from crossplane.ext.lua import LuaBlockPlugin
from crossplane.lexer import register_external_lexer
from crossplane.parser import _prepare_if_args

import os
import tempfile

# OpenResty's *_by_lua_block directives that crossplane does not register itself.
register_external_lexer(
    directives=(
        "exit_worker_by_lua_block",
        "server_rewrite_by_lua_block",
        "ssl_client_hello_by_lua_block",
        "preread_by_lua_block",
    ),
    lexer=LuaBlockPlugin().lex,
)


@contextlib.contextmanager
def config_path(data):
    """Yield a filesystem path holding ``data``: a temporary file, or on Linux
    an anonymous in-memory file when no temporary directory is writable."""
    try:
        tmp = tempfile.NamedTemporaryFile(mode="wb", suffix=".conf", delete=False)
    except OSError:
        if not (hasattr(os, "memfd_create") and os.path.isdir("/proc/self/fd")):
            raise
        tmp = None
    if tmp is None:
        fd = os.memfd_create("gixy.conf")
        try:
            with open(fd, "wb", closefd=False) as memfile:
                memfile.write(data)
            yield "/proc/self/fd/{0}".format(fd)
        finally:
            os.close(fd)
        return
    try:
        with tmp:
            tmp.write(data)
        yield tmp.name
    finally:
        os.unlink(tmp.name)


def _process_nginx_string(value):
    r"""
    Decode nginx's string escapes while preserving PCRE escapes such as \d.
    """
    if not isinstance(value, str):
        return value

    escapes = {"n": "\n", "r": "\r", "t": "\t"}
    return re.sub(r"""\\([\\'"nrt])""", lambda m: escapes.get(m[1], m[1]), value)


def _tokenize_lua_content(content):
    """
    Treat Lua content as opaque for security analysis.
    Gixy's security plugins don't analyze Lua syntax, so we just preserve the content as-is.
    """
    if content is None:
        return []

    if isinstance(content, bytes):
        content = content.decode("utf-8", errors="replace")
    elif not isinstance(content, str):
        content = str(content)

    # Return the content as a single opaque token
    # This preserves the Lua code but doesn't try to parse its internal structure
    return [content]


class ParseException(Exception):
    """Exception for parsing errors that mimics pyparsing.ParseException interface"""

    def __init__(self, msg, line=1):
        super(ParseException, self).__init__(msg)
        self.msg = msg
        self.line = line


def scan_tokens(tokens):
    """Raise on an unexpected "{" or "}", and on a stray ";" that ends a block
    or the file, as nginx does. Return the line of each statement that follows
    any other stray ";", in order."""
    depth, pending, stray, recovered = 0, False, None, []
    for token, line, quoted in tokens:
        if not quoted and token.startswith("#"):
            continue
        if stray is not None:
            if not quoted and token in ("{", "}"):
                raise ParseException('unexpected ";"', stray)
            stray = None
            if not quoted and token == ";":
                continue
            recovered.append(line)
        if quoted:
            pending = True
        elif token == "{":
            if not pending:
                raise ParseException('unexpected "{"', line)
            depth, pending = depth + 1, False
        elif token == "}":
            if pending or not depth:
                raise ParseException('unexpected "}"', line)
            depth -= 1
        elif token == ";":
            if not pending:
                stray = line
            pending = False
        else:
            pending = True
    if stray is not None:
        raise ParseException('unexpected ";"', stray)
    return recovered


def raise_on_crossplane_failure(parsed):
    if not isinstance(parsed, dict) or parsed.get("status") != "failed":
        return

    # Prefer top-level aggregated errors, fall back to per-file errors.
    err = None
    errs = parsed.get("errors") or []
    if errs:
        err = errs[0]
    else:
        cfg = parsed.get("config") or []
        if cfg and (cfg[0].get("errors") or []):
            err = cfg[0]["errors"][0]

    if err:
        msg = err.get("error") or "Failed to parse nginx config"
        line = err.get("line", None) or err.get("lineno", None) or 1
        raise ParseException(msg, line)


r"""
Legacy note:

This module previously exposed a pyparsing-like ParseResults. We now normalize
crossplane output directly into a lightweight dict node structure and return
list[dict] from RawParser.

If these changes are ever reverted, please do not forget to change
value_wq = Regex(r'(?:\([^\s;]*\)|\$\{\w+\}|[^\s;(){}])+')
to
value_wq = Regex(r'(?:\([^\s;]*\)|\$\{\w+\}|\\[(){};\s]|[^\s;{}])+')
"""


class RawParser(object):
    """
    A class that parses nginx configuration with crossplane
    """

    def parse(self, data):
        """Parse nginx configuration content and return normalized nodes (list[dict])."""
        if isinstance(data, bytes):
            content = data.decode("utf-8", errors="replace")
        else:
            content = data

        # Remove UTF-8 BOM if present (works for both bytes->string and string input)
        if content.startswith("\ufeff"):
            content = content[1:]

        if not content:
            return []

        try:
            with config_path(content.encode("utf-8")) as temp_filename:
                recovered = scan_tokens(crossplane.lex(temp_filename))
                # Parse using crossplane with relaxed context checking for standalone configs
                parsed = crossplane.parse(
                    temp_filename,
                    single=True,
                    strict=False,  # Allow directives outside their normal context
                    check_ctx=False,  # Skip context validation
                    check_args=False,  # Skip argument validation
                    comments=True,  # Include comments in the output
                )

                raise_on_crossplane_failure(parsed)
                return self._normalize_crossplane(parsed, recovered)

        except NgxParserBaseException as e:
            # Convert crossplane exception to ParseException format
            line = getattr(e, "line", None) or getattr(e, "lineno", None) or 1
            raise ParseException(str(e), line=line)
        except ParseException:
            raise
        except Exception as e:
            raise ParseException(str(e), line=1) from e

    def parse_path(self, path):
        """Parse nginx configuration by file path and return normalized nodes (list[dict])."""
        try:
            recovered = scan_tokens(crossplane.lex(path))
            parsed = crossplane.parse(
                path,
                single=True,
                strict=False,  # Allow directives outside their normal context
                check_ctx=False,  # Skip context validation
                check_args=False,  # Skip argument validation
                comments=True,  # Include comments in the output
            )
            raise_on_crossplane_failure(parsed)
            return self._normalize_crossplane(parsed, recovered)
        except NgxParserBaseException as e:
            line = getattr(e, "line", None) or getattr(e, "lineno", None) or 1
            # Convert crossplane error to ParseException format
            raise ParseException(str(e), line=line)
        except ParseException:
            raise
        except Exception as e:
            raise ParseException(str(e), line=1) from e

    def _normalize_crossplane(self, crossplane_data, recovered=()):
        """Convert crossplane JSON output to a normalized list[dict] node structure.

        Node shapes:
            {"kind": "directive", "name": str, "args": list[str]}
            {"kind": "block", "name": str, "args": list[str], "children": list[dict], "raw": Optional[list[str]]}
            {"kind": "include", "name": "include", "args": list[str]}
            {"kind": "file_delimiter", "file": str}
            {"kind": "comment", "text": str}
            {"kind": "unexpected", "text": str}
        """
        result = []
        recovered = iter(recovered)

        if not crossplane_data or "config" not in crossplane_data:
            return result

        config_list = crossplane_data["config"]
        if not config_list:
            return result

        multi_file = len(config_list) > 1
        for file_data in config_list:
            if "parsed" in file_data and file_data["parsed"]:
                if multi_file:
                    result.append(
                        {
                            "kind": "file_delimiter",
                            "file": file_data.get("file", "unknown"),
                            "line": None,
                        }
                    )
                result.extend(self._normalize_blocks(file_data["parsed"], recovered))

        return result

    def _normalize_blocks(self, blocks, recovered):
        """Normalize crossplane 'parsed' list into list[dict] nodes."""
        result = []

        # Filter out inline comments (comments that share line numbers with directives)
        line_numbers_with_directives = set()
        for item in blocks:
            if isinstance(item, dict) and item.get("directive") != "#":
                line = item.get("line")
                if line is not None:
                    line_numbers_with_directives.add(line)

        filtered_blocks = []
        for item in blocks:
            if isinstance(item, dict) and item.get("directive") == "#":
                # Skip comments that are on the same line as directives (inline comments)
                if item.get("line") not in line_numbers_with_directives:
                    filtered_blocks.append(item)
            else:
                filtered_blocks.append(item)

        for node in filtered_blocks:
            if not isinstance(node, dict):
                continue

            if node.get("directive") == ";":
                result.append({"kind": "unexpected", "text": ";", "line": node.get("line")})
                if not node.get("args"):
                    continue
                line = next(recovered, node.get("line"))
                node = dict(node, directive=node["args"][0], args=node["args"][1:], line=line)
                if node["directive"] == "if":
                    _prepare_if_args(node)

            directive_name = _process_nginx_string(node.get("directive", ""))
            args = [_process_nginx_string(arg) for arg in node.get("args", [])]

            if "block" in node:
                # Block directive
                children = self._normalize_blocks(node["block"], recovered)
                if directive_name == "if":
                    # Normalize condition args for if-blocks
                    args = self._parse_if_condition(args)
                normalized = {
                    "kind": "block",
                    "name": directive_name,
                    "args": list(args),
                    "children": children,
                    "line": node.get("line"),
                }
                result.append(normalized)
            else:
                # Simple directive / comment / include / lua blocks represented as directives
                if directive_name == "#":
                    comment_text = node.get("comment", "").strip()
                    if comment_text.startswith(
                        "configuration file "
                    ) and comment_text.endswith(":"):
                        file_path = comment_text[len("configuration file "):-1]
                        result.append(
                            {
                                "kind": "file_delimiter",
                                "file": file_path,
                                "line": node.get("line"),
                            }
                        )
                    else:
                        result.append(
                            {
                                "kind": "comment",
                                "text": comment_text,
                                "line": node.get("line"),
                            }
                        )
                    continue

                if directive_name == "include":
                    result.append(
                        {
                            "kind": "include",
                            "name": "include",
                            "args": args,
                            "line": node.get("line"),
                        }
                    )
                    continue

                if directive_name.endswith("_lua_block"):
                    # Treat as a block with raw content preserved for tests/tools
                    raw = []
                    if args and args[0]:
                        raw = _tokenize_lua_content(args[0])
                    result.append(
                        {
                            "kind": "block",
                            "name": directive_name,
                            "args": [],
                            "children": [],
                            "raw": raw,
                            "line": node.get("line"),
                        }
                    )
                    continue

                # Regular directive
                result.append(
                    {
                        "kind": "directive",
                        "name": directive_name,
                        "args": args,
                        "line": node.get("line"),
                    }
                )

        return result

    def _parse_if_condition(self, args):
        """Normalize if-condition arguments as a flat list of tokens."""
        return list(args or [])
