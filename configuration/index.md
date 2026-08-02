# Configuration Guide

You can run `gixy` entirely from CLI flags, but a configuration file may also be used to read settings, including output formatting, where to write reports, which checks to run, whether to process `include` directives, some plugin-specific settings, output severity filtering, and where to look for custom variable drop-ins.

If you are looking for day-to-day CLI usage examples, see the [Usage Guide](https://gixy.io/usage/).

## Where config files live

By default, `gixy` looks in these locations (loaded in this order):

- `/etc/gixy/gixy.cfg`
- `~/.config/gixy/gixy.conf`

You can also point to a specific file:

```
# Load gixy configuration file from ./gixy.conf
gixy --config ./gixy.conf
```

And if you want a starting point, you can generate a config file from your current command-line args:

```
# Write a gixy configuration file to ./gixy.conf
gixy --write-config ./gixy.conf
```

## File format

The format is intentionally boring:

- `key = value`
- `#` starts a comment
- optional `[sections]` (mainly used for plugin settings)

Values may be quoted or not, and lists should be comma-separated.

Most keys match the long CLI flags with the leading `--` removed. For example:

- CLI: `--disable-includes`
- Config: `disable-includes = true`

`[sections]` blocks are equivalent to their appended, CLI flag usage. For example, the config equivalent of `--add-header-redefinition-headers X-Frame-Options` is:

```
[add_header_redefinition]
headers = X-Frame-Options
```

For non-plugin options, use the `[gixy]` block:

```
[gixy]
level = 2
```

## Settings you can configure

These are the knobs you can set in the config file.

### level

You may set the level of filtering applied to the output of `gixy`:

```
; Report issues of a given severity level or higher (-l for LOW, -ll for MEDIUM, -lll for HIGH)
level = 2
```

### format

Choose the output format:

```
format = console   # default, colored output
# format = text    # plain text (no ANSI)
# format = json    # machine-readable JSON
# format = sarif   # SARIF 2.1.0, e.g. for GitHub code scanning
```

### output

Write results to a file instead of stdout:

```
output = ./gixy-report.json
```

### debug

Run `gixy` in debug mode or not:

```
; Turn on debug mode
debug = false
```

### tests

You may wish to only run a specific set of tests:

```
; Comma-separated list of tests to exclusively run
tests = add_header_redefinition,hash_without_default,http_splitting
```

## skips

You may wish to skip specific tests:

```
; Comma-separated list of tests to exclusively skip
skips = proxy_pass_normalized,if_is_evil
```

### disable-includes

If enabled, `include` directives do not have their included-files read:

```
; Disable "include" directive processing
disable-includes = false
```

### vars-dirs

Provide directories containing custom variable drop-ins:

```
; Comma-separated list of directories with custom variable drop-ins
vars-dirs = ./vars,/etc/gixy/vars
```

If you do not know what vars-dirs is, you probably do not need it. When you do, the dedicated guide is in [Custom Variables & Drop-Ins](https://gixy.io/variables-dropins/).

## Minimal example

A tiny config that skips the `low_keepalive_requests` test, and saves a JSON-formatted report to `gixy-report.json`.

```
[gixy]
format = json
output = ./gixy-report.json
skips = low_keepalive_requests
```

Run it like this:

```
# Load gixy configuration file from ./gixy.conf
gixy --config ./gixy.conf
```

## Plugin-specific configuration

Most `gixy` settings are global and work well as shared defaults in a config file. Some plugins also expose their own flags/configurations (and those can be set via CLI or via the config file), but the details are specific to each check.

If you need to tune a specific plugin, start with its documentation:

- [add_header_redefinition](https://gixy.io/plugins/add_header_redefinition/)
- [origins](https://gixy.io/plugins/origins/)
- [regex_redos](https://gixy.io/plugins/regex_redos/)
