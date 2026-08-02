# Usage Guide

Gixy-Next ships as the `gixy` and `gixy-next` CLI. It statically analyzes NGINX configuration (your `nginx.conf` plus any files it includes) and reports security and hardening issues, along with a few common performance footguns.

In-Browser Scanner

Gixy-Next can also be used in the browser on [this webpage](https://gixy.io/scanner/). No download is needed, you can just scan your configurations on the website (locally, using WebAssembly).

## Basic scan

If you have a standard NGINX install, this is usually enough:

```
# By-default scans /etc/nginx/nginx.conf
gixy
```

`gixy` can also read from a specific file, or even from stdin:

```
# Scan a specific file
gixy /opt/nginx/nginx.conf
# pipe into gixy and read from stdin
cat /opt/nginx/nginx.conf | gixy -
```

## Scan a rendered config dump

One of the easiest ways to get consistent results from `gixy` is to scan the fully rendered live configuration that NGINX sees (see [nginx -T Live Configuration Dump](https://gixy.io/nginx-config-dump)). NGINX can print that with `nginx -T`.

On the machine that has NGINX (or inside your NGINX container):

```
# Dump the full rendered/live NGINX config to a single file
nginx -T > nginx-dump.conf
```

Then you can copy `nginx-dump.conf` anywhere and scan it there:

```
# Scan the NGINX dump file ./nginx-dump.conf
gixy ./nginx-dump.conf
```

This workflow is especially handy when:

- Your NGINX config is spread across many `include` files
- You want your CI pipeline to scan exactly what NGINX is loading
- You are auditing production config without giving the scanner direct filesystem access

## Scan with Docker

Gixy-Next is available as a Docker image from [Docker Hub](https://hub.docker.com/r/megamansec/gixy-next/) or [GitHub Registry](https://github.com/MegaManSec/Gixy-Next/pkgs/container/gixy-next).

Scan a local config file by mounting it into the container:

```
# Use GitHub Registry
docker run --pull=always --rm -v "$PWD/nginx.conf:/nginx.conf:ro" ghcr.io/megamansec/gixy-next /nginx.conf
# Or Docker Hub
docker run --pull=always --rm -v "$PWD/nginx.conf:/nginx.conf:ro" megamansec/gixy-next /nginx.conf
```

Scan an NGINX live configuration dump:

```
nginx -T > ./nginx-dump.conf
# Use GitHub Registry
docker run --pull=always --rm -v "$PWD/nginx-dump.conf:/nginx-dump.conf:ro" ghcr.io/megamansec/gixy-next /nginx-dump.conf
# Or Docker Hub
docker run --pull=always --rm -v "$PWD/nginx-dump.conf:/nginx-dump.conf:ro" megamansec/gixy-next /nginx-dump.conf
```

Scan from stdin:

```
# Use GitHub Registry
nginx -T | docker run --pull=always --rm -i ghcr.io/megamansec/gixy-next gixy-next -
# Or Docker Hub
nginx -T | docker run --pull=always --rm -i megamansec/gixy-next gixy-next -
```

## Severity filtering

By default, `gixy` reports everything it finds. If you only care about higher-severity issues, use `-l` repeats:

```
# Show LOW severity issues and above
gixy -l

# Show MEDIUM severity issues and above
gixy -ll

# Show HIGH severity issues only
gixy -lll
```

## Choose which checks run

You can run a focused subset of checks with `--tests`:

```
# Only run these checks
gixy --tests http_splitting,ssrf,version_disclosure
```

Or skip a few noisy checks with `--skips`:

```
# Run everything except these checks
gixy --skips low_keepalive_requests,worker_rlimit_nofile_vs_connections
```

## Output formats

`gixy` can print to the console for humans or emit clean output for tooling:

```
# Console (default): colored outputs, readable sections.
gixy -f console

# Plaintext: readable sections without ANSI color codes.
gixy -f text

# JSON: Reproducible JSON, best for CI and post-processing.
gixy -f json

# SARIF 2.1.0: for tooling that consumes SARIF, e.g. GitHub code scanning.
gixy -f sarif
```

### SARIF output (GitHub code scanning)

The `sarif` format emits a [SARIF 2.1.0](https://sarifweb.azurewebsites.net/) log, which is a standard format understood by many code-scanning tools, including GitHub's. Write it to a file and upload it with [`github/codeql-action/upload-sarif`](https://github.com/github/codeql-action/tree/main/upload-sarif) to see findings as annotations on your PRs and in the Security tab:

```
# Write a SARIF report to a file
gixy -f sarif -o gixy-results.sarif
```

```
# Example GitHub Actions step
- name: Scan NGINX config with Gixy-Next
  run: gixy /etc/nginx/nginx.conf -f sarif -o gixy-results.sarif

- name: Upload SARIF results
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: gixy-results.sarif
```

## Write reports to a file

To save the report instead of printing it:

```
# Write plain text output to a file
gixy -f text -o gixy-report.txt

# Write JSON output to a file
gixy -f json -o gixy-report.json
```

## Debug mode

If something looks off (missing includes, weird parsing, unexpected results), debug mode is your friend:

```
# Enable debug mode
gixy --debug
```

## Include processing

By default, `gixy` processes `include` directives so it can analyze the full config tree. If you want to treat the input file as standalone, you can disable include processing:

```
# Do not read any files that are referenced in 'include' directives
gixy --disable-includes /path/to/nginx.conf
```

When scanning a rendered `nginx -T` dump, leaving includes enabled is usually fine, but disabling them can fix any odd edge cases such as when an include file could not be found on the system the dump was performed on.

## Custom variable drop-ins

If you ever see warnings about unknown variables, you may wish to specify them manually. You can point `gixy` to a directory containing files which define additional variables:

```
# Read all the *.cfg and *.conf files in ./vars,/etc/gixy/vars
gixy --vars-dirs ./vars,/etc/gixy/vars
```

More information about the expected files in these directories can be found in [Custom Variables & Drop-Ins](https://gixy.io/variables-dropins/).

## Plugin-specific configuration

Most `gixy` settings are global and work well as shared defaults in a config file. Some plugins also expose their own flags/configurations (and those can be set via CLI or via the config file), but the details are specific to each check.

If you need to tune a specific plugin, start with its documentation:

- [add_header_redefinition](https://gixy.io/plugins/add_header_redefinition/)
- [origins](https://gixy.io/plugins/origins/)
- [regex_redos](https://gixy.io/plugins/regex_redos/)

## Using a config file

If you do not want to pass the same flags every time you run `gixy`, you can load options from a config file:

```
# Load gixy configuration file from ./gixy.conf
gixy --config ./gixy.conf
```

You can also generate a config file from your current CLI arguments:

```
# Write a gixy configuration file to ./gixy.conf
gixy --write-config ./gixy.conf
```

Full details are found in the [Configuration Guide](https://gixy.io/configuration/).
