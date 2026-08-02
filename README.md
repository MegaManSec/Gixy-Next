# Gixy-Next: NGINX Configuration Security Scanner for Security Audits

## Overview

<a href="https://gixy.io/"><img width="192" height="192" alt="Gixy-Next Mascot Logo" style="float: right;" align="right" src="https://gixy.io/imgs/gixy.jpg" /></a>

Gixy-Next (Gixy) is an open-source NGINX configuration security scanner and hardening tool that statically analyzes your nginx.conf to detect security misconfigurations, hardening gaps, and common performance pitfalls before they reach production. It is an actively maintained fork of Yandex's [Gixy](https://github.com/yandex/gixy). Gixy-Next's source code is [available on GitHub](https://github.com/megamansec/gixy-next).

Gixy-Next can also be run in the browser on [this page](https://gixy.io/scanner/). No download is needed; you can scan your configurations on the website (locally, using WebAssembly).

### Quick start

Gixy-Next (the `gixy` or `gixy-next` CLI) is distributed on [PyPI](https://pypi.python.org/pypi/Gixy-Next). You can install it with pip or uv:

```shell-session
# pip
pip3 install gixy-next
# uv
uv pip install gixy-next
```

You can then run it:

```shell-session
# gixy defaults to reading /etc/nginx/nginx.conf
gixy
# But you can also specify a path to the configuration
gixy /opt/nginx.conf
```

### Scan a directory

Instead of a single file, you can point `gixy` at a directory. It will recursively scan it for `*.conf` files (skipping VCS/dependency directories like `.git` and `node_modules`) and analyze each one found:

```shell-session
# Recursively find and scan every *.conf file under /etc/nginx
gixy /etc/nginx
```

You can also export your NGINX configuration to a single dump file (see [nginx -T Live Configuration Dump](https://gixy.io/nginx-config-dump)):

```shell-session
# Dumps the full NGINX configuration into a single file (including all includes)
nginx -T > ./nginx-dump.conf
# Scan the dump elsewhere (or via stdin):
gixy ./nginx-dump.conf
# or
cat ./nginx-dump.conf | gixy -
```

### Web-based scanner

Instead of downloading and running Gixy-Next locally, you can use [this webpage](https://gixy.io/scanner/) and scan a configuration from your web browser (locally, using WebAssembly).

### Scan with Docker

Gixy-Next is available as a Docker image from [Docker Hub](https://hub.docker.com/r/megamansec/gixy-next/) or [GitHub Registry](https://github.com/MegaManSec/Gixy-Next/pkgs/container/gixy-next).

Scan a local config file by mounting it into the container:

```shell-session
# Use Github Registry
docker run --pull=always --rm -v "$PWD/nginx.conf:/nginx.conf:ro" ghcr.io/megamansec/gixy-next /nginx.conf
# Or Docker Hub
docker run --pull=always --rm -v "$PWD/nginx.conf:/nginx.conf:ro" megamansec/gixy-next /nginx.conf
```

Scan an NGINX live configuration dump:

```shell-session
# Dumps the full NGINX configuration into a single file (including all includes)
nginx -T > ./nginx-dump.conf
# Use Github Registry
docker run --pull=always --rm -v "$PWD/nginx-dump.conf:/nginx-dump.conf:ro" ghcr.io/megamansec/gixy-next /nginx-dump.conf
# Or Docker Hub
docker run --pull=always --rm -v "$PWD/nginx-dump.conf:/nginx-dump.conf:ro" megamansec/gixy-next /nginx-dump.conf
```

Scan from stdin:

```shell-session
# Use Github Registry
nginx -T | docker run --pull=always --rm -i ghcr.io/megamansec/gixy-next gixy-next -
# Or Docker Hub
nginx -T | docker run --pull=always --rm -i megamansec/gixy-next gixy-next -
```

## What it can do

Gixy-Next can detect a wide range of NGINX security and performance misconfigurations across `nginx.conf` and included configuration files. The following plugins are supported:

- [[add_header_content_type] Setting Content-Type via add_header](https://gixy.io/plugins/add_header_content_type/)
- [[add_header_multiline] Multiline response headers](https://gixy.io/plugins/add_header_multiline/)
- [[add_header_redefinition] Redefining of response headers by "add_header" directive](https://gixy.io/plugins/add_header_redefinition/)
- [[alias_traversal] Path traversal via misconfigured alias](https://gixy.io/plugins/alias_traversal/)
- [[allow_without_deny] Allow specified without deny](https://gixy.io/plugins/allow_without_deny/)
- [[default_server_flag] Missing default_server flag](https://gixy.io/plugins/default_server_flag/)
- [[error_log_off] `error_log` set to `off`](https://gixy.io/plugins/error_log_off/)
- [[hash_without_default] Missing default in hash blocks](https://gixy.io/plugins/hash_without_default/)
- [[host_spoofing] Request's Host header forgery](https://gixy.io/plugins/host_spoofing/)
- [[http2_misdirected_request] Missing HTTP/2 misdirected-request safeguard](https://gixy.io/plugins/http2_misdirected_request/)
- [[http_splitting] HTTP Response Splitting](https://gixy.io/plugins/http_splitting/)
- [[if_is_evil] If is evil when used in location context](https://gixy.io/plugins/if_is_evil/)
- [[invalid_regex] Invalid regex capture groups](https://gixy.io/plugins/invalid_regex/)
- [[low_keepalive_requests] Low `keepalive_requests`](https://gixy.io/plugins/low_keepalive_requests/)
- [[missing_worker_processes] Missing `worker_processes`](https://gixy.io/plugins/missing_worker_processes/)
- [[mixed_case_variable] Mixed-case variable references](https://gixy.io/plugins/mixed_case_variable/)
- [[origins] Problems with referer/origin header validation](https://gixy.io/plugins/origins/)
- [[overlapping_captures] Overlapping captures in rewrite redirect/args context](https://gixy.io/plugins/overlapping_captures/)
- [[proxy_buffering_off] Disabling `proxy_buffering`](https://gixy.io/plugins/proxy_buffering_off/)
- [[proxy_pass_normalized] `proxy_pass` path normalization issues](https://gixy.io/plugins/proxy_pass_normalized/)
- [[quic_bpf_reuseport] QUIC connections silently dropped after reload](https://gixy.io/plugins/quic_bpf_reuseport/)
- [[regex_redos] Regular expression denial of service (ReDoS)](https://gixy.io/plugins/regex_redos/)
- [[resolver_external] Using external DNS nameservers](https://gixy.io/plugins/resolver_external/)
- [[return_bypasses_allow_deny] Return directive bypasses allow/deny restrictions](https://gixy.io/plugins/return_bypasses_allow_deny/)
- [[ssl_stapling_without_resolver] OCSP stapling silently fails without a resolver](https://gixy.io/plugins/ssl_stapling_without_resolver/)
- [[ssrf] Server Side Request Forgery](https://gixy.io/plugins/ssrf/)
- [[stale_dns_cache] Outdated/stale cached DNS records used in proxy_pass](https://gixy.io/plugins/stale_dns_cache/)
- [[status_page_exposed] Ensures that status_page is not exposed to the world](https://gixy.io/plugins/status_page_exposed/)
- [[try_files_is_evil_too] `try_files` directive is evil without open_file_cache](https://gixy.io/plugins/try_files_is_evil_too/)
- [[unanchored_regex] Unanchored regular expressions](https://gixy.io/plugins/unanchored_regex/)
- [[unnamed_groups] Unnamed capture groups in rewrite query string](https://gixy.io/plugins/unnamed_groups/)
- [[valid_referers] none/blocked in valid_referers](https://gixy.io/plugins/valid_referers/)
- [[version_disclosure] Using insecure values for server_tokens](https://gixy.io/plugins/version_disclosure/)
- [[worker_rlimit_nofile_vs_connections] `worker_rlimit_nofile` must be at least twice `worker_connections`](https://gixy.io/plugins/worker_rlimit_nofile_vs_connections/)

Something not detected? Please open an [issue](https://github.com/MegaManSec/Gixy-Next/issues) on GitHub with what's missing!

## Usage (flags)

`gixy` defaults to reading a system's NGINX configuration from `/etc/nginx/nginx.conf`. You can also specify the location by passing it to `gixy`:

```shell-session
# Analyze the configuration in /opt/nginx.conf
gixy /opt/nginx.conf
```

You can run a focused subset of checks with `--tests`:

```shell-session
# Only run these checks
gixy --tests http_splitting,ssrf,version_disclosure
```

Or skip a few noisy checks with `--skips`:

```shell-session
# Run everything except these checks
gixy --skips low_keepalive_requests,worker_rlimit_nofile_vs_connections
```

To only report issues of a certain severity or higher, use the compounding `-l` flag:

```shell-session
# -l for LOW severity issues and higher, -ll for MEDIUM and higher, and -lll for only HIGH severity issues
gixy -ll
```

By default, the output of `gixy` is ANSI-colored; best viewed in a compatible terminal. You can use the `--format` (`-f`) flag with the `text` value to get an uncolored output:

```shell-session
$ gixy -f text

==================== Results ===================

Problem: [http_splitting] Possible HTTP-Splitting vulnerability.
Description: Using variables that can contain "\n" may lead to http injection.
Additional info: https://gixy.io/plugins/http_splitting/
Reason: At least variable "$action" can contain "\n"
Pseudo config:
include /etc/nginx/sites/default.conf;

	server {

		location ~ /v1/((?<action>[^.]*)\.json)?$ {
			add_header X-Action $action;
		}
	}


==================== Summary ===================
Total issues:
    Informational: 0
    Low: 0
    Medium: 0
    High: 1
```

You can also use `-f json` to get a reproducible, machine-readable JSON output:

```shell-session
$ gixy -f json
[{"config":"\nserver {\n\n\tlocation ~ /v1/((?<action>[^.]*)\\.json)?$ {\n\t\tadd_header X-Action $action;\n\t}\n}","description":"Using variables that can contain \"\\n\" or \"\\r\" may lead to http injection.","file":"/etc/nginx/nginx.conf","line":4,"path":"/etc/nginx/nginx.conf","plugin":"http_splitting","reason":"At least variable \"$action\" can contain \"\\n\"","reference":"https://gixy.io/plugins/http_splitting/","severity":"HIGH","summary":"Possible HTTP-Splitting vulnerability."}]
```

You can also use `-f sarif` to get a [SARIF 2.1.0](https://sarifweb.azurewebsites.net/) log, e.g. for uploading to GitHub code scanning:

```shell-session
# Write a SARIF report to a file, e.g. for `github/codeql-action/upload-sarif`
gixy -f sarif -o gixy-results.sarif
```

More flags for usage can be found by passing `--help` to `gixy`. You can also find more information in the [Usage Guide](https://gixy.io/usage/).

## Configuration and plugin options

Some plugins expose options which you can set via CLI flags or a configuration file. You can read more about those in the [Configuration guide](https://gixy.io/configuration/).

## Gixy-Next for NGINX security and compliance

Unlike running `nginx -t` which only checks syntax, Gixy-Next actually analyzes your configuration and detects unhardened instances and vulnerabilities.

With Gixy-Next, you can perform an automated NGINX configuration security review that can run locally on every change, whether for auditing, compliance, or general testing, helping produce actionable findings that help prevent unstable/slow NGINX servers, and reduce risk from unsafe directives and insecure defaults.

## Contributing

Gixy-Next is maintained by [Joshua Rogers](https://joshua.hu), but contributions are always welcome! You can help us in different ways, such as:

- Reporting bugs.
- Suggesting new plugins for detection.
- Improving documentation.
- Fixing, refactoring, improving, and writing new code.

Before submitting any changes in pull requests, please read the contribution guideline document, [Contributing to Gixy-Next](https://gixy.io/contributing/).

The official homepage of Gixy-Next is [https://gixy.io/](https://gixy.io/). Any changes to documentation in Gixy-Next will automatically be reflected on that website.

The source code can be found at [https://github.com/MegaManSec/Gixy-Next](https://github.com/MegaManSec/Gixy-Next).

## What is Gixy? (Background)

_Gixy_ is an NGINX configuration analyzer that was [originally](https://github.com/yandex/gixy) developed by Yandex's Andrew Krasichkov. It was first released in 2017 and has since become unmaintained. It does not support modern versions of Python, contains numerous bugs, and is limited in its functionality and ability to detect vulnerable NGINX configurations. Running the original Gixy today on a modern system will result in the following error:

```text
  File "gixy/core/sre_parse/sre_parse.py", line 61, in <module>
    "t": SRE_FLAG_TEMPLATE,
         ^^^^^^^^^^^^^^^^^
NameError: name 'SRE_FLAG_TEMPLATE' is not defined. Did you mean: 'SRE_FLAG_VERBOSE'?
```

Gixy-Next, therefore, is a fork that adds support for modern systems, adds new checks, performance improvements, hardening suggestions, and support for modern Python and NGINX versions.

### Why not `gixy-ng`?

Gixy-Next is actually a fork of `gixy-ng`, which itself was a fork of the original `gixy`. Gixy-Next was created after the maintainer of `gixy-ng` started producing large amounts of AI-assisted changes and auto-generated code that was both unreviewably large as well as broken.

After some time, the maintainer of `gixy-ng` began to commit AI-generated changes to the codebase which introduced obvious regressions, broke critical behavior of the tool (which anybody using the tool would have picked up), added random AI-tooling artifacts, and introduced code which simply did not do what it was supposed to do. Most importantly, the maintainer also **added marketing for their business to all documentation, all output, and all source code** of `gixy-ng`.

In other words, the `gixy-ng` maintainer took the original `gixy`, asked AI to make changes, introduced a bunch of bugs (and other AI slop), and then added advertising to the code. They also accepted contributions in the form of merge requests, but stripped the author's information (see [this](https://joshua.hu/gixy-ng-new-version-gixy-updated-checks#quality-degradation) post and [this](https://joshua.hu/gixy-ng-ai-slop-gixy-next-maintained) post).

Gixy-Next focuses on restoring quality, and has been battle-tested on NGINX configurations which are nearly 100,000-lines-long. It fixes bugs and misdetections introduced by changes introduced in `gixy-ng`, removes AI tool artifacts/junk, and tries to keep the codebase reviewable and maintainable. This fork is for those interested in clean code and long-term maintainability.
