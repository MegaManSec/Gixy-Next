# [regex_redos] Regular Expression Denial of Service (ReDoS)

## What this check looks for

This plugin checks regex usage in directives like:

- `location ~ ...`
- `if ($var ~ ...)`
- `server_name ~ ...`
- `rewrite ...`
- `map` regex keys (`~...`)

It warns about patterns that may cause catastrophic backtracking. This issue is also known as [ReDoS](https://en.wikipedia.org/wiki/ReDoS).

## Why this is a problem

PCRE-style regex engines can take exponential time on certain inputs when the pattern is ambiguous (nested groups, overlapping alternations, repeated wildcards). With user-controlled input (URI, headers), a single request can burn a lot of CPU in one worker, allowing it to effectively be killed.

## Bad configuration

```
# Classic catastrophic backtracking style pattern
location ~ (a+)+$ {
    return 200 "ok";
}
```

A long string of `a` characters followed by a mismatch can keep the engine backtracking for an extremely long time (many seconds per request).

## Better configuration

Anchor the pattern, simplify it, and avoid nested quantifiers:

```
# Anchored, linear-time for simple inputs
location ~ ^a+$ {
    return 200 "ok";
}
```

General approaches:

- use `^` and `$` anchors whenever possible,
- avoid nested `(...)+` or `(.*)+` constructs,
- keep alternations unambiguous,
- constrain input length before matching expensive patterns.
- use [recheck](https://makenowjust-labs.github.io/recheck/playground/) against any regex patterns used to check for vulnerable expressions.

## Configuration

This plugin is opt-in. It does not run unless you point it at a ReDoS checking service.

### url

You can use the `url` option to configure the ReDoS checking server. The plugin will POST regex patterns to this endpoint and expects a response compatible with the `recheck` JSON format (for example, MegaManSec/recheck-http-api).

By default, this value is empty, which means the plugin skips.

#### CLI

```
# Send regex patterns to this service for evaluation
gixy --regex-redos-url "http://127.0.0.1:8080/"
```

#### Config

```
[regex_redos]
; URL of a compatible ReDoS checking server
url = http://127.0.0.1:8080/
```

## Additional notes

### Severity

This plugin reports issues at MEDIUM severity when the external checker confirms a regex is vulnerable to ReDoS. If the checker cannot evaluate an expression (server failure, network failure, invalid JSON, unknown complexity), nothing is reported.

### When this check is skipped

This plugin is intentionally "opt-in" and will silently skip in these cases:

- The Python `requests` dependency is not available.
- You did not configure a checker URL (the `--regex-redos-url` / plugin `url` option).

The plugin is opt-in because it requires calling to an external service. You can download an run that service, titled [recheck-http-api](https://github.com/megamansec/recheck-http-api).

## More information

For more information about ReDoS vulnerabilities in nginx, see [this post](https://joshua.hu/nginx-directives-regex-redos-denial-of-service-vulnerable).
