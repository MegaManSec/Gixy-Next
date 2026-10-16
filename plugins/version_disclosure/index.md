# [version_disclosure] Version disclosure

## What this check looks for

This plugin checks how `server_tokens` is configured, and warns when it is explicitly unsafe or when it is missing in a context where it will inherit an unsafe default.

It flags:

- `server_tokens on;`
- `server_tokens build;`
- missing `server_tokens off;` in configurations where version disclosure would otherwise occur

## Why this is a problem

By default, NGINX includes its version in the `Server` header and on some error pages. That makes passive fingerprinting easy, and attackers can quickly narrow down known issues for that version.

Hiding the version does not fix vulnerabilities, but it removes a free signal.

## Bad configuration

```
http {
    server_tokens on;
}
```

Or, more subtly:

```
http {
    # server_tokens not set here (defaults apply)

    server {
        listen 80;
        server_name example.com;
    }
}
```

If the default in your build exposes the version, every server block inherits that behavior.

## Better configuration

Set it once at the top level:

```
http {
    server_tokens off;

    server {
        listen 80;
        server_name example.com;
    }
}
```

## Additional notes

The check for a missing `server_tokens` is only performed when a full configuration scan occurs, i.e. when the configuration scanned includes an `http { .. }` block.
