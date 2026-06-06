---
title: "Status Page Exposed"
description: "Detects stub_status locations that are reachable over TCP without IP allow/deny restrictions. Exposed metrics endpoints can aid reconnaissance and traffic mapping."
---

# [status_page_exposed] `stub_status` exposed without IP restrictions

## What this check looks for

This plugin flags `stub_status` endpoints that do not implement an IP whitelist using `allow` plus a final `deny all`.

It only reports findings when the enclosing `server` is reachable over TCP (i.e., it is not a server that listens exclusively on `unix:` sockets).

## Why this is a problem

`stub_status` reveals operational details such as active connections and request handling state. While it does not expose application data directly, it is valuable for reconnaissance:

- confirms the server is NGINX and that a status endpoint exists,
- provides traffic and connection signals that help time attacks,
- can reveal load patterns and availability.

If the endpoint is publicly reachable, anyone can query it.

## Bad configuration

`stub_status` enabled with no IP restrictions:

```nginx
server {
    listen 80;
    server_name example.com;

    location /nginx_status {
        stub_status;
    }
}
```

Partial restrictions are also flagged. For example, a whitelist without `deny all`:

```nginx
location /nginx_status {
    stub_status;

    allow 10.0.0.0/8;
    # missing: deny all;
}
```

Or `deny all` without an explicit whitelist:

```nginx
location /nginx_status {
    stub_status;

    # missing: allow <trusted ranges>;
    deny all;
}
```

## Better configuration

Restrict access to trusted IP ranges and end with a catch-all deny:

```nginx
server {
    listen 80;
    server_name example.com;

    location /nginx_status {
        stub_status;

        allow 10.0.0.0/8;
        allow 192.168.0.0/16;
        allow 203.0.113.10;  # monitoring host
        deny all;
    }
}
```

## Additional notes

- This plugin treats `allow all` as not a whitelist and does not count it as a restriction.
- `allow`/`deny` are resolved with NGINX inheritance: rules set on an enclosing `server`/`http` scope protect a `stub_status` location that declares none of its own. (A location that sets its *own* `allow`/`deny` does not inherit the parent's, matching `ngx_http_access_module`, so in that case it must repeat them.)
- Servers that listen only on `unix:` sockets are ignored by this check, since they are not reachable over the network.
- Prefer keeping the endpoint unadvertised (non-obvious path) in addition to access control, but do not rely on obscurity alone.
