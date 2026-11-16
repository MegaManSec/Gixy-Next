---
title: "Status Page Exposed"
description: "Detects stub_status locations that are reachable over the network without IP allow/deny restrictions. Exposed metrics endpoints can aid reconnaissance and traffic mapping."
---

# [status_page_exposed] `stub_status` exposed without IP restrictions

## What this check looks for

This plugin flags `stub_status` endpoints that clients outside the trusted `allow` ranges can reach: no `deny all` closes the rule list, or an `allow` covering every address comes first.

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

A whitelist without `deny all` is also flagged:

```nginx
location /nginx_status {
    stub_status;

    allow 10.0.0.0/8;
    # missing: deny all;
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

- An `allow` that covers every address the `server` accepts is not a whitelist. `allow all` always qualifies, while `0.0.0.0/0` covers only IPv4 clients and `::/0` only IPv6 clients. The same applies to `deny`.
- Rules are evaluated in order and the first match decides, so `allow 10.0.0.0/8; allow all; deny all;` is reported: the `deny all` never applies.
- `deny all` with no `allow` is not reported: every client is denied, so nobody reaches the endpoint.
- Rules on an enclosing `server` or `http` protect a location that declares none of its own. A location with its own `allow`/`deny` does not inherit them.
- An endpoint protected by `auth_basic`, `auth_request`, `auth_jwt` or `auth_oidc` is not reported, unless `satisfy any` is paired with an `allow` that covers every address: that lets everyone in without authenticating. `satisfy any; allow 10.0.0.0/8; deny all;` with authentication is fine. `auth_basic` only counts when an `auth_basic_user_file` is in effect; in a file without an `http` block, the user file is assumed to be set in the main configuration.
- The address families are read off the `server`'s `listen` directives:

    | `listen` spelling              | Server accepts                                     |
    | ------------------------------ | -------------------------------------------------- |
    | none (implicit `*:80`)         | IPv4                                               |
    | `listen 80;`, `listen *:80;`   | IPv4                                               |
    | `listen 10.0.0.1:80;`          | IPv4                                               |
    | `listen [::]:80;`              | IPv6 only, because `ipv6only` defaults to `on`     |
    | `listen [::]:80 ipv6only=off;` | IPv4 and IPv6, as IPv4-mapped addresses            |
    | `listen example.com:80;`       | assumed both; resolution at startup decides        |

- Servers that listen only on `unix:` sockets, loopback addresses or `localhost` cannot be reached from the network and are ignored, as is a location marked `internal`.
- Prefer keeping the endpoint unadvertised (non-obvious path) in addition to access control, but do not rely on obscurity alone.
