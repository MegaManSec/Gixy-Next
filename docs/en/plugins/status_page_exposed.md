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

- This plugin treats an `allow` covering every address the enclosing `server` can accept as not a whitelist, and does not count it as a restriction. `allow all` always qualifies. `0.0.0.0/0` and `::/0` are per-family: `ngx_http_access_rule` files the first under the IPv4 rule list and the second under the IPv6 one, and `ngx_http_access_handler` consults only the list matching the client's address family. So `allow ::/0` covers every client of an IPv6-capable server but nobody on an IPv4-only one, and `allow 0.0.0.0/0` the other way around. The same applies to `deny`.
- `allow`/`deny` are read in order, as NGINX evaluates them: the first matching rule decides the request, so anything written after an `allow all` is dead. `allow 10.0.0.0/8; allow all; deny all;` is reported, because everyone the `/8` did not cover is let in by the `allow all` and the `deny all` never applies.
- `allow`/`deny` are resolved with NGINX inheritance: rules set on an enclosing `server`/`http` scope protect a `stub_status` location that declares none of its own. (A location that sets its *own* `allow`/`deny` does not inherit the parent's, matching `ngx_http_access_module`, so in that case it must repeat them.)
- An endpoint protected by an auth module (`auth_basic`, `auth_request`, `auth_jwt`, or `auth_oidc`) is not reported, with one exception: under `satisfy any`, an `allow` covering every address makes the access module succeed on its own and NGINX then skips the rest of the access phase, so the authentication never runs. `satisfy any; allow all;` alongside `auth_basic` is therefore reported as exposed. The intended `trusted network OR password` shape — `satisfy any; allow 10.0.0.0/8; deny all;` with `auth_basic` — is not.
- The address families are read off the `server`'s `listen` directives:

    | `listen` spelling              | Server accepts                                     |
    | ------------------------------ | -------------------------------------------------- |
    | none (implicit `*:80`)         | IPv4                                               |
    | `listen 80;`, `listen *:80;`   | IPv4                                               |
    | `listen 127.0.0.1:80;`         | IPv4                                               |
    | `listen [::]:80;`              | IPv6 only, because `ipv6only` defaults to `on`     |
    | `listen [::]:80 ipv6only=off;` | IPv4 and IPv6, as IPv4-mapped addresses            |
    | `listen example.com:80;`       | assumed both; resolution at startup decides        |

- Servers that listen only on `unix:` sockets are ignored by this check, since they are not reachable over the network.
- Prefer keeping the endpoint unadvertised (non-obvious path) in addition to access control, but do not rely on obscurity alone.
