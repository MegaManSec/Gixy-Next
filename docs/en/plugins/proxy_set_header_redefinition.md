---
title: "Proxy Header Inheritance Issues"
description: "Detects proxy_set_header usage that unintentionally drops request headers due to inheritance rules. Declaring a single proxy_set_header in a nested block replaces every proxy_set_header inherited from the levels above it."
---

# [proxy_set_header_redefinition] Redefining proxied request headers with `proxy_set_header`

## What this check looks for

This plugin looks for nested contexts where `proxy_set_header` is used at a lower level and headers declared at higher levels are no longer sent to the upstream.

## Why this is a problem

`proxy_set_header` follows an all-or-nothing inheritance rule: the header list is inherited from the previous level only if there are no `proxy_set_header` directives at the current level. As soon as you set any header in a nested block, every header defined above it is dropped.

This is the same trap as [`add_header`](https://gixy.io/plugins/add_header_redefinition/), but the consequences land on the upstream instead of the client. The headers that usually end up missing are the ones a backend relies on for correctness and security: `Host`, `X-Forwarded-For`, `X-Forwarded-Proto`, or an `Authorization` header for an internal API.

It also silently re-opens header spoofing. A common hardening pattern is to blank out a header so that a client cannot forge it:

```nginx
server {
    proxy_set_header X-Internal-Auth "";
}
```

If a nested block declares any `proxy_set_header` of its own, that blanking is dropped too, and a client-supplied `X-Internal-Auth` reaches the backend again.

## Bad configuration

```nginx
server {
    proxy_set_header Host $host;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;

    location /internal {
        # Looks harmless, but it drops the two headers above for /internal
        proxy_set_header X-Forwarded-Port $server_port;
        proxy_pass http://backend;
    }
}
```

Requests to `/internal` reach the backend with only `X-Forwarded-Port`, and the backend sees no client address at all.

## Better configuration

Option 1: keep all headers at one level (often `server` or `http`), and avoid declaring them in child blocks.

```nginx
server {
    proxy_set_header Host $host;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Port $server_port;

    location /internal {
        proxy_pass http://backend;
    }
}
```

Option 2: if you really need headers that vary by location, repeat the inherited ones in the nested block:

```nginx
server {
    proxy_set_header Host $host;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;

    location /internal {
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Port $server_port;
        proxy_pass http://backend;
    }
}
```

A common variant of option 2 is to move the shared headers into their own file and `include` it at every level that declares headers:

```nginx
server {
    include proxy_params.conf;

    location /internal {
        include proxy_params.conf;
        proxy_set_header X-Forwarded-Port $server_port;
        proxy_pass http://backend;
    }
}
```

## Additional notes

### Which levels are checked

`proxy_set_header` is only valid in the `http`, `server` and `location` contexts, so the plugin reports on `server` and `location` blocks that replace headers declared above them. A `server` block that declares a header drops the `http`-level list in exactly the same way a `location` does.

### The built-in defaults still apply

NGINX always merges its own default header list on top of whatever is in effect, so `Host` and `Connection` are never left unset. Dropping `proxy_set_header Host $host;` does not remove the `Host` header, it reverts it to the default `$proxy_host`, which is the upstream address rather than the name the client asked for.

### What counts as a finding

The plugin only reports a block when something was actually inherited and is actually lost. A nested block that re-declares every inherited header is correct and is not reported, even when the values differ. A nested block whose parents declare no `proxy_set_header` at all has nothing to drop and is not reported either.
