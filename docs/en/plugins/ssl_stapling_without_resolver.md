---
title: "OCSP Stapling Without Resolver"
description: "Detects SSL servers where ssl_stapling on is effective but no resolver directive is reachable in scope, causing OCSP stapling to silently fail at runtime."
---

# [ssl_stapling_without_resolver] OCSP stapling silently fails without a resolver

## What this check looks for

This plugin flags `server` blocks where all of the following are true:

* The server handles SSL/TLS connections (`listen ... ssl;`, `listen ... quic;`, or `listen ... http3;`)
* `ssl_stapling on;` is in effect — declared directly in the server or inherited from the enclosing `http {}` block
* No `resolver` directive is reachable in the server's scope or any enclosing scope
* No `ssl_stapling_file` is set (a pre-loaded OCSP response removes the need for a resolver)

## Why this is a problem

`ssl_stapling` directs nginx to fetch a signed OCSP response from the certificate authority and staple it to the TLS handshake. To reach the CA's OCSP responder, nginx must resolve the responder hostname — and it can only do that if a `resolver` is configured in the same or a parent scope.

Without one, nginx logs a warning at startup and silently disables stapling. Clients then have to make their own OCSP requests during every handshake, adding a round trip of latency and defeating the point of enabling stapling in the first place.

## Bad configuration

`ssl_stapling on` in the server block, but no resolver anywhere:

```nginx
server {
    listen 443 ssl;
    server_name example.com;

    ssl_certificate     /etc/ssl/certs/example.com.pem;
    ssl_certificate_key /etc/ssl/private/example.com.key;

    ssl_stapling on;
    ssl_stapling_verify on;
    # no resolver — stapling silently fails
}
```

Inherited from `http {}` with still no resolver:

```nginx
http {
    ssl_stapling on;     # applies to every server below

    server {
        listen 443 ssl;
        ssl_certificate     /etc/ssl/certs/example.com.pem;
        ssl_certificate_key /etc/ssl/private/example.com.key;
        # no resolver anywhere up the chain
    }
}
```

## Better configuration

Put the resolver at `http` level so every SSL server inherits it:

```nginx
http {
    resolver 1.1.1.1 8.8.8.8 valid=300s ipv6=off;
    resolver_timeout 5s;

    ssl_stapling on;
    ssl_stapling_verify on;

    server {
        listen 443 ssl;
        server_name example.com;

        ssl_certificate     /etc/ssl/certs/example.com.pem;
        ssl_certificate_key /etc/ssl/private/example.com.key;
    }
}
```

## Additional notes

* A `resolver` declared in the same server block is also sufficient; http-level is just the most common pattern.
* If you pre-load the stapled response via `ssl_stapling_file`, nginx uses that file directly and does not need a resolver.
* A server that overrides with `ssl_stapling off;` is not flagged, even when the http block enables stapling globally.
* Non-SSL servers (plain `listen 80;`) are skipped — stapling is irrelevant there.
