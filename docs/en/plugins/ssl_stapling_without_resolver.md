---
title: "OCSP Stapling Without Resolver"
description: "Detects SSL servers with ssl_stapling on but no resolver in scope, so NGINX resolves the OCSP responder only at startup."
---

# [ssl_stapling_without_resolver] OCSP responder never re-resolved without a resolver

## What this check looks for

This plugin flags `server` blocks where all of the following are true:

- The server handles TLS: one of its `listen` directives has `ssl`, `quic` or `http3`, or another server has `listen ... ssl` on the same address and port
- `ssl_stapling on;` is in effect, in the server or inherited from the enclosing `http {}` block
- No `resolver` is set in the server or an enclosing block
- No `ssl_stapling_file` is set, since a pre-loaded OCSP response needs no resolver
- `ssl_stapling_responder`, if set, names a host other than an IP address or `localhost`, whose addresses cannot change

## Why this is a problem

`ssl_stapling` makes NGINX fetch an OCSP response from the certificate authority and staple it to the TLS handshake. Without a `resolver` in scope, NGINX resolves the responder's hostname once, with the system resolver at startup, and never again. If the responder moves and its old addresses stop answering, NGINX keeps stapling the last response until it expires and then staples nothing until the next reload. A responder that cannot be resolved at startup is logged as `"ssl_stapling" ignored, host not found` and is never stapled at all.

## Bad configuration

No `resolver` in the server or above it:

```nginx
server {
    listen 443 ssl;
    server_name example.com;

    ssl_certificate     /etc/ssl/certs/example.com.pem;
    ssl_certificate_key /etc/ssl/private/example.com.key;

    ssl_stapling on;
    ssl_stapling_verify on;
}
```

The same, with `ssl_stapling` inherited from `http {}`:

```nginx
http {
    ssl_stapling on;

    server {
        listen 443 ssl;
        ssl_certificate     /etc/ssl/certs/example.com.pem;
        ssl_certificate_key /etc/ssl/private/example.com.key;
    }
}
```

## Better configuration

Set `resolver` at `http` level, pointing at a local or internal caching resolver, so every server inherits it:

```nginx
http {
    resolver 127.0.0.1 valid=300s ipv6=off;
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

- Point `resolver` at a local caching resolver (`127.0.0.1`, `[::1]`) or one inside your network, not at a public DNS service, which [resolver_external](resolver_external.md) reports at MEDIUM severity.
- A Let's Encrypt certificate has no OCSP URL, so there is nothing to resolve; [ssl_stapling_letsencrypt](ssl_stapling_letsencrypt.md) reports that case, and removing the stapling directives resolves both findings.
