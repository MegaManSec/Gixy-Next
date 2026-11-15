---
title: "OCSP Stapling Without Resolver"
description: "Detects SSL servers with ssl_stapling on but no resolver in scope, so nginx resolves the OCSP responder only at startup."
---

# [ssl_stapling_without_resolver] OCSP responder never re-resolved without a resolver

## What this check looks for

This plugin flags `server` blocks where all of the following are true:

- The server handles SSL/TLS connections: a `listen` of its own has `ssl`, `quic` or `http3`, or shares its address and port with another server's `listen ... ssl`
- `ssl_stapling on;` is in effect — declared directly in the server or inherited from the enclosing `http {}` block
- No `resolver` directive is reachable in the server's scope or any enclosing scope
- No `ssl_stapling_file` is set (a pre-loaded OCSP response removes the need for a resolver)

## Why this is a problem

`ssl_stapling` makes nginx fetch an OCSP response from the certificate authority and staple it to the TLS handshake. Without a `resolver` in scope, nginx resolves the responder's hostname only once, at startup. If those addresses change, it keeps stapling the last response until it expires and then staples nothing until a reload, so clients make their own OCSP requests again.

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
    # no resolver — the responder is never re-resolved
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

Put the resolver at `http` level so every SSL server inherits it, pointing at a local or provider-internal caching resolver:

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
- A server whose `ssl_stapling_responder` is an IP-literal URL (for example `http://192.0.2.1/ocsp`) or `localhost` is not flagged, since its addresses cannot change.
