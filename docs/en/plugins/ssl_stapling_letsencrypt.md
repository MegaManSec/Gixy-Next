---
title: "OCSP Stapling With Let's Encrypt"
description: "Let's Encrypt retired its OCSP responders on 2025-08-06, so ssl_stapling on with a certbot certificate staples nothing and is dead configuration."
---

# [ssl_stapling_letsencrypt] OCSP stapling does nothing for a Let's Encrypt certificate

## What this check looks for

This plugin flags `server` blocks where all of the following are true:

- The server handles TLS: one of its `listen` directives has `ssl`, `quic` or `http3`, or another server has `listen ... ssl` on the same address and port
- `ssl_stapling on;` is in effect, in the server or inherited from an enclosing block
- The `ssl_certificate` in effect for the server (its own, or the enclosing block's) points under `/etc/letsencrypt/`, certbot's default layout. An `ssl_trusted_certificate` under that path counts too, unless the `ssl_certificate` in effect is a fixed path elsewhere, since the OCSP URL comes from the certificate

## Why this is a problem

Let's Encrypt stopped including OCSP URLs in new certificates on **2025-05-07** and shut its responders down on **2025-08-06**; it relies on short certificate lifetimes and CRLs instead. The `ssl_stapling on;` and `ssl_trusted_certificate` lines that TLS guides written before then recommend now do nothing for its certificates: with no OCSP URL in the certificate, NGINX has nothing to fetch, logs a warning at startup and staples nothing:

```console
$ nginx -t
nginx: [warn] "ssl_stapling" ignored, no OCSP responder URL in the certificate
              "/etc/letsencrypt/live/example.com/fullchain.pem"
nginx: configuration file /etc/nginx/nginx.conf test is successful
```

This is dead configuration rather than a vulnerability, so the finding is LOW.

## Bad configuration

```nginx
server {
    listen 443 ssl;
    server_name example.com;

    ssl_certificate     /etc/letsencrypt/live/example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/example.com/privkey.pem;

    ssl_stapling on;
    ssl_stapling_verify on;
    ssl_trusted_certificate /etc/letsencrypt/live/example.com/chain.pem;
    resolver 127.0.0.1 valid=300s;
}
```

## Better configuration

Drop the stapling directives, and the `ssl_trusted_certificate` if nothing else needs it:

```nginx
server {
    listen 443 ssl;
    server_name example.com;

    ssl_certificate     /etc/letsencrypt/live/example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/example.com/privkey.pem;
}
```

If the same `http {}` block enables stapling globally for other certificates, turn it off for this server instead:

```nginx
server {
    listen 443 ssl;
    server_name example.com;

    ssl_certificate     /etc/letsencrypt/live/example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/example.com/privkey.pem;

    ssl_stapling off;
}
```

## Additional notes

- Detection is by path, so the reason says "appears to be": certbot can write to `/etc/letsencrypt/` for another ACME server with `--server`.
- The check is deliberately narrow: other ACME CAs, such as ZeroSSL, Google Trust Services and Buypass, still run OCSP responders, so a broader ACME-path heuristic would produce false positives.
- Let's Encrypt certificates kept somewhere else (`acme.sh` in `~/.acme.sh`, `lego`, certbot with a custom `--config-dir`) are not detected.
- A Let's Encrypt server with stapling on and no `resolver` is also reported by [ssl_stapling_without_resolver](ssl_stapling_without_resolver.md), which cannot see that the certificate has no OCSP URL. Removing the stapling directives resolves both.
