# [ssl_stapling_letsencrypt] OCSP stapling does nothing for a Let's Encrypt certificate

## What this check looks for

This plugin flags `server` blocks where all of the following are true:

- The server handles SSL/TLS connections (`listen ... ssl;`, `listen ... quic;`, or `listen ... http3;`)
- `ssl_stapling on;` is in effect — declared directly in the server or inherited from an enclosing block
- An `ssl_certificate` or `ssl_trusted_certificate` in scope points under `/etc/letsencrypt/`, certbot's default layout

## Why this is a problem

Nearly every NGINX TLS guide written before 2025 ends with the same three lines:

```
ssl_stapling on;
ssl_stapling_verify on;
ssl_trusted_certificate /etc/letsencrypt/live/example.com/chain.pem;
```

For a Let's Encrypt certificate those lines now do nothing at all. Let's Encrypt announced the end of OCSP in July 2024, stopped including OCSP URLs in newly issued certificates in early 2025, and shut its responders down on **2025-08-06**.

OCSP stapling works by NGINX fetching a signed status response from the URL in the certificate's Authority Information Access extension. With no such URL there is nothing to fetch, so NGINX logs a warning at startup and serves handshakes with no stapled response:

```
$ nginx -t
nginx: [warn] "ssl_stapling" ignored, no OCSP responder URL in the certificate
              "/etc/letsencrypt/live/example.com/fullchain.pem"
nginx: configuration file /etc/nginx/nginx.conf test is successful
```

```
$ openssl s_client -connect example.com:443 -status
OCSP responses: no responses sent
```

This is dead configuration rather than a vulnerability, which is why the finding is LOW. The cost is a startup warning, misplaced confidence that revocation checking is being accelerated, and an `ssl_trusted_certificate` that may exist for no other reason.

Revocation for Let's Encrypt is handled through short certificate lifetimes and CRLs instead.

## Bad configuration

```
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

```
server {
    listen 443 ssl;
    server_name example.com;

    ssl_certificate     /etc/letsencrypt/live/example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/example.com/privkey.pem;
}
```

If the same `http {}` block enables stapling globally for other certificates, turn it off for this server instead:

```
server {
    listen 443 ssl;
    server_name example.com;

    ssl_certificate     /etc/letsencrypt/live/example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/example.com/privkey.pem;

    ssl_stapling off;
}
```

## Additional notes

- Detection is by path: `/etc/letsencrypt/` is certbot's default directory and certbot defaults to Let's Encrypt. The wording says "appears to be" because certbot can be pointed at another ACME server with `--server` while still writing to that path.
- The check is deliberately narrow. Other ACME CAs — ZeroSSL, Google Trust Services, Buypass — still run OCSP responders, so stapling remains useful for them and a broader ACME-path heuristic would produce false positives.
- Let's Encrypt certificates kept somewhere else (`acme.sh` in `~/.acme.sh`, `lego`, certbot with a custom `--config-dir`) are not detected.
- A server that overrides with `ssl_stapling off;` is not flagged, even when an enclosing block enables stapling globally.
- Non-SSL servers (plain `listen 80;`) are skipped — stapling is irrelevant there.
- A Let's Encrypt server with stapling on and no `resolver` in scope will also be reported by [ssl_stapling_without_resolver](https://gixy.io/plugins/ssl_stapling_without_resolver/index.md). Both findings are accurate; removing the stapling directives resolves both.
