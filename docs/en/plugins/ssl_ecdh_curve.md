---
title: "Post-Quantum ssl_ecdh_curve Stops NGINX From Starting"
description: "Detects post-quantum groups such as X25519MLKEM768 in ssl_ecdh_curve, which make OpenSSL reject the whole group list so NGINX refuses to load the configuration on OpenSSL 3.0 and 3.2."
---

# [ssl_ecdh_curve] Post-quantum groups stop NGINX from starting on older OpenSSL

## What this check looks for

This plugin flags `ssl_ecdh_curve` values that name a post-quantum group without the `?` prefix — anything containing `MLKEM` or `KYBER`, such as `X25519MLKEM768`, `SecP256r1MLKEM768`, or the pre-standard `X25519Kyber768Draft00`.

## Why this is a problem

NGINX hands the value of `ssl_ecdh_curve` straight to OpenSSL:

```c
/* src/event/ngx_event_openssl.c */
if (SSL_CTX_set1_curves_list(ssl->ctx, (char *) name->data) == 0) {
    ngx_ssl_error(NGX_LOG_EMERG, ssl->log, 0,
                  "SSL_CTX_set1_curves_list(\"%s\") failed", name->data);
    return NGX_ERROR;
}
```

Two properties combine badly:

1. **OpenSSL rejects the entire list** when a single group name is unknown. There is no partial acceptance — `X25519MLKEM768:X25519:prime256v1` fails as a whole, even though the other two groups are universally supported.
2. **NGINX treats that as `NGX_LOG_EMERG`** and returns an error, so the configuration never loads. A cold start fails outright; a reload logs the error and silently keeps serving the *old* configuration, so a change you believe you deployed was never applied.

This is a startup failure, not a graceful downgrade to a classical curve.

Post-quantum hybrid groups arrived in **OpenSSL 3.5**. The distributions most production NGINX runs on ship older:

| Distribution | OpenSSL | `X25519MLKEM768` |
|---|---|---|
| Debian 12 (bookworm) | 3.0 | NGINX will not start |
| Ubuntu 24.04 LTS | 3.0 | NGINX will not start |
| RHEL / AlmaLinux / Rocky 9 | 3.2 | NGINX will not start |

Check what you actually have with `openssl version`; `openssl list -tls-groups` shows the exact set the linked library accepts.

## Bad configuration

```nginx
server {
    listen 443 ssl;
    server_name example.com;

    ssl_certificate     /etc/ssl/certs/example.com.pem;
    ssl_certificate_key /etc/ssl/private/example.com.key;

    ssl_ecdh_curve X25519MLKEM768:X25519:prime256v1;
}
```

On OpenSSL 3.0:

```console
$ nginx -t
nginx: [emerg] SSL_CTX_set1_curves_list("X25519MLKEM768:X25519:prime256v1") failed
       (SSL: error:0A080106:SSL routines::passed invalid argument:group
       'X25519MLKEM768' cannot be set)
nginx: configuration file /etc/nginx/nginx.conf test failed
```

## Better configuration

If every target runs **OpenSSL 3.3 or newer**, prefix the post-quantum groups with `?`. OpenSSL then skips names it does not recognise instead of failing the list:

```nginx
server {
    listen 443 ssl;
    server_name example.com;

    ssl_certificate     /etc/ssl/certs/example.com.pem;
    ssl_certificate_key /etc/ssl/private/example.com.key;

    ssl_ecdh_curve ?X25519MLKEM768:X25519:prime256v1;
}
```

A host with OpenSSL 3.5+ negotiates `X25519MLKEM768`; one with 3.3 or 3.4 falls back to `X25519` and keeps serving.

## The `?` prefix has its own version gate

`?` was added in **OpenSSL 3.3**. On OpenSSL 3.0 and 3.2, `?X25519MLKEM768` is itself an unparseable group name and fails in exactly the same way:

```console
$ nginx -t
nginx: [emerg] SSL_CTX_set1_curves_list("?X25519MLKEM768:X25519") failed
       (SSL: error:0A080106:SSL routines::passed invalid argument:group
       '?X25519MLKEM768' cannot be set)
```

So `?` is not a universal escape hatch:

- **OpenSSL 3.5+** — name post-quantum groups directly, or with `?`.
- **OpenSSL 3.3 / 3.4** — use `?` so the configuration is forward-compatible.
- **OpenSSL 3.0 / 3.2** (Debian 12, Ubuntu 24.04, RHEL 9) — do not name post-quantum groups at all. Leave `ssl_ecdh_curve auto;`, which is the default, or list only classical curves.

If one configuration is deployed to a mixed fleet, gate the directive at build or template time rather than assuming `?` saves you.

## Additional notes

- `ssl_ecdh_curve auto;` is special-cased by NGINX and returned early before OpenSSL sees a list, so it is never flagged.
- Classical curve lists (`X25519:prime256v1:secp384r1`) are not flagged.
- Groups that already carry the `?` prefix are not flagged, on the assumption that a config author who wrote `?` knows the OpenSSL 3.3 requirement.
- `X25519Kyber768Draft00` and the other pre-standard Kyber draft names were never accepted by upstream OpenSSL at all — not even 3.5+ — so they are flagged regardless of how new the library is.
