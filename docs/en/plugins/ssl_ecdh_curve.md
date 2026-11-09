---
title: "Post-Quantum ssl_ecdh_curve Groups"
description: "Detects ssl_ecdh_curve group lists that stop NGINX from loading its configuration on OpenSSL 3.0 and 3.2, and pinned lists that turn off X25519MLKEM768 key exchange on OpenSSL 3.5+."
---

# [ssl_ecdh_curve] Group lists that break startup or post-quantum key exchange

## What this check looks for

This plugin reads the group list in `ssl_ecdh_curve` and flags:

- a post-quantum group without the `?` prefix (anything containing `MLKEM` or `KYBER`, such as `X25519MLKEM768`, `SecP256r1MLKEM768`, or the pre-standard `X25519Kyber768Draft00`), which stops NGINX from loading the configuration on OpenSSL older than 3.5,
- a list that names no post-quantum group, or ranks every one below a classical group, which turns post-quantum key exchange off on OpenSSL 3.5+,
- a list that puts post-quantum and classical groups in the same preference tier, so that on OpenSSL 3.5+ a client that leads with an X25519 key share negotiates classical X25519.

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

Post-quantum hybrid groups arrived in **OpenSSL 3.5**. Current distribution releases ship it, but the long-term releases many servers still run do not:

| Distribution                            | OpenSSL | `X25519MLKEM768`     |
| --------------------------------------- | ------- | -------------------- |
| Debian 12 (bookworm)                    | 3.0     | NGINX will not start |
| Ubuntu 24.04 LTS                        | 3.0     | NGINX will not start |
| RHEL / AlmaLinux / Rocky 9.0-9.4        | 3.0     | NGINX will not start |
| RHEL / AlmaLinux / Rocky 9.5, 9.6, 10.0 | 3.2     | NGINX will not start |
| RHEL / AlmaLinux / Rocky 9.7+, 10.1+    | 3.5     | Supported            |
| Debian 13 (trixie)                      | 3.5     | Supported            |
| Ubuntu 26.04 LTS                        | 3.5     | Supported            |
| Amazon Linux 2023                       | 3.5     | Supported            |

Check what NGINX is actually linked against with `nginx -V` (the `built with OpenSSL` line); `openssl list -tls-groups` shows the exact set that library accepts.

The `?` prefix, which makes OpenSSL skip a group it does not recognise, was added in **OpenSSL 3.3**. On OpenSSL 3.0 and 3.2, `?X25519MLKEM768` is itself an unparseable group name and fails in exactly the same way:

```console
$ nginx -t
nginx: [emerg] SSL_CTX_set1_curves_list("?X25519MLKEM768:X25519") failed
       (SSL: error:0A080106:SSL routines::passed invalid argument:group
       '?X25519MLKEM768' cannot be set)
```

The opposite mistake is quieter. An explicit `ssl_ecdh_curve` list replaces OpenSSL's default instead of extending it, and on OpenSSL 3.5+ that default puts `X25519MLKEM768` in its own top preference tier. A pinned classical list, the hardening advice from before ML-KEM existed, makes NGINX negotiate X25519 even with a client that offers the hybrid first. `nginx -t` passes, nothing is logged, and recorded traffic stays exposed to a future quantum computer.

OpenSSL 3.5 also reads the list as preference tiers: `:` joins groups in one tier and `/` starts the next. OpenSSL picks the first tier the client supports and, inside it, uses a key share the client already sent. It sends a HelloRetryRequest only when the client sent no key share for any group in that tier. A post-quantum group that shares a tier with `X25519` therefore loses to any client that sends only an X25519 key share, even with `ssl_prefer_server_ciphers on`.

## Bad configuration

### post-quantum group without `?`

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

### classical groups only

```nginx
server {
    listen 443 ssl;
    server_name example.com;

    ssl_certificate     /etc/ssl/certs/example.com.pem;
    ssl_certificate_key /etc/ssl/private/example.com.key;

    ssl_ecdh_curve X25519:prime256v1:secp384r1;
}
```

On OpenSSL 3.5+, a client that offers the hybrid first still gets X25519:

```console
$ openssl s_client -connect example.com:443 -groups X25519MLKEM768:X25519 </dev/null 2>/dev/null \
    | grep -E 'Negotiated TLS1.3 group|Temp Key'
Peer Temp Key: X25519, 253 bits
```

A list that puts the post-quantum groups in a lower tier, such as `X25519/?X25519MLKEM768`, behaves the same way for every client that also supports `X25519`.

### post-quantum and classical groups in one tier

```nginx
server {
    listen 443 ssl;
    server_name example.com;

    ssl_certificate     /etc/ssl/certs/example.com.pem;
    ssl_certificate_key /etc/ssl/private/example.com.key;

    ssl_ecdh_curve ?X25519MLKEM768:X25519:prime256v1;
}
```

On OpenSSL 3.5+, a client that supports the hybrid but sends only an X25519 key share negotiates X25519.

## Better configuration

### no ssl_ecdh_curve

```nginx
server {
    listen 443 ssl;
    server_name example.com;

    ssl_certificate     /etc/ssl/certs/example.com.pem;
    ssl_certificate_key /etc/ssl/private/example.com.key;
}
```

Removing the directive fixes all three findings on every OpenSSL version. On OpenSSL 3.5+ the default puts `X25519MLKEM768` in its own top tier, so every client that supports the hybrid negotiates it, and the `s_client` command above prints `Negotiated TLS1.3 group: X25519MLKEM768`. On older OpenSSL the default is a classical list that always loads. If one configuration is deployed to a mixed fleet, this is the only setting that is right on all of it.

### a pinned list on OpenSSL 3.5+

If you must pin the list, for example to drop a group, give the post-quantum groups their own first tier:

```nginx
server {
    listen 443 ssl;
    server_name example.com;

    ssl_certificate     /etc/ssl/certs/example.com.pem;
    ssl_certificate_key /etc/ssl/private/example.com.key;

    ssl_ecdh_curve ?X25519MLKEM768/X25519:prime256v1;
}
```

The server then asks a client that sent only an X25519 key share for a hybrid one instead. `/` is OpenSSL 3.5 syntax, though. OpenSSL 3.0 and 3.2 reject this list. OpenSSL 3.3 and 3.4 read `?X25519MLKEM768/X25519` as one unknown, `?`-prefixed name and skip it, so only `prime256v1` is left and clients that support nothing but X25519 fail the handshake.

By OpenSSL version:

- **OpenSSL 3.5+**: remove the directive, or pin a tiered list as above.
- **OpenSSL 3.3 / 3.4**: no post-quantum groups exist yet. Remove the directive; `?X25519MLKEM768:X25519:prime256v1` also loads, because OpenSSL skips the `?`-prefixed group.
- **OpenSSL 3.0 / 3.2** (Debian 12, Ubuntu 24.04, RHEL 9.0-9.6 and 10.0): do not name post-quantum groups at all. Remove the directive, or set `ssl_ecdh_curve auto;`, which is the same thing.

## How severity is determined

- **MEDIUM**: a post-quantum group without the `?` prefix, because NGINX fails to load the configuration on OpenSSL older than 3.5. It is not HIGH because the check cannot see which OpenSSL the server links, so it also fires on configurations that are correct on OpenSSL 3.5+.
- **LOW**: a list with no post-quantum group, or with every one below a classical group. On OpenSSL 3.0 through 3.4 the list changes nothing today, since those versions have no post-quantum groups.
- **INFORMATION**: post-quantum and classical groups in the same tier. Current browsers send the hybrid key share first and are unaffected.

## Additional notes

- `ssl_ecdh_curve auto;` is special-cased by NGINX and returned early before OpenSSL sees a list, so it is never flagged. NGINX only matches lowercase `auto`.
- Lists that use the OpenSSL 3.5 `DEFAULT` keyword (for example `DEFAULT:-X448`) are not flagged: only OpenSSL 3.5+ parses `DEFAULT`, and it expands to the default list, which leads with the hybrid.
- Groups that already carry the `?` prefix are not reported as startup failures, on the assumption that a config author who wrote `?` knows the OpenSSL 3.3 requirement. `?` has to be the first character: OpenSSL 3.3 and 3.4 reject `*?X25519MLKEM768`.
- A `-` prefix removes a group, so `-X25519MLKEM768` does not count as offering one.
- `X25519Kyber768Draft00` and the other pre-standard Kyber draft names were never accepted by upstream OpenSSL at all — not even 3.5+ — so they are flagged regardless of how new the library is.
- Group lists set with `ssl_conf_command Groups` are not inspected.
