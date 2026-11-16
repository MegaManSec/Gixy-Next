---
title: "Post-Quantum ssl_ecdh_curve Groups"
description: "Detects ssl_ecdh_curve group lists that stop NGINX from loading its configuration before OpenSSL 3.5, and pinned lists that turn off X25519MLKEM768 key exchange on OpenSSL 3.5+."
---

# [ssl_ecdh_curve] Group lists that break startup or post-quantum key exchange

## What this check looks for

This plugin reads the group list in `ssl_ecdh_curve` and in `ssl_conf_command Groups` (or `Curves`) and flags:

- a post-quantum group without the `?` prefix (any name containing `MLKEM` or `KYBER`, such as `X25519MLKEM768`, `SecP256r1MLKEM768` or the pre-standard `X25519Kyber768Draft00`), which stops NGINX from loading the configuration on OpenSSL older than 3.5, or on any OpenSSL for the Kyber drafts,
- a list of only post-quantum groups, which does not load before OpenSSL 3.5 and on OpenSSL 3.5+ locks out clients that do not support a hybrid,
- a value OpenSSL always rejects, such as `AUTO` (NGINX only recognises lowercase `auto`) or `DEFAULT` with a prefix,
- a list that offers no ML-KEM group, ranks every one below a classical group, or removes `X25519MLKEM768` from `DEFAULT`, which turns post-quantum key exchange off on OpenSSL 3.5+,
- a list that puts post-quantum and classical groups in the same preference tier, so that on OpenSSL 3.5+ a client that sends its X25519 key share first negotiates classical X25519.

The last two cases are only reported for the list in effect for the default server of a TLS `listen` socket, which NGINX uses for every server on that socket. An `ssl_ecdh_curve` that an `ssl_conf_command Groups` replaces, and the groups that `proxy_ssl_conf_command`, `grpc_ssl_conf_command` and `uwsgi_ssl_conf_command` offer to TLS upstreams, are only checked for startup failures.

## Why this is a problem

NGINX passes the list to OpenSSL as a whole, and OpenSSL rejects the whole list when a single group name is unknown to it. NGINX then refuses to load the configuration: a cold start fails, and a reload logs the error and keeps serving the old configuration. Post-quantum groups exist from OpenSSL 3.5, and the `?` prefix that makes OpenSSL skip an unknown group exists from OpenSSL 3.3, so on older OpenSSL `?X25519MLKEM768` fails in the same way. `nginx -V` shows which OpenSSL NGINX is built with, and `openssl list -tls-groups` which groups that library accepts.

The opposite mistake is quieter. An explicit list replaces OpenSSL's default instead of extending it, and on OpenSSL 3.5+ that default starts with a preference tier of post-quantum hybrids led by `X25519MLKEM768`. A pinned classical list, the hardening advice from before ML-KEM existed, makes NGINX negotiate X25519 even with a client that offers the hybrid first. `nginx -t` passes, nothing is logged, and recorded traffic stays exposed to a future quantum computer.

OpenSSL 3.5 reads the list as preference tiers: `:` joins groups in one tier and `/` starts the next. The server picks the first tier the client supports and, inside it, a group the client already sent a key share for; it asks for another key share only when the client sent none for that tier. A post-quantum group that shares a tier with `X25519` therefore loses to a client that sends its X25519 key share first, and `ssl_prefer_server_ciphers on` only helps when the client also sent a hybrid key share.

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

### only post-quantum groups

```nginx
server {
    listen 443 ssl;
    server_name example.com;

    ssl_certificate     /etc/ssl/certs/example.com.pem;
    ssl_certificate_key /etc/ssl/private/example.com.key;

    ssl_ecdh_curve ?X25519MLKEM768;
}
```

OpenSSL before 3.3 rejects the `?` prefix, and OpenSSL 3.3 and 3.4 skip the unknown group and then reject the empty list, so NGINX does not start. On OpenSSL 3.5+ the list loads, but a client that does not support the hybrid fails the handshake.

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

On OpenSSL 3.5+, a client that offers the hybrid first still gets X25519, as an OpenSSL 3.5+ `openssl s_client` shows:

```console
$ openssl s_client -connect example.com:443 -groups X25519MLKEM768:X25519 </dev/null 2>/dev/null \
    | grep -E 'Negotiated TLS1.3 group|Temp Key'
Peer Temp Key: X25519, 253 bits
```

A list that puts the post-quantum groups in a lower tier, such as `X25519/?X25519MLKEM768`, behaves the same way for every client that also supports `X25519`. So does `ssl_conf_command Groups X25519:prime256v1;`.

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

Removing the directive fixes every finding above and loads on every OpenSSL version. On OpenSSL 3.5+ the default starts with a tier of post-quantum hybrids, so every client that supports the hybrid negotiates it and the `s_client` command above prints `Negotiated TLS1.3 group: X25519MLKEM768`; on older OpenSSL the default is a classical list.

Where a system crypto policy sets OpenSSL's default, as on RHEL 9.7 and Amazon Linux 2023, post-quantum key exchange stays off until you enable it there (`update-crypto-policies --set DEFAULT:PQ` on Amazon Linux 2023). A pinned list, as below, overrides the policy.

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

The server then asks a client that sent only an X25519 key share for a hybrid one, and post-quantum key exchange is on even where a system crypto policy leaves it out of the default. `/` is OpenSSL 3.5 syntax, though: OpenSSL before 3.3 rejects this list, and OpenSSL 3.3 and 3.4 read `?X25519MLKEM768/X25519` as one unknown `?`-prefixed name and skip it, so only `prime256v1` is left and clients that support nothing but X25519 fail the handshake.

By OpenSSL version:

- **OpenSSL 3.5+** (Debian 13, Ubuntu 26.04, RHEL 9.7+ and 10.1+, Amazon Linux 2023): remove the directive, or pin a tiered list as above.
- **OpenSSL 3.3 / 3.4**: no post-quantum groups exist yet. Remove the directive; `?X25519MLKEM768:X25519:prime256v1` also loads, because OpenSSL skips the `?`-prefixed group.
- **OpenSSL 1.1.1 / 3.0 / 3.2** (Debian 12, Ubuntu 22.04 and 24.04, RHEL 8, RHEL 9.0-9.6 and 10.0): do not name post-quantum groups at all. Remove the directive, or set `ssl_ecdh_curve auto;`, which is the same thing.

## How severity is determined

- **MEDIUM**: a post-quantum group without the `?` prefix, a list of only post-quantum groups, or a value OpenSSL always rejects. NGINX fails to load the configuration on OpenSSL older than 3.5, or on every OpenSSL for the Kyber drafts and rejected values, and a list of only post-quantum groups also locks out clients without a hybrid on OpenSSL 3.5+. It is not HIGH because the check cannot see which OpenSSL the server links, so the first case also fires on configurations that are correct on OpenSSL 3.5+.
- **LOW**: a list with no ML-KEM group, with every one below a classical group, or that removes `X25519MLKEM768` from `DEFAULT`. On OpenSSL before 3.5 a `:`-separated list like this changes nothing today, since those versions have no post-quantum groups.
- **INFORMATION**: post-quantum and classical groups in the same tier. Current browsers send the hybrid key share first and are unaffected.

## Additional notes

- `ssl_ecdh_curve auto;` is never flagged: NGINX returns before OpenSSL sees a list. Only lowercase `auto` is special; `AUTO` or `Auto` goes to OpenSSL, which rejects it, and so does `ssl_conf_command Groups auto;`.
- Lists that use the OpenSSL 3.5 `DEFAULT` keyword (for example `DEFAULT:-X448`) are only checked for removing `X25519MLKEM768`, since `DEFAULT` expands to the default tiers, which lead with the hybrid; adding `X25519MLKEM768` back later in the list does not return it to the top tier. `DEFAULT` takes no prefix: `?DEFAULT` is a syntax error. OpenSSL 3.5.0 to 3.5.5 and 3.6.0 to 3.6.1 lose the tiers when the list uses `DEFAULT` (fixed in 3.5.6 and 3.6.2), so there a client that sends only an X25519 key share negotiates X25519.
- `/`, `*`, `-` and `DEFAULT` are OpenSSL 3.5 syntax. On older OpenSSL a list that uses them fails to load, unless the 3.5-only part sits inside an entry that starts with `?`: OpenSSL 3.3 and 3.4 then skip that whole entry, including any classical groups in it. The plugin treats such a list as written for OpenSSL 3.5+ and does not report the syntax itself.
- Groups that already carry the `?` prefix are not reported as startup failures, on the assumption that whoever wrote `?` knows the OpenSSL 3.3 requirement. A list made only of `?`-prefixed post-quantum groups is still reported, because it fails on OpenSSL 3.3 and 3.4 too. `?` has to be the first character: OpenSSL 3.3 and 3.4 reject `*?X25519MLKEM768`.
- A `-` prefix removes a group, including one listed earlier, so `-X25519MLKEM768` never counts as offering one.
- Spaces around group names and separators are ignored, as OpenSSL ignores them.
- `X25519Kyber768Draft00` and the other pre-standard Kyber draft names are rejected by every OpenSSL release, 3.5+ included, so they are flagged whatever the library version. With `?` they are skipped, so `?X25519Kyber768Draft00:X25519` counts as a list with no ML-KEM group.
- `ssl_conf_command Groups` (or `Curves`) is applied after `ssl_ecdh_curve` and replaces its list. It applies to a block when that block, or the nearest enclosing level with any `ssl_conf_command`, sets it: a level with its own `ssl_conf_command` directives does not inherit the enclosing ones.
- When NGINX switches to the server named by SNI, OpenSSL keeps the group list of the default server's context, so a list in any other `server` on the socket changes nothing, in `http` and `stream` alike. A `listen` without `ssl` is TLS when another server's `listen` on the same address and port has it. Without an `http` or `stream` block the default server is unknown, so the list is still reported, with a note in the reason.
