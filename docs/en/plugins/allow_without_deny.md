---
title: "Allow Without Deny"
description: "Detects allow and deny rules that have no effect: allow rules with no deny that would otherwise catch their clients, and rules shadowed by earlier rules so that they never apply."
---

# [allow_without_deny] `allow` without `deny`

## What this check looks for

This plugin simulates how NGINX evaluates the `allow` and `deny` rules of a context and flags:

- `allow` directives that change nothing, because no `deny` in the same context would otherwise have blocked any of the allowed clients. Usually that means `deny all;` is missing; a `deny` for an unrelated range is just as ineffective.
- a `deny` that never applies, because earlier `allow` rules already match every address it names.
- an `allow` that never applies, because earlier `deny` rules already match every address it names.

## Why this is a problem

In NGINX, `allow` does not mean "only these addresses". Rules are checked in order, the first match wins, and a client that matches no rule is let through. An `allow` therefore only has an effect when a later `deny` would otherwise have blocked some of those addresses; everyone else is still allowed too unless you deny them. For the same reason a rule placed after one that already covers its addresses is dead: the configuration reads as if it restricts something, but it does not.

## Bad configuration

### no deny at all

```nginx
location /admin/ {
    root /var/www/;
    allow 10.0.0.0/8;
    # ... no deny
}
```

This allows `10.0.0.0/8`, but it does not block anything else.

### deny that does not cover the allowed range

```nginx
location /admin/ {
    root /var/www/;
    allow 10.0.0.0/8;
    deny 192.0.2.0/24;
}
```

A client from `203.0.113.7` matches neither rule and is let through, so the `allow` changes nothing.

### deny shadowed by an earlier allow

```nginx
location /admin/ {
    root /var/www/;
    allow 10.0.0.0/8;
    deny 10.1.2.3;
}
```

`10.1.2.3` matches `allow 10.0.0.0/8` first, so the `deny` never applies and that host is allowed.

### allow shadowed by an earlier deny

```nginx
location /admin/ {
    root /var/www/;
    deny 192.0.2.0/24;
    allow 192.0.2.5;
}
```

`192.0.2.5` matches the `deny` first, so the `allow` never applies and that host is denied. Swap the two rules to carve the exception out of the subnet.

## Better configuration

### deny all after the allow list

```nginx
location /admin/ {
    root /var/www/;
    allow 10.0.0.0/8;
    deny all;
}
```

Now the access policy is unambiguous: allow the private range, deny everyone else.

### deny that overlaps the allow

```nginx
location /admin/ {
    root /var/www/;
    allow 192.0.2.5;
    deny 192.0.2.0/24;
}
```

Blocking a subnet except for one host is a legitimate pattern: the `allow` comes first and carves an exception out of the `deny`, so it is not reported.

## How severity is determined

- **HIGH**: `allow` directives without an effective `deny`, and a `deny` that never applies. In both cases clients the configuration appears to block are let through.
- **MEDIUM**: an `allow` that never applies. The clients it names stay blocked, which is a lockout rather than an exposure, but the configuration does not do what it says.

## Additional notes

`allow` and `deny` rules are not merged across levels. As soon as a child context declares an `allow` or `deny` of its own, it stops inheriting the parent's rules (`ngx_http_access_merge_loc_conf`). A `deny all;` at the `server` level therefore does *not* protect a `location` that only says `allow 10.0.0.0/8;`: that location is open to everyone, while a sibling location without rules of its own still inherits the `deny all;`. Every context that declares an `allow` needs its own `deny`.

NGINX keeps separate rule lists for IPv4, IPv6 and `unix:` clients, and `all` joins every list. `deny 0.0.0.0/0;` therefore blocks only IPv4 clients and `deny ::/0;` only IPv6 ones, so neither counts as covering an `allow` from the other family. An IPv4-mapped IPv6 client (`::ffff:a.b.c.d`, as seen on a `listen [::]:80 ipv6only=off` socket) is checked against the IPv4 rules whenever the context has any, so `allow ::ffff:10.0.0.0/104; deny all;` denies those clients: `deny all` is also an IPv4 rule and matches first.

A rule that repeats what an earlier rule of the same kind already covers is redundant but harmless, and is not reported.

This plugin does not warn about `allow` directives without a `deny` when the effective configuration is `satisfy any;` combined with an auth module (`auth_basic`, `auth_request`, `auth_jwt`, or `auth_oidc`):

```nginx
location /admin/ {
    satisfy any;
    allow 10.0.0.0/8;
    auth_basic "Restricted";
    auth_basic_user_file /etc/nginx/htpasswd;
}
```

That is the intended "IP allowlist OR authentication" pattern. Clients outside the allow list fall through to authentication whether or not `deny all;` is present, so omitting it changes nothing.
