---
title: "Allow Without Deny"
description: "Detects allow rules that are not paired with a deny covering the allowed addresses. Without such a deny, the block is still publicly accessible."
---

# [allow_without_deny] `allow` without `deny`

## What this check looks for

This plugin warns when a block contains one or more `allow` directives, but no `deny` in the same scope covers any of the allowed addresses. Usually that means `deny all;` is missing; a `deny` for an unrelated range is just as ineffective.

## Why this is a problem

In NGINX, `allow` does not mean "only these addresses". Rules are checked in order, the first match wins, and a client that matches no rule is let through. An `allow` therefore only has an effect when a later `deny` would otherwise have blocked some of those addresses; everyone else is still allowed too unless you deny them.

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

Blocking a subnet except for one host is a legitimate pattern: the `allow` carves an exception out of the `deny`, so it is not reported.

## Additional notes

`allow` and `deny` rules are not merged across levels. As soon as a child context declares an `allow` or `deny` of its own, it stops inheriting the parent's rules (`ngx_http_access_merge_loc_conf`). A `deny all;` at the `server` level therefore does *not* protect a `location` that only says `allow 10.0.0.0/8;`: that location is open to everyone, while a sibling location without rules of its own still inherits the `deny all;`. Every context that declares an `allow` needs its own `deny`.

`deny all;` covers both address families. `deny 0.0.0.0/0;` blocks only IPv4 clients and `deny ::/0;` only IPv6 ones, so neither counts as covering an `allow` from the other family.

This plugin does not warn when the effective configuration is `satisfy any;` combined with an auth module (`auth_basic`, `auth_request`, `auth_jwt`, or `auth_oidc`):

```nginx
location /admin/ {
    satisfy any;
    allow 10.0.0.0/8;
    auth_basic "Restricted";
    auth_basic_user_file /etc/nginx/htpasswd;
}
```

That is the intended "IP allowlist OR authentication" pattern. Clients outside the allow list fall through to authentication whether or not `deny all;` is present, so omitting it changes nothing.
