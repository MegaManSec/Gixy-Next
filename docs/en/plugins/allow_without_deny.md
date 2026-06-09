---
title: "Allow Without Deny"
description: "Detects allow rules that are not paired with an explicit deny. Without a deny, the block is still publicly accessible."
---

# [allow_without_deny] `allow` without `deny`

## What this check looks for

This plugin warns when a block contains one or more `allow` directives, but does not also enforce a `deny` (usually `deny all;`) in the same effective scope.

## Why this is a problem

In NGINX, `allow` does not mean "only these addresses". It means "these addresses are allowed", but everyone else is still allowed too unless you also deny them somewhere.

## Bad configuration

```nginx
location /admin/ {
    root /var/www/;
    allow 10.0.0.0/8;
    # ... no deny
}
```

This allows `10.0.0.0/8`, but it does not block anything else.

## Better configuration

```nginx
location /admin/ {
    root /var/www/;
    allow 10.0.0.0/8;
    deny all;
}
```

Now the access policy is unambiguous: allow the private range, deny everyone else.

## Additional notes

If you apply `deny all;` at a higher level (for example at `server`), and then selectively allow in a child location, that can also be valid. The important part is that the final effective policy is "allow some, deny the rest", not just "allow some".

This plugin does not warn when the effective configuration is `satisfy any;` combined with an auth module (`auth_basic`, `auth_request`, or `auth_jwt`):

```nginx
location /admin/ {
    satisfy any;
    allow 10.0.0.0/8;
    auth_basic "Restricted";
    auth_basic_user_file /etc/nginx/htpasswd;
}
```

That is the intended "IP allowlist OR authentication" pattern. Clients outside the allow list fall through to authentication whether or not `deny all;` is present, so omitting it changes nothing.
