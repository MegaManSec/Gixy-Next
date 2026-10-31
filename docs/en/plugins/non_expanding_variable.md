---
title: "Variables That NGINX Does Not Expand"
description: "Detects variables written where NGINX takes the text literally: geo and split_clients values, location prefixes, server_name and map keys, the auth_request URI, paths such as error_log, and regular expressions."
---

# [non_expanding_variable] Variable used where NGINX does not expand variables

## What this check looks for

This plugin flags variables in places where NGINX does not expand them. In these places, `$name` is literal text:

- the values of `geo` and `split_clients` blocks,
- location prefixes, including `location = ...` and `location ^~ ...`,
- `server_name` entries and `map` keys,
- the URI of `auth_request`,
- the path of `error_log`, the `*_temp_path` directives and the `*_cache_path` directives.

In a regular expression, `$name` is not a variable either. `$` is the end-of-string anchor, so `^/$admin/` asks for the end of the string followed by `admin/`, which can never happen. The plugin checks the regular expressions in `location`, `if`, `rewrite`, `server_name` and `map`.

## Why this is a problem

NGINX gives no warning for any of these, and `nginx -t` reports the configuration as valid. The variable silently becomes a constant, or the block silently never matches:

- `geo $limit_key { default $binary_remote_addr; }` sets `$limit_key` to the 19-character string `$binary_remote_addr` for every client. A `limit_req_zone` keyed on it puts all of those clients in one shared bucket.
- `location ~ ^/$admin_prefix/ { deny all; }` never matches, so the requests it was meant to deny are handled by some other location.
- `error_log /var/log/nginx/$host.log;` writes to a file literally named `$host.log`.

## Bad configuration

### rate limiting keyed on a geo value

```nginx
geo $limit_key {
    default $binary_remote_addr;
    10.0.0.0/8 "";
}

limit_req_zone $limit_key zone=per_ip:10m rate=10r/s;
```

Every client outside `10.0.0.0/8` gets the same key, `$binary_remote_addr`, and therefore the same bucket.

### a variable in a regular expression

```nginx
location ~ ^/$admin_prefix/ {
    deny all;
}
```

The location never matches, so the `deny` never applies.

### a variable in a location prefix

```nginx
location /api/$version/ {
    proxy_pass http://backend;
}
```

This only matches requests whose path literally starts with `/api/$version/`.

## Better configuration

### rate limiting with an allowlist

`map` expands variables in its values, so use `geo` to decide who is exempt and `map` to pick the key:

```nginx
geo $allowlisted {
    default 0;
    10.0.0.0/8 1;
}

map $allowlisted $limit_key {
    0 $binary_remote_addr;
    1 "";
}

limit_req_zone $limit_key zone=per_ip:10m rate=10r/s;
```

`limit_req` and `limit_conn` do not count requests with an empty key, so allowlisted clients are not limited.

### matching on a value

Write the value into the location or pattern itself. If it really has to come from a variable, compute a flag with `map` and act on it in the `server` block, where it applies before any location is chosen:

```nginx
map $uri $is_admin {
    ~^/admin/ 1;
    default "";
}

server {
    if ($is_admin) {
        return 403;
    }
}
```

A predicate location such as `location $is_admin` (NGINX 1.31.5 and later) is not a replacement here: NGINX only tries it after the regular-expression locations, and skips it after a `^~` match, so `/admin/x.php` can still reach a `location ~ \.php$`.

### paths

Write the path literally. For a per-site error log, put an `error_log` in each `server` block:

```nginx
server {
    server_name example.com;
    error_log /var/log/nginx/example.com.error.log;
}
```

## How severity is determined

- **HIGH**: a `geo` or `split_clients` value that a `limit_req_zone` or `limit_conn_zone` key depends on entirely, directly or through `map`. Also a location or `if` that never matches the requests it was written for, because of a literal prefix or a regular expression that can never match, but that contains access control: `deny`, `auth_basic`, `auth_request`, `auth_jwt`, `auth_oidc`, or `return` with `401`, `403` or `444`.
- **MEDIUM**: any other value, location, `server_name`, `map`, `rewrite`, `if` or `auth_request` finding.
- **LOW**: a path, since it only changes where NGINX writes files.

## Additional notes

`location $name` without a modifier is a predicate location and is not reported, and neither is a named location such as `location @fallback`. `server_name $hostname` is the machine's host name, so it is not reported either.

In a regular expression, an escaped dollar (`\$`) and a character class (`[$]`) are literal dollar signs and are not reported. Neither is a `$name` in an optional part of the pattern, such as one branch of an alternation, since the rest of the pattern can still match. With a negated match such as `if ($uri !~ ^/$prefix/)`, the condition is always true instead.
