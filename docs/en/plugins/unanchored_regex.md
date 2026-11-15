---
title: "Unanchored Regex Pattern"
description: "Detects regular expressions on the request URI or host name that are not anchored with ^ or $, so they also match requests they were not written for."
---

# [unanchored_regex] Unanchored regular expressions

## What this check looks for

A regular expression matched against the request URI or host name that is not anchored with `^` or `$`. In an alternation, every branch needs its own anchor. The plugin checks:

- `location ~` and `location ~*` patterns,
- `if` tests of `$uri`, `$document_uri` or `$request_uri`, and regex keys of a `map` on one of them,
- `rewrite` patterns,
- `server_name` regular expressions.

## Why this is a problem

An unanchored pattern matches anywhere in the input. `location ~ \.php` also handles `/foo.php/x`, `server_name ~example\.com` also selects the server for `notexample.com.attacker.net`, and `if ($request_uri !~ "/api/") { return 403; }` lets `/x/api/y` through.

## Bad configuration

```nginx
location ~ \.php {
    # ...
}
```

```nginx
# Matches /bar, /x/bar, /foo/bar/baz, ...
location ~ ^/foo|/bar {
    # ...
}
```

```nginx
server {
    server_name ~example\.com;

    location / {
        if ($request_uri !~ "/api/") {
            return 403;
        }
    }
}
```

## Better configuration

```nginx
location ~ \.php$ {
    # ...
}

location ~ ^/foo$|^/bar$ {
    # ...
}
```

```nginx
server {
    server_name ~^(www\.)?example\.com$;

    location / {
        if ($request_uri !~ "^/api/") {
            return 403;
        }
    }
}
```

## Additional notes

- Not reported, because matching anywhere is the intent: a `location` or positive `if` whose block only rejects (`deny`, `internal`, or a 4xx or 5xx `return`, optionally with `access_log` and `log_not_found`), such as `location ~ /\.ht { deny all; }`, and a positive `if` whose block only sets variables. A negated `if` is still reported.
- A `rewrite` whose leading text the enclosing `location` path already starts with, such as `rewrite /app(.*) $1 break;` in `location ^~ /app/`, is not reported, because it can only match at the start.
- A pattern of only `.` wildcards, such as `server_name ~.;`, matches anything and is not reported. Neither are tests of other variables, such as `if ($http_user_agent ~* bot)`.
- A pattern gixy cannot parse, such as branch reset `(?|...)` or recursion `(?R)`, is skipped, so no finding there says nothing about its anchors.
