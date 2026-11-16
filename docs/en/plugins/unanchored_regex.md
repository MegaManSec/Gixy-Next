---
title: "Unanchored Regular Expression"
description: "Detects regular expressions on the request URI or host name that are not anchored with ^ or $, so they also match requests they were not written for."
---

# [unanchored_regex] Unanchored regular expressions

## What this check looks for

A regular expression on the request URI that is not anchored with `^` or `$`, or on the host name that is not anchored with both. In an alternation, every branch needs its own anchors. The plugin checks:

- `location ~` and `location ~*` patterns,
- `if` tests of `$uri`, `$document_uri`, `$request_uri` or `$host`, and regex keys of a `map` on one of them,
- `rewrite` patterns,
- `server_name` regular expressions.

## Why this is a problem

An unanchored pattern matches anywhere in the input. `location ~ \.php` also hands `/uploads/x.php.jpg` to PHP, `location ~ \.(jpg|png)` also serves `/x.jpg.php` as a static file, and `if ($request_uri !~ "/api/") { return 403; }` lets `/x/api/y` through.

A host name needs both anchors, because the client chooses the name: `server_name ~^(www\.)?example\.com` also selects the server for `example.com.attacker.net`, and `~example\.com$` for `notexample.com`.

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
    server_name ~^(www\.)?example\.com;

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

- A `location` or positive `if` whose block only rejects (`deny`, `internal` or a 4xx or 5xx `return`, with or without logging directives), such as `location ~ /\.ht { deny all; }`, is not reported: matching anywhere is the intent. A negated `if` is still reported.
- A positive `if` whose block only sets variables, such as a cache-skip list, is not reported either.
- A `rewrite` whose leading text the enclosing `location` path already starts with, such as `rewrite /app(.*) $1 break;` in `location ^~ /app/`, can only match at the start and is not reported.
- A pattern of only `.` wildcards, such as `server_name ~.;`, matches anything and is not reported. Neither are tests of other variables, such as `if ($http_user_agent ~* bot)`.
- A pattern gixy cannot parse, such as branch reset `(?|...)` or recursion `(?R)`, is skipped and may still be unanchored.
