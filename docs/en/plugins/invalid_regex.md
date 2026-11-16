---
title: "Invalid Regex Captures"
description: "Detects $N references to capture groups that no regex defines. NGINX substitutes an empty string, which silently breaks rewrites and logic."
---

# [invalid_regex] Invalid regex capture groups

## What this check looks for

A `$1` to `$9` reference that the regex in effect cannot set:

- a `rewrite` replacement or a regex `map` value that uses a group its own pattern lacks,
- a `set` inside an `if ($var ~ regex)` block that uses a group the pattern lacks, or any group inside an `if ($var !~ regex)` block; a `rewrite` earlier in the block takes over, and one that stops on a match (`last`, `break`, `redirect`, `permanent`, or an `http://`, `https://` or `$scheme` replacement) leaves no group,
- any other value, such as `return`, `proxy_pass`, `root`, `alias`, `add_header`, `fastcgi_param` or an `if` comparison, that uses a group no regex in the server or in a `map` defines.

NGINX reads one digit after `$`, so `$12` is `$1` followed by `2`. In a file without an `http` or `server` block, the last check runs only under a regex `location`, because the including file may hold the other regexes.

## Why this is a problem

NGINX substitutes an empty string for a missing group, which silently breaks redirects, paths and conditions.

## Bad configuration

### modifier without a capture

```nginx
rewrite "(?i)/path" /$1 break;
```

`(?i)` changes matching, but it does not capture, so `$1` is empty.

### map value without a capture

```nginx
map $uri $dest {
    ~^/old/ $1;
}
```

### no capture provider in scope

```nginx
location ~ ^/static/ {
    return 301 https://example.com/$1;
}
```

## Better configuration

```nginx
rewrite "^/path/(.*)$" /newpath/$1 redirect;
```

```nginx
map $uri $dest {
    ~^/old/(.*)$ /new/$1;
}
```

```nginx
location ~ ^/static/(.*)$ {
    return 301 https://example.com/$1;
}
```

## Additional notes

- A regex gixy cannot parse, such as branch reset `(?|...)` or recursion `(?R)`, is skipped, and because it could define any group, the whole-scope check stays quiet for its server (or the whole configuration, for a `map` key).
