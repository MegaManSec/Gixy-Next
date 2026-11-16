---
title: "Capture Before Regex Map (CVE-2026-42533)"
description: "Detects a value that reads a numbered capture before a variable from a regex map, which overflows a heap buffer on NGINX before 1.30.4 and 1.31.3 (CVE-2026-42533)."
---

# [capture_before_map] Capture `$N` read before a regex `map` variable (CVE-2026-42533)

## What this check looks for

A value with variables (`return`, `set`, `add_header`, `proxy_pass`, a `rewrite` replacement, an `if` comparison, a `map` value, and so on) where:

- a numbered capture (`$1`, `$2`, ...) comes first,
- a variable from a `map` with regex keys comes later,
- one of that map's regex keys defines the same group.

Findings are INFORMATION, because Gixy-Next cannot tell the NGINX version. Patched versions need no change.

## Why this is a problem

On NGINX before 1.30.4 and 1.31.3, the buffer for the value is sized in one pass and filled in a second. Evaluating the map variable in the first pass runs its regex, which replaces the request's captures, so the second pass copies the map's `$1` into room sized for the original one.

## Bad configuration

```nginx
map $uri $section {
    ~^/([^/]+)/ $1;
    default "";
}

server {
    location ~ ^/(.) {
        return 200 "$1$section";
    }
}
```

`$1` is sized as one character, but the map's capture is the whole first path segment. A request for `/` followed by a few thousand `a`s and `/x` overflows the buffer.

## Better configuration

Upgrade NGINX. Until then, use a named capture, which the map does not change:

```nginx
map $uri $section {
    ~^/([^/]+)/ $1;
    default "";
}

server {
    location ~ ^/(?<first>.) {
        return 200 "$first$section";
    }
}
```

## Additional notes

- A map variable placed before the capture (`"$section$1"`) is not reported; `$1` is then the map's capture.
- NGINX caches a map variable for the request unless the map is `volatile`, so a map already evaluated earlier does not run again. Gixy-Next cannot see that and reports the pattern anyway.
