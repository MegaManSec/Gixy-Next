---
title: "Capture Before Regex Map (CVE-2026-42533)"
description: "Detects a value that reads $N before a variable from a regex map, the pattern that triggers CVE-2026-42533."
---

# [capture_before_map] `$N` before a regex `map` variable in one value (CVE-2026-42533)

CVE-2026-42533 is a heap buffer overflow in nginx workers before 1.30.4 (stable) and 1.31.3 (mainline).

## What this check looks for

A value with variables (`return`, `set`, `add_header`, `proxy_pass`, a `rewrite` replacement, an `if` comparison, a `map` value, and so on) where:

- a numeric capture (`$1`, `$2`, ...) comes first,
- a variable from a `map` with regex keys comes later,
- one of that map's regex keys defines the same group.

The nginx version is not in the configuration, so the finding is INFORMATION. Patched versions need no change.

## Why this is a problem

nginx sizes the buffer for the value in one pass and fills it in a second. The map runs in between and replaces `$1` with its own capture, which can be longer than the buffer.

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

A request for `/aaaa…aaaa/x` with a few thousand `a`s overflows the buffer.

## Better configuration

Upgrade nginx. Until then, use a named capture, which the map does not change:

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
- nginx caches a map variable for the request, so a map already evaluated earlier does not run again. Gixy-Next cannot see that and reports the pattern anyway.
