---
title: "Invalid Regex Captures"
description: "Detects references to non-existent regex capture groups (for example $2 when the pattern has only one group). NGINX treats missing captures as empty strings, which can silently break rewrites and logic."
---

# [invalid_regex] Using a nonexistent regex capture group

## What this check looks for

This plugin looks for places where a configuration references `$1`, `$2`, and so on, but the regex being used does not actually define that capture group.

Common places this shows up:

- `rewrite` replacement strings
- `set` inside an `if ($var ~ regex)` block
- regex `map` entries whose value references captures the key pattern does not define
- `return`, `proxy_pass`, `add_header`/`more_set_headers`, `try_files` and `set` values referencing `$N` when no regex anywhere in the enclosing server (location, if, rewrite, server_name) or any map key defines that group
- patterns that use non-capturing groups like `(?:...)` or inline modifiers like `(?i)` and then expect numbered captures

Note that NGINX reads exactly one digit after `$`: `$12` means capture `$1`
followed by a literal `2`, so only `$1` through `$9` exist.

Because `$N` always refers to the most recent regex evaluation at runtime,
the whole-scope check is deliberately conservative: it only reports a
reference when **no** regex that could run for the request defines that
group, which makes the reference provably empty.

## Why this is a problem

NGINX does not throw an error when you reference a missing group. It just substitutes an empty string. That turns into subtle bugs: broken redirects, unexpected paths, or conditions that never match the way you think they do.

## Bad configuration

### Case 1: modifier without a capture

```nginx
rewrite "(?i)/path" /$1 break;
```

`(?i)` changes matching behavior, but it does not create a capture. There is no `$1`, so the replacement becomes `/`.

### Case 2: no captures at all

```nginx
rewrite "^/path" /$1 redirect;
```

The pattern has zero capture groups, so `$1` is always empty.

### Case 3: map value without a capture

```nginx
map $uri $dest {
    ~^/old/ $1;
}
```

When a map regex is evaluated it resets the request's numbered captures, so
`$1` in the value can only come from the entry's own pattern — which defines
no groups here. The value is always empty.

### Case 4: no capture provider anywhere in scope

```nginx
location ~ ^/static/ {
    return 301 https://example.com/$1;
}
```

No regex in the enclosing server defines a capture group, so `$1` is
guaranteed empty.

## Better configuration

Either remove the unnecessary capture reference:

```nginx
rewrite "^/path" /newpath redirect;
```

Or add a capture group if you actually need part of the input:

```nginx
rewrite "^/path/(.*)$" /newpath/$1 redirect;
```

Same idea inside an `if`:

```nginx
if ($uri ~ "^/path/(.*)$") {
    set $x $1;
}
```
