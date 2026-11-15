---
title: "Map Default Value Missing"
description: "Detects hash/geo blocks that omit a default. Missing defaults can cause unexpected fall-through behavior that weakens access control, routing, and rate-limit logic."
---

# [hash_without_default] Missing `default` in hash blocks (`map`, `geo`)

## What this check looks for

This plugin checks hash-like blocks such as `map` and `geo` and warns when they do not define a `default` value.

### Map special-case

For `map`, the check intentionally ignores a very common pattern of when a `map` has exactly one mapping entry and no explicit `default`. This configuration is often meant to return an empty string for all other inputs, and is used with `limit_req` and `limit_conn`, where an empty key disables limits.

Therefore, this plugin only really warns for `map` when there are two or more mapping entries (not counting `hostnames` and `volatile`) and no explicit `default`. It warns for all cases with `geo`, unless both `0.0.0.0/0` and `::/0` are listed, which is what `default` stands for.

## Why this is a problem

A `map` or `geo` without a default gives unmatched inputs an empty string, which `if` treats like `0`. That is harmless when the empty value is also the safe one, but when the safe fallback is non-empty, every input you did not list gets the unsafe value:

- an empty rate-limit key turns `limit_req` and `limit_conn` off for that request,
- an empty value can skip security or routing logic that only acts on a non-empty one,
- or it can let a request through that should have been denied.

## Bad configuration

```nginx
map $http_x_client_tier $limit_key {
    free  $binary_remote_addr;
    trial $binary_remote_addr;
    # no default
}

limit_req_zone $limit_key zone=api:10m rate=5r/s;
```

A client that sends no `X-Client-Tier` header, or any other tier, gets an empty key and is not rate-limited.

## Better configuration

Pick an explicit default that matches least privilege:

```nginx
map $http_x_client_tier $limit_key {
    default $binary_remote_addr;   # limited unless exempted
    premium "";
}

limit_req_zone $limit_key zone=api:10m rate=5r/s;
```

Same idea for `geo`:

```nginx
geo $block_client {
    default 0;        # not blocked unless matched
    192.0.2.0/24 1;
}
```

## Additional notes

- If the variable controls an allow/deny decision, prefer deny-by-default and add allow rules narrowly.
- For routing decisions, choose a safe fallback upstream and keep it explicit.
- If you rely on the "empty disables behavior" pattern (for example, rate limiting keys), keep the `map` minimal and document the intent.
