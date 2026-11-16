---
title: "Missing Map/Geo Default"
description: "Detects map and geo blocks without a default, which give every unmatched input an empty string and can disable rate limits or skip access and routing logic."
---

# [hash_without_default] Missing `default` in `map` and `geo` blocks

## What this check looks for

This plugin flags:

- a `map` with two or more entries and no `default`,
- a `geo` with no `default`.

## Why this is a problem

A `map` or `geo` without a `default` gives every input you did not list an empty string. When empty is also the safe value, that is fine. When it is not, every unlisted input gets the unsafe behavior: an empty `limit_req` or `limit_conn` key disables the limit for that request, and `if ($var)` treats an empty value as false, so a check that acts on a non-empty value is skipped.

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

- A `map` with a single entry and no `default` is not reported. That pattern usually means "empty for everything else", for example a `limit_req` key that only applies to one kind of request. `hostnames` and `volatile` do not count as entries.
- A `geo` that lists both `0.0.0.0/0` and `::/0` is not reported, since that is what `default` stands for. `0.0.0.0/0` alone still leaves IPv6 clients with the empty value.
