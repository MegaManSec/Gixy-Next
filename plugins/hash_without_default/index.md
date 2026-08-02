# [hash_without_default] Missing `default` in hash blocks (`map`, `geo`)

## What this check looks for

This plugin checks hash-like blocks such as `map` and `geo` and warns when they do not define a `default` value.

### Map special-case

For `map`, the check intentionally ignores a very common pattern of when a `map` has exactly one mapping entry and no explicit `default`. This configuration is often meant to return an empty string for all other inputs, and is used with `limit_req` and `limit_conn`, where an empty key disables limits.

Therefore, this plugin only really warns for `map` when there are two or more mapping entries and no explicit `default`. It warns for all cases with `geo`.

## Why this is a problem

A `map` or `geo` without a default can leave "unmatched" inputs in a surprising state. Depending on how you use the variable later, that can mean:

- falling back to an unintended value,
- skipping security or routing logic,
- or accidentally allowing a request that should have been denied.

For `map`, this risk grows as the number of explicit mappings increases (because more cases are being handled, but unmatched inputs still have no defined behavior).

## Bad configuration

```
map $request_uri $is_admin {
    /admin 1;
    /admin/ 1;
    # no default
}

# Later:
if ($is_admin) {
    allow 10.0.0.0/8;
}
```

If `$request_uri` does not match, `$is_admin` may be empty and the surrounding logic may not behave the way you expect.

## Better configuration

Pick an explicit default that matches least privilege:

```
map $request_uri $is_admin {
    default 0;   # not admin unless matched
    /admin  1;
    /admin/ 1;
}
```

Same idea for `geo`:

```
geo $block_client {
    default 0;        # not blocked unless matched
    192.0.2.0/24 1;
}
```

## Intentional empty default pattern (map)

Sometimes, an implicit empty result is the goal. A common example is selectively enabling rate limits:

```
# Only requests matching /api get a non-empty key (limits apply).
# Everything else gets an empty key (limits disabled).
map $request_uri $limit_key {
    ~^/api $binary_remote_addr;
}
```

This is why the plugin does not warn on `map` blocks with a single mapping entry and no explicit `default`.

## Additional notes

- If the variable controls an allow/deny decision, prefer deny-by-default and add allow rules narrowly.
- For routing decisions, choose a safe fallback upstream and keep it explicit.
- If you rely on the "empty disables behavior" pattern (for example, rate limiting keys), keep the `map` minimal and document the intent.
