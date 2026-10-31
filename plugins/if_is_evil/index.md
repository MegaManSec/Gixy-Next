# [if_is_evil] `if` is evil when used in location context

## What this check looks for

This plugin warns about `if` directives placed inside a `location` block.

## Why this is a problem

`if` belongs to the rewrite module and is evaluated during the rewrite phase. Inside a `location`, mixing `if` with directives from other modules can produce surprising results, including directives being skipped, headers not being set, or in some historical edge cases even crashes. The configuration may look reasonable, but the request processing model is not "run these directives in order".

The only operations that are considered consistently safe inside an `if` in a location are:

- `return ...;`
- `rewrite ... last;`
- `rewrite ... redirect;`
- `rewrite ... permanent;`

## Bad configuration

```
location /only-one-if {
    set $true 1;

    if ($true) {
        add_header X-First 1;
    }

    if ($true) {
        add_header X-Second 1;
    }
}
```

This is a classic foot-gun: you expect both headers, but you will typically only see one, because `add_header` is not "safe" inside this style of `if` usage.

Another common pitfall:

```
location /if-try-files {
    try_files /file @fallback;

    set $true 1;
    if ($true) {
        # nothing
    }
}
```

The presence of `if` can change how the location behaves, and can break things you would not expect to be related.

## Better configuration

If your goal is to return early based on a condition, keep it simple and use `return`:

```
location / {
    if ($bad) {
        return 403;
    }

    # Normal processing continues here
}
```

For anything more complex, move the logic out of `if`:

- use `map` at `http` level to compute a variable,
- or split behavior into separate locations and use `error_page` with a named location.

Example: choose an alternate handler via a named location:

```
location / {
    error_page 418 = @other;
    recursive_error_pages on;

    if ($something) {
        return 418;
    }

    # normal handling
}

location @other {
    # alternate handling
}
```

## Additional notes

If you still want to use `if` inside a location, treat it as a rewrite-only tool. As soon as you are using it to toggle headers, access rules, proxying, or file handling, you are in the territory where configs become fragile. To read more about "If Is Evil", read [this page](https://web.archive.org/web/20220316092522/https://www.nginx.com/resources/wiki/start/topics/depth/ifisevil/) and [this page](https://web.archive.org/web/20240908024013/http://forum.nginx.org/read.php?2,174917).
