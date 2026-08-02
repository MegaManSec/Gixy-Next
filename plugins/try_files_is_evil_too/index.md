# [try_files_is_evil_too] `try_files` without `open_file_cache`

## What this check looks for

This plugin warns when `try_files` is used, but `open_file_cache` is not configured.

## Why this is a problem

`try_files` checks the filesystem repeatedly to see whether files exist. Without caching, those checks translate into repeated `stat()` syscalls. Under load, that adds up quickly and can become one of the hottest spots on a busy server.

## Bad configuration

```
location / {
    try_files $uri $uri/ /index.html;
}
```

This works, but every request may trigger multiple filesystem checks.

## Better configuration

Enable `open_file_cache` to cache file metadata:

```
open_file_cache          max=10000 inactive=30s;
open_file_cache_valid    60s;
open_file_cache_min_uses 2;
open_file_cache_errors   on;

server {
    location / {
        try_files $uri $uri/ /index.html;
    }
}
```

## Additional notes

Caching is not always appropriate. If you serve highly dynamic file trees that change constantly (or you are on a filesystem where metadata caching is risky), you may choose to skip it. If you do, at least be aware of the performance tradeoff and test under realistic load.
