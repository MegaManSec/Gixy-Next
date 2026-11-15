---
title: "Uncached try_files"
description: "Detects try_files usage without open_file_cache, which makes every request repeat a stat() call for each candidate file."
---

# [try_files_is_evil_too] `try_files` without `open_file_cache`

## What this check looks for

This plugin warns when `try_files` is used, but `open_file_cache` is not configured.

## Why this is a problem

`try_files` checks each candidate file with a `stat()` call: one extra system call when the first candidate exists, plus one for every candidate a request skips. Without `open_file_cache`, every request repeats them. Each call is cheap, so this matters mostly on busy servers.

## Bad configuration

```nginx
location / {
    try_files $uri $uri/ /index.html;
}
```

## Better configuration

Enable `open_file_cache` to cache file metadata:

```nginx
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

Failed lookups are cached only with `open_file_cache_errors on;`. A file created after a cached failure is found once `open_file_cache_valid` (60 seconds by default) has passed.

Caching may not suit file trees that change constantly, or filesystems where metadata caching is risky.
