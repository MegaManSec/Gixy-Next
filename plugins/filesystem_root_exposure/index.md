# [filesystem_root_exposure] Filesystem root used as a document root

## What this check looks for

This plugin flags a `root` or `alias` whose path resolves to `/`: the bare `/`, and spellings of it such as `//`, `/./` or `/usr/..`.

## Why this is a problem

NGINX builds the file path for a request by appending the URI to `root`, or by swapping the matched location prefix for `alias`. When that base is `/`, the request path becomes the filesystem path:

```
$ curl http://example.com/etc/passwd
root:x:0:0:root:/root:/bin/bash
...
```

Any file the worker processes can read is served this way: `/etc/passwd`, application source, and any `.env` files or keys the worker user has read access to.

## Bad configuration

```
location / {
    root /;
}

location /files/ {
    alias /;
}
```

## Better configuration

Point `root` or `alias` at a directory that holds only the files you mean to publish:

```
location / {
    root /var/www/example;
}

location /files/ {
    alias /srv/downloads/;
}
```

If the location only proxies or returns and never serves files, it does not need `root /;` at all; remove it.

## Additional notes

- Paths containing variables are not checked, since their value is only known at request time.
- `..` is resolved textually, so `/usr/..` counts as `/`. If a directory before `..` is a symlink, the operating system resolves `..` from the symlink's target instead: on macOS `/tmp` points to `/private/tmp`, so `root /tmp/..;` serves `/private`, not `/`.
- NGINX joins the `alias` and the rest of the URI as text. Under `location /files/`, `alias /.;` maps `/files/etc/passwd` to `/.etc/passwd`, not `/etc/passwd`, so in a location ending in `/` an `alias` is only flagged when it also ends in `/`. Under `location /files`, the same alias maps the request to `/./etc/passwd` and is flagged; [alias_traversal](https://gixy.io/plugins/alias_traversal/index.md) reports that location too.
- An `alias` is only flagged in a prefix location (no modifier, or `^~`). In a regex or exact-match (`=`) location, `alias` replaces the whole request path, so every request maps to `/` itself rather than to a file under it.
