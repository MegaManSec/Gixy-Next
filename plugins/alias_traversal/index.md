# [alias_traversal] Path traversal via misconfigured alias

## What this check looks for

This plugin flags `alias` directives where the `location` prefix and the alias path are not aligned (most commonly: missing a trailing slash on the `location`).

## Why this is a problem

With a mismatched `location`/`alias` pair, NGINX can build the filesystem path in unexpected ways. Attackers can use crafted paths like `/i../` to escape the intended directory and read files outside of it.

## Bad configuration

```
# Location does not end with a slash, but alias points to a directory
location /i {
    alias /data/w3/images/;
}
```

A request to `/i../app/config.py` may map to `/data/w3/app/config.py`, which is outside the intended `/images/` directory.

Regex locations can be even trickier because capture groups may get spliced directly into the filesystem path:

```
location ~ /site(.*) {
  alias /var/www/site/$1;
}
```

If `$1` can start with `.` (or contain `/`), you can end up with traversal-style paths reaching outside the intended directory.

## Better configuration

If the alias points to a directory, make the location look like a directory too:

```
location /i/ {
    alias /data/w3/images/;
}
```

If you are mapping a single file, use an exact match:

```
location = /i.gif {
    alias /data/w3/images/i.gif;
}
```

## Additional notes

This plugin may report either as HIGH or MEDIUM severity, depending on what is detected, and the impact of the configuration:

- Configurations that allow for unfettered path traversal (e.g. from `/var/www/` to `/var/www/../../etc/passwd`) are reported as HIGH.
- Configurations that allow for restricted path traversal (e.g. from `/var/www` to `/var/www-anything-except-dot`) are reported as MEDIUM.
