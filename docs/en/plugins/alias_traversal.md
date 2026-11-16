---
title: "Alias Path Traversal"
description: "Detects alias locations that can be abused for directory traversal when the location and alias trailing slashes do not match."
---

# [alias_traversal] Path traversal via misconfigured alias

## What this check looks for

This plugin flags an `alias` that lets a request reach files outside the aliased directory:

- a prefix `location` without a trailing slash, such as `location /i`;
- a prefix `location` with a trailing slash whose `alias` has none;
- a regex capture or a client-controlled variable, such as `$arg_dir`, that can put `..` into the path.

## Why this is a problem

NGINX replaces the matched location prefix with the alias and appends the rest of the URI as text, and it only collapses `..` when it is a whole path segment of the URI.

## Bad configuration

### location without a trailing slash

```nginx
location /i {
    alias /data/w3/images/;
}
```

A request to `/i../app/config.py` maps to `/data/w3/app/config.py`, outside the intended `/images/` directory.

### alias without a trailing slash

```nginx
location /i/ {
    alias /data/w3/images;
}
```

A request to `/i/-private/secret.txt` maps to `/data/w3/images-private/secret.txt`.

### regex capture

```nginx
location ~ /site(.*) {
  alias /var/www/site/$1;
}
```

`/site../secret.txt` sets `$1` to `../secret.txt`. Making the slash optional, as in `^/download(/?.*)$`, does not help.

### request variable

```nginx
location /files/ {
    alias /home/$arg_dir/;
}
```

Query arguments are not normalized, so `/files/passwd?dir=../etc` serves `/etc/passwd`.

## Better configuration

### directory

If the alias points to a directory, make the location look like a directory too:

```nginx
location /i/ {
    alias /data/w3/images/;
}
```

### single file

If you are mapping a single file, use an exact match:

```nginx
location = /i.gif {
    alias /data/w3/images/i.gif;
}
```

## How severity is determined

- **HIGH**: the path can climb out of the directory, e.g. from `/var/www/` to `/var/www/../../etc/passwd`.
- **MEDIUM**: only a restricted escape is possible, e.g. from `/var/www` to `/var/www-anything-except-dot`.
