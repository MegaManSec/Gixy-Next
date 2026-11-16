---
title: "Alias Path Traversal"
description: "Detects alias directives that let a request escape the aliased directory: a location and alias that disagree on a trailing slash, or a capture or request variable in the alias path."
---

# [alias_traversal] Path traversal via misconfigured alias

## What this check looks for

This plugin flags an `alias` that lets a request reach files outside the aliased directory:

- a prefix `location` without a trailing slash, such as `location /i`;
- a prefix `location` with a trailing slash whose `alias` has none;
- a regex capture or a client-controlled variable, such as `$arg_dir`, that can put `..` into the path.

## Why this is a problem

NGINX replaces the matched location prefix with the alias and appends the rest of the URI as text. It collapses `..` only when it is a whole URI segment, so `/i../` passes through unchanged, and a `..` inside a variable is never checked.

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

## Additional notes

- A capture that follows a `/` in the location regex, such as `^/images/(.*)$`, is not reported: NGINX has already collapsed `..` segments in the URI. Nor is a capture that cannot form `..`, such as `(\.[a-z]+)`.
- Variables are followed through `set`, `if` and `map`: `set $dir $arg_dir; alias /home/$dir/;` is reported like `alias /home/$arg_dir/;`, and `alias $root;` with a fixed `set $root` is judged by that value's trailing slash. A `map` of fixed paths is not judged.
- `$host`, `$http_host` and `server_name` captures are not reported, since NGINX rejects a Host header containing `/` or `..`.
- `$remote_user` is not reported while `auth_basic` with an `auth_basic_user_file` is in effect and `satisfy` is not `any`: only user names listed in the file get through. In a file without an `http` block, the user file is assumed to be set in the main configuration. Under `satisfy any`, a client from an allowed address can send any user name, so it is reported.
