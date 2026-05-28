---
title: "nginx -T Live Configuration Dump"
description: "See what an nginx live configuration dump looks like, why nginx -T is useful for debugging includes, and how to capture the dump (stdout) separately from test status (stderr)."
---

# Live Configuration Dumps: nginx -T

An nginx "live configuration dump" is what you get from running this command on a system configured for NGINX:

```bash
nginx -T
```

The `-T` flag is an addition to nginx's `-t` flag:

- `-t` tests the configuration: nginx checks syntax, tries to open all files referenced by the config (includes, certificates, logs, etc.), and resolves any static hostnames in the config.
- `-T` does the same test, and additionally dumps all loaded configuration files to standard output, as a *single* output to stdout.

This is useful because nginx configs are usually a pile of `include`s across multiple files, and this turns that pile into a single artifact you can diff, grep, attach to a ticket, or feed into tooling.

Gixy-Next can use this single-file configuration dump and parse each section, treating it as a picture-perfect NGINX configuration, providing a perfect view of the configuration that NGINX will actually use, regardless of where NGINX or Gixy-Next is running. You can paste such a configuration dump into the [Gixy-Next In-Browser Scanner](https://gixy.io/scanner/) if you desire, too.

The configuration dump is printed to stdout, while the status of the configuration is printed to stderr, which looks like this:

```text
nginx: the configuration file /etc/nginx/nginx.conf syntax is ok
nginx: configuration file /etc/nginx/nginx.conf test is successful
```

## Example

The following is an example of how a multi-file configuration is packed by `nginx -T` into a single file.

### Example config on disk

In `/etc/nginx/nginx.conf`:

```nginx
user  nginx;
worker_processes auto;

events {
    worker_connections 1024;
}

http {
    include       /etc/nginx/mime.types;
    default_type  application/octet-stream;

    access_log /var/log/nginx/access.log;
    error_log  /var/log/nginx/error.log warn;

    sendfile on;
    keepalive_timeout 65;

    include /etc/nginx/conf.d/*.conf;
    include /etc/nginx/sites-enabled/*;
}
```

In `/etc/nginx/conf.d/gzip.conf`:

```nginx
gzip on;
gzip_comp_level 5;
gzip_types text/plain text/css application/json application/javascript;
```

In `/etc/nginx/sites-enabled/example.conf`:

```nginx
upstream app_backend {
    server 127.0.0.1:3000;
    keepalive 16;
}

server {
    listen 80;
    server_name example.test;

    location /healthz {
        return 200 "ok\n";
        add_header Content-Type text/plain;
    }

    location / {
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_pass http://app_backend;
    }
}
```

### Representative `nginx -T` output

Running `nginx -T`, we get in `stderr`:

```text
nginx: the configuration file /etc/nginx/nginx.conf syntax is ok
nginx: configuration file /etc/nginx/nginx.conf test is successful
```

In `stdout`, we get:

```nginx
# configuration file /etc/nginx/nginx.conf:
user  nginx;
worker_processes auto;

events {
    worker_connections 1024;
}

http {
    include       /etc/nginx/mime.types;
    default_type  application/octet-stream;

    access_log /var/log/nginx/access.log;
    error_log  /var/log/nginx/error.log warn;

    sendfile on;
    keepalive_timeout 65;

    include /etc/nginx/conf.d/*.conf;
    include /etc/nginx/sites-enabled/*;
}

# configuration file /etc/nginx/mime.types:
types {
    text/html                             html htm shtml;
    text/css                              css;
    application/javascript                js;
    # ... lots more ...
}

# configuration file /etc/nginx/conf.d/gzip.conf:
gzip on;
gzip_comp_level 5;
gzip_types text/plain text/css application/json application/javascript;

# configuration file /etc/nginx/sites-enabled/example.conf:
upstream app_backend {
    server 127.0.0.1:3000;
    keepalive 16;
}

server {
    listen 80;
    server_name example.test;

    location /healthz {
        return 200 "ok\n";
        add_header Content-Type text/plain;
    }

    location / {
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_pass http://app_backend;
    }
}
```

Note: you may get an error to `stderr` like

```text
nginx: [emerg] host not found in upstream "backend.example.com" in /etc/nginx/conf.d/site.conf:42
```

This error means that nginx cannot resolve one of the hostnames in your configuration that has been passed to `proxy_pass`. You probably shouldn't be using a static `proxy_pass` anyways, see [stale_dns_cache](https://gixy.io/plugins/stale_dns_cache/).

## Why you would ever need this

Using `nginx -T` can be useful for a few reasons, namely:

- You want to see the full configuration of what `nginx` actually loads after all `include`s are loaded and so on.
- You want to analyze the full configuration on a system other than the one that is actually running NGINX.
- You want a CI artifact: "this is the config that will be run".

## Gixy-Next and nginx -T

Gixy-Next will automatically detect when a configuration dump like this is scanned. The file being scanned MUST begin with:

```text
# configuration file
```

To confirm that the configuration dump was picked up correctly, pass `--debug` to the `gixy` CLI and you'll see the message "Switched to parse nginx configuration dump". See [Debug Mode](https://gixy.io/usage/#debug-mode) for more.
