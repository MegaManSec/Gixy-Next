# [error_log_off] `error_log` set to off

## What this check looks for

This plugin flags `error_log off;`.

## Why this is a problem

Unlike `access_log`, the `error_log` directive does not support an `off` parameter. When you write `error_log off;`, NGINX interprets `off` as a path and creates a log file named `off` in the default config directory (often `/etc/nginx`).

That is confusing at best, and at worst it can fill a filesystem you did not expect to be writing to.

## Bad configuration

```
error_log off;
```

This does not turn logging off; it just changes the log destination to a file named `off`.

## Better configuration

In general, keep error logging enabled. If you have a very specific reason to suppress it, redirect to `/dev/null` and set a strict level:

```
# Disable error logging as much as possible
error_log /dev/null emerg;
```

## Additional notes

NGINX still needs to validate the config during startup/reload. Errors during that phase can be written to the default error log path until the config is fully read. If you need to change the startup log path, use the `-e` / `--error-log-path` option when launching NGINX.
