# [resolver_external] Using external DNS nameservers

## What this check looks for

This plugin warns when the `resolver` directive points to public IPs (for example 1.1.1.1 or 8.8.8.8) instead of a trusted local resolver.

## Why this is a problem

When NGINX uses DNS at request time, it normally caches results. If an attacker can influence DNS responses, they can poison the cache and redirect traffic to an attacker-controlled host. Using public resolvers directly increases the number of hops and parties involved, which increases the chances of getting a bad answer.

Various vulnerabilities have been [discovered](https://web.archive.org/web/20250317201620/https://blog.zorinaq.com/nginx-resolver-vulns/) in Nginx's dns resolver, with some of them still unfixed.

## Bad configuration

```
# Public resolvers
resolver 1.1.1.1 8.8.8.8;
```

## Better configuration

Use a local resolver on loopback that you control (dnsmasq, unbound, systemd-resolved, etc.):

```
resolver 127.0.0.1 [::1] valid=10s;
resolver_timeout 5s;
```
