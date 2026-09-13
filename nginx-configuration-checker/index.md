# NGINX Config Checker: gixy-next vs nginx -t

When people say "NGINX configuration checker", they usually mean one of two things:

- `nginx -t` for syntax validation, or
- A static analyzer like the actively maintained Gixy fork, Gixy-Next, which focuses on security and best practices and actual runtime behavior.

This page explains how Gixy-Next complements `nginx -t`, and how to use it as your NGINX configuration checker in day to day work.

## What `nginx -t` actually checks

The built-in `nginx -t` command is great at catching low level problems:

- Syntax errors in configuration files
- Missing or unreadable include files
- Some simple directive level issues (unknown directives, bad arguments, etc.)

If `nginx -t` passes, it means:

- NGINX can start or reload successfully
- Your configuration is syntactically valid

It does **not** mean:

- Your configuration is secure
- You are following best practices
- There are no logic or security bugs in complex `location`, `map`, `proxy_pass`, or `if` blocks

It is a linter for syntax, not a security review.

## What Gixy-Next adds as a configuration checker

Gixy-Next is an **NGINX configuration security checker**. It parses your `nginx.conf` (and all included files) and runs a set of security and correctness checks on top of simple syntax validation.

Gixy-Next can detect issues such as:

- `ssrf` - server side request forgery risks in `proxy_pass` and similar directives
- `http_splitting` - HTTP response splitting via unsafe variables in headers
- `host_spoofing` - insecure use of the `Host` header
- `alias_traversal` - path traversal through misconfigured `alias`
- `add_header_content_type` - setting `Content-Type` via `add_header`
- `version_disclosure` - leaking NGINX version via `server_tokens`
- `unanchored_regex` - regular expressions without anchors in security sensitive places.
- `stale_dns_cache` - outdated or incorrect hosts/ip addresses being used for upstream proxying due to DNS caching.

In other words:

- `nginx -t` answers: *Can NGINX load this config?*
- Gixy-Next answers: *Is this config safe and sane?*

## Quick start as a configuration checker

If you have Gixy-Next installed, a basic check looks like this:​

```
# Check the default NGINX config (usually /etc/nginx/nginx.conf)
gixy

# Or specify the path explicitly
gixy /etc/nginx/nginx.conf
```

If you want to scan the nginx config using Gixy-Next on a system other than that which is running NGINX, you can perform a live-configuration dump (see [nginx -T Live Configuration Dump](https://gixy.io/nginx-config-dump)), like so:

```
# Dump the whole nginx configuration to a single file
nginx -T > nginx.dump

# Scan the full configuration (all "include" files included) with Gixy-Next
gixy nginx.dump
```

To skip specific checks that you know are noisy for your environment:

```
# Skip the HTTP splitting check
gixy --skips http_splitting /etc/nginx/nginx.conf
```

To focus on more serious problems only (depending on how you wire severity flags in Gixy-Next):

```
# Example: only medium and high severity issues
gixy -ll /etc/nginx/nginx.conf
```

## Side by side: `nginx -t` vs Gixy-Next

| Tool       | Syntax validation | Includes / multi file configs | Security misconfig checks | Best practice checks | CI/CD friendly |
| ---------- | ----------------- | ----------------------------- | ------------------------- | -------------------- | -------------- |
| `nginx -t` | Yes               | Yes                           | No                        | No                   | Sort of        |
| Gixy-Next  | Parses config     | Yes                           | Yes                       | Yes (via plugins)    | Yes            |

They are complementary:

- Always run `nginx -t` before reloads to avoid broken configs.
- Run **Gixy-Next** as your NGINX configuration checker before changes hit production, to catch security and logic issues.

## Example: treating Gixy-Next as a gatekeeper

A simple manual workflow:

1. Edit your NGINX configuration.
1. Run Gixy-Next:

```
gixy /etc/nginx/nginx.conf
```

1. Fix any reported issues (especially `High` and `Medium` severity).
1. Run `nginx -t`.
1. Reload NGINX only after both steps succeed.

This way:

- Gixy-Next acts as your **NGINX configuration checker** and security auditor.
- `nginx -t` remains the last line of defense against syntax errors.

## When to use each tool

Use **`nginx -t`** when:

- You just edited a configuration file and want to be sure NGINX will start.
- You are troubleshooting a reload failure.

Use **Gixy-Next** when:

- You want to perform an **NGINX configuration security audit**.
- You are onboarding a new application or team and want to catch common misconfigurations.
- You are preparing for compliance (PCI DSS, etc) and need a repeatable NGINX security check.

Used together, they give you both correctness and security: one checks that NGINX can read your configuration, the other checks that attackers will not enjoy it.
