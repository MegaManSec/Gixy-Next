# Custom Variables & Drop-ins

`gixy` (Gixy-Next's CLI) tries to resolve variables as it analyzes your NGINX config. When it sees a variable it does not recognize, it will warn; not because your config is wrong, but because the scanner cannot safely tell what might flow into that value.

This comes up a lot with third-party modules and bespoke setups (for example variables like `$brotli_ratio`), or when your organization injects variables through templates.

Variable drop-ins are the solution to this: you provide a small directory of definitions, and `gixy` learns what those variables are supposed to look like.

Note: If you never see warnings about unknown variables, you probably don't need to use these.

## Enable drop-ins

Point `gixy` at one or more directories containing variable definition files.

CLI:

```
# Read all the *.cfg and *.conf files in /etc/gixy/vars,~/.config/gixy/vars
gixy --vars-dirs /etc/gixy/vars,~/.config/gixy/vars
```

Config file:

```
[gixy]
vars-dirs = /etc/gixy/vars,~/.config/gixy/vars
```

`gixy` will read all files ending in `.cfg` or `.conf` inside those directories.

## File format

Each non-empty, non-comment line defines one variable:

```
name value
```

Variable names must be written without the leading `$` (for example `brotli_ratio` matches `$brotli_ratio` in your NGINX config).

A few value styles are supported:

- Quoted literals, treated as literal, fixed values: `'...'` or `"..."`.
- Regex patterns, treated as regular expressions describing what the value is allowed to contain: `r'...'` or `r"..."`.
- `none` or `null` (case-insensitive), marking the variable as "non user-controlled" for the purpose of analysis.

Also:

- Blank lines are ignored
- Lines starting with `#` or `;` are ignored
- You may use `name value`, `name = value`, or `name: value`
- A trailing comma after the value is accepted (handy if you are copy/pasting)

### Examples

```
# /etc/gixy/vars/nginx-module-brotli.cfg
brotli_ratio none

# /etc/gixy/vars/nginx-module-foo.cfg
foo_host "example.com"
foo_uri  r'/[^\s]*',
```

## Prefix variables

You can define variable prefixes by ending the name with an underscore (`_`), similar to NGINX built-ins. For example, defining `http_` will match variables like `$http_user_agent`, `$http_x_forwarded_for`, and so on.

```
# Treat any $http_* variable as present
http_ r'.+'
```
