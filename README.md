# csp-gen

[![npm version](https://img.shields.io/npm/v/@lxgicstudios/csp-gen.svg)](https://www.npmjs.com/package/@lxgicstudios/csp-gen)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)

Crawl any URL, catalog all script, style, image, and font sources, then generate a production-ready Content-Security-Policy header. Outputs for nginx, Express, or HTML meta tag. Can also audit an existing CSP for weaknesses.

## Install

```bash
# Run directly with npx
npx @lxgicstudios/csp-gen https://example.com

# Or install globally
npm install -g @lxgicstudios/csp-gen
```

## Usage

```bash
# Generate CSP from page analysis
csp-gen https://example.com

# Output as nginx config
csp-gen https://example.com --output nginx

# Express middleware format
csp-gen https://example.com --output express

# HTML meta tag
csp-gen https://example.com --output meta

# Report-only mode (test without breaking anything)
csp-gen https://example.com --strict

# Audit existing CSP on a site
csp-gen https://example.com --audit

# No unsafe-inline or unsafe-eval
csp-gen https://example.com --no-unsafe

# Verbose mode (shows all detected sources)
csp-gen https://example.com --verbose
```

## Features

- **Zero dependencies** - uses only built-in Node.js modules (https/http)
- Crawls a page and catalogs all external resource sources
- Detects scripts, stylesheets, images, fonts, iframes, media, and API endpoints
- Generates a complete CSP with all standard directives
- Outputs in nginx, Express middleware, HTML meta tag, or raw header format
- `--strict` mode generates `Content-Security-Policy-Report-Only` header
- `--audit` mode checks an existing CSP for common security issues
- `--no-unsafe` mode blocks `unsafe-inline` and `unsafe-eval`
- Detects inline scripts/styles and eval() usage

## Options

| Option | Description |
|--------|-------------|
| `--help` | Show help message |
| `--json` | Output results as JSON |
| `--strict` | Use Content-Security-Policy-Report-Only header |
| `--output <format>` | Output format: nginx, express, meta, raw (default: raw) |
| `--audit` | Audit existing CSP header instead of generating |
| `--include-report` | Add report-uri directive |
| `--report-to <url>` | Set the report-uri endpoint |
| `--no-unsafe` | Don't allow unsafe-inline or unsafe-eval |
| `--verbose` | Show all detected sources |

## Output Formats

**Raw (default):**
```
Content-Security-Policy: default-src 'self'; script-src 'self' ...
```

**nginx:**
```nginx
add_header Content-Security-Policy "default-src 'self'; ..." always;
```

**Express:**
```javascript
app.use((req, res, next) => {
  res.setHeader('Content-Security-Policy', '...');
  next();
});
```

**Meta tag:**
```html
<meta http-equiv="Content-Security-Policy" content="default-src 'self'; ...">
```

## Audit Mode

Run `--audit` against any URL to check its existing CSP for issues:

- Missing critical directives (default-src, script-src, object-src)
- Usage of `unsafe-inline` and `unsafe-eval`
- Wildcard sources (`*`)
- HTTP (non-encrypted) sources
- Missing frame-ancestors (clickjacking protection)
- data: URIs in dangerous directives

## License

MIT - [LXGIC Studios](https://github.com/lxgicstudios)
