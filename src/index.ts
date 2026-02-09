#!/usr/bin/env node

import * as https from "https";
import * as http from "http";

// ANSI colors
const c = {
  reset: "\x1b[0m",
  bold: "\x1b[1m",
  dim: "\x1b[2m",
  red: "\x1b[31m",
  green: "\x1b[32m",
  yellow: "\x1b[33m",
  blue: "\x1b[34m",
  magenta: "\x1b[35m",
  cyan: "\x1b[36m",
  white: "\x1b[37m",
  bgRed: "\x1b[41m",
  bgGreen: "\x1b[42m",
  bgYellow: "\x1b[43m",
};

interface SourceCatalog {
  scripts: Set<string>;
  styles: Set<string>;
  images: Set<string>;
  fonts: Set<string>;
  frames: Set<string>;
  connects: Set<string>;
  media: Set<string>;
  objects: Set<string>;
  hasInlineScript: boolean;
  hasInlineStyle: boolean;
  hasEvalUsage: boolean;
}

interface CSPDirectives {
  [key: string]: string[];
}

interface AuditFinding {
  directive: string;
  issue: string;
  severity: "info" | "warning" | "critical";
  recommendation: string;
}

const HELP = `
${c.bold}${c.cyan}csp-gen${c.reset} - Generate Content-Security-Policy headers from page analysis

${c.bold}USAGE${c.reset}
  ${c.green}npx @lxgicstudios/csp-gen${c.reset} <url> [options]
  ${c.green}npx @lxgicstudios/csp-gen${c.reset} https://example.com
  ${c.green}npx @lxgicstudios/csp-gen${c.reset} https://example.com --output nginx

${c.bold}OPTIONS${c.reset}
  --help              Show this help message
  --json              Output results as JSON
  --strict            Use Content-Security-Policy-Report-Only header
  --output <format>   Output format: nginx | express | meta | raw (default: raw)
  --audit             Audit existing CSP header instead of generating
  --include-report    Add report-uri directive
  --report-to <url>   Set report-uri endpoint
  --no-unsafe         Don't allow unsafe-inline or unsafe-eval
  --verbose           Show detected sources

${c.bold}EXAMPLES${c.reset}
  ${c.dim}# Generate CSP from page analysis${c.reset}
  npx @lxgicstudios/csp-gen https://example.com

  ${c.dim}# Output as nginx config${c.reset}
  npx @lxgicstudios/csp-gen https://example.com --output nginx

  ${c.dim}# Strict mode (report-only)${c.reset}
  npx @lxgicstudios/csp-gen https://example.com --strict

  ${c.dim}# Audit existing CSP${c.reset}
  npx @lxgicstudios/csp-gen https://example.com --audit

  ${c.dim}# Express middleware format${c.reset}
  npx @lxgicstudios/csp-gen https://example.com --output express
`;

function parseArgs(argv: string[]) {
  const args = {
    help: false,
    json: false,
    strict: false,
    output: "raw" as "nginx" | "express" | "meta" | "raw",
    audit: false,
    includeReport: false,
    reportTo: "",
    noUnsafe: false,
    verbose: false,
    url: "",
  };

  for (let i = 2; i < argv.length; i++) {
    const arg = argv[i];
    switch (arg) {
      case "--help":
      case "-h":
        args.help = true;
        break;
      case "--json":
        args.json = true;
        break;
      case "--strict":
        args.strict = true;
        break;
      case "--output":
      case "-o":
        args.output = (argv[++i] || "raw") as any;
        break;
      case "--audit":
        args.audit = true;
        break;
      case "--include-report":
        args.includeReport = true;
        break;
      case "--report-to":
        args.reportTo = argv[++i] || "";
        args.includeReport = true;
        break;
      case "--no-unsafe":
        args.noUnsafe = true;
        break;
      case "--verbose":
      case "-v":
        args.verbose = true;
        break;
      default:
        if (!arg.startsWith("-") && !args.url) {
          args.url = arg;
        }
        break;
    }
  }

  return args;
}

function fetchPage(
  targetUrl: string,
  maxRedirects: number = 5
): Promise<{ body: string; headers: http.IncomingHttpHeaders; statusCode: number; finalUrl: string }> {
  return new Promise((resolve, reject) => {
    const parsed = new URL(targetUrl);
    const client = parsed.protocol === "https:" ? https : http;

    client
      .get(
        targetUrl,
        {
          headers: {
            "User-Agent": "csp-gen/1.0 (https://github.com/lxgicstudios/csp-gen)",
            Accept: "text/html,application/xhtml+xml,*/*",
          },
          timeout: 15000,
        },
        (res) => {
          if (
            res.statusCode &&
            res.statusCode >= 300 &&
            res.statusCode < 400 &&
            res.headers.location &&
            maxRedirects > 0
          ) {
            const redirectUrl = new URL(res.headers.location, targetUrl).toString();
            fetchPage(redirectUrl, maxRedirects - 1).then(resolve).catch(reject);
            return;
          }

          let body = "";
          res.on("data", (chunk: Buffer) => (body += chunk.toString()));
          res.on("end", () => {
            resolve({
              body,
              headers: res.headers,
              statusCode: res.statusCode || 0,
              finalUrl: targetUrl,
            });
          });
        }
      )
      .on("error", reject);
  });
}

function extractOrigin(src: string, baseUrl: string): string | null {
  if (!src) return null;

  // Data URIs
  if (src.startsWith("data:")) return "'data:'";

  // Blob URIs
  if (src.startsWith("blob:")) return "'blob:'";

  // Protocol-relative
  if (src.startsWith("//")) {
    try {
      const parsed = new URL("https:" + src);
      return `${parsed.protocol}//${parsed.host}`;
    } catch {
      return null;
    }
  }

  // Absolute URL
  if (src.startsWith("http://") || src.startsWith("https://")) {
    try {
      const parsed = new URL(src);
      return `${parsed.protocol}//${parsed.host}`;
    } catch {
      return null;
    }
  }

  // Relative URL - same origin
  return "'self'";
}

function catalogSources(html: string, baseUrl: string): SourceCatalog {
  const catalog: SourceCatalog = {
    scripts: new Set<string>(),
    styles: new Set<string>(),
    images: new Set<string>(),
    fonts: new Set<string>(),
    frames: new Set<string>(),
    connects: new Set<string>(),
    media: new Set<string>(),
    objects: new Set<string>(),
    hasInlineScript: false,
    hasInlineStyle: false,
    hasEvalUsage: false,
  };

  // Script sources
  const scriptSrcRe = /<script[^>]+src=["']([^"']+)["']/gi;
  let match: RegExpExecArray | null;
  while ((match = scriptSrcRe.exec(html)) !== null) {
    const origin = extractOrigin(match[1], baseUrl);
    if (origin) catalog.scripts.add(origin);
  }

  // Inline scripts
  if (/<script(?:\s[^>]*)?>[\s\S]*?[^\s<][\s\S]*?<\/script>/i.test(html)) {
    catalog.hasInlineScript = true;
  }

  // Eval usage
  if (/\beval\s*\(/.test(html) || /new\s+Function\s*\(/.test(html)) {
    catalog.hasEvalUsage = true;
  }

  // Style sources (link rel="stylesheet")
  const styleSrcRe = /<link[^>]+rel=["']stylesheet["'][^>]+href=["']([^"']+)["']/gi;
  while ((match = styleSrcRe.exec(html)) !== null) {
    const origin = extractOrigin(match[1], baseUrl);
    if (origin) catalog.styles.add(origin);
  }

  // Also match href before rel
  const styleSrcRe2 = /<link[^>]+href=["']([^"']+)["'][^>]+rel=["']stylesheet["']/gi;
  while ((match = styleSrcRe2.exec(html)) !== null) {
    const origin = extractOrigin(match[1], baseUrl);
    if (origin) catalog.styles.add(origin);
  }

  // Inline styles
  if (/<style[\s>]/i.test(html) || /\bstyle=["']/i.test(html)) {
    catalog.hasInlineStyle = true;
  }

  // Image sources
  const imgSrcRe = /<img[^>]+src=["']([^"']+)["']/gi;
  while ((match = imgSrcRe.exec(html)) !== null) {
    const origin = extractOrigin(match[1], baseUrl);
    if (origin) catalog.images.add(origin);
  }

  // Srcset
  const srcsetRe = /srcset=["']([^"']+)["']/gi;
  while ((match = srcsetRe.exec(html)) !== null) {
    const entries = match[1].split(",");
    for (const entry of entries) {
      const src = entry.trim().split(/\s+/)[0];
      const origin = extractOrigin(src, baseUrl);
      if (origin) catalog.images.add(origin);
    }
  }

  // CSS background images (basic detection)
  const bgUrlRe = /url\(\s*["']?([^"')]+)["']?\s*\)/gi;
  while ((match = bgUrlRe.exec(html)) !== null) {
    const origin = extractOrigin(match[1], baseUrl);
    if (origin) catalog.images.add(origin);
  }

  // Font sources (preload)
  const fontRe = /<link[^>]+as=["']font["'][^>]+href=["']([^"']+)["']/gi;
  while ((match = fontRe.exec(html)) !== null) {
    const origin = extractOrigin(match[1], baseUrl);
    if (origin) catalog.fonts.add(origin);
  }

  // Google Fonts, etc.
  const fontCssRe = /fonts\.googleapis\.com|fonts\.gstatic\.com|use\.typekit\.net/g;
  while ((match = fontCssRe.exec(html)) !== null) {
    catalog.fonts.add(`https://${match[0]}`);
    catalog.styles.add(`https://${match[0]}`);
  }

  // Iframe sources
  const iframeSrcRe = /<iframe[^>]+src=["']([^"']+)["']/gi;
  while ((match = iframeSrcRe.exec(html)) !== null) {
    const origin = extractOrigin(match[1], baseUrl);
    if (origin) catalog.frames.add(origin);
  }

  // Video/audio
  const mediaSrcRe = /<(?:video|audio|source)[^>]+src=["']([^"']+)["']/gi;
  while ((match = mediaSrcRe.exec(html)) !== null) {
    const origin = extractOrigin(match[1], baseUrl);
    if (origin) catalog.media.add(origin);
  }

  // Object/embed
  const objectSrcRe = /<(?:object|embed)[^>]+(?:data|src)=["']([^"']+)["']/gi;
  while ((match = objectSrcRe.exec(html)) !== null) {
    const origin = extractOrigin(match[1], baseUrl);
    if (origin) catalog.objects.add(origin);
  }

  // Fetch/XHR targets (basic detection from inline scripts)
  const fetchRe = /(?:fetch|XMLHttpRequest|axios|\.get|\.post)\s*\(\s*["'`]([^"'`]+)["'`]/gi;
  while ((match = fetchRe.exec(html)) !== null) {
    const origin = extractOrigin(match[1], baseUrl);
    if (origin) catalog.connects.add(origin);
  }

  return catalog;
}

function buildCSP(catalog: SourceCatalog, noUnsafe: boolean): CSPDirectives {
  const directives: CSPDirectives = {};

  // default-src
  directives["default-src"] = ["'self'"];

  // script-src
  const scriptSources = ["'self'", ...catalog.scripts];
  if (catalog.hasInlineScript && !noUnsafe) {
    scriptSources.push("'unsafe-inline'");
  }
  if (catalog.hasEvalUsage && !noUnsafe) {
    scriptSources.push("'unsafe-eval'");
  }
  directives["script-src"] = [...new Set(scriptSources)];

  // style-src
  const styleSources = ["'self'", ...catalog.styles];
  if (catalog.hasInlineStyle && !noUnsafe) {
    styleSources.push("'unsafe-inline'");
  }
  directives["style-src"] = [...new Set(styleSources)];

  // img-src
  const imgSources = ["'self'", ...catalog.images];
  imgSources.push("data:"); // Common for images
  directives["img-src"] = [...new Set(imgSources)];

  // font-src
  if (catalog.fonts.size > 0) {
    directives["font-src"] = ["'self'", ...catalog.fonts];
  } else {
    directives["font-src"] = ["'self'"];
  }

  // connect-src
  if (catalog.connects.size > 0) {
    directives["connect-src"] = ["'self'", ...catalog.connects];
  } else {
    directives["connect-src"] = ["'self'"];
  }

  // frame-src
  if (catalog.frames.size > 0) {
    directives["frame-src"] = [...catalog.frames];
  } else {
    directives["frame-src"] = ["'none'"];
  }

  // media-src
  if (catalog.media.size > 0) {
    directives["media-src"] = ["'self'", ...catalog.media];
  }

  // object-src
  if (catalog.objects.size > 0) {
    directives["object-src"] = [...catalog.objects];
  } else {
    directives["object-src"] = ["'none'"];
  }

  // base-uri
  directives["base-uri"] = ["'self'"];

  // form-action
  directives["form-action"] = ["'self'"];

  // frame-ancestors
  directives["frame-ancestors"] = ["'none'"];

  return directives;
}

function directivesToString(directives: CSPDirectives): string {
  return Object.entries(directives)
    .map(([key, values]) => `${key} ${values.join(" ")}`)
    .join("; ");
}

function formatOutput(
  cspString: string,
  format: string,
  strict: boolean
): string {
  const headerName = strict
    ? "Content-Security-Policy-Report-Only"
    : "Content-Security-Policy";

  switch (format) {
    case "nginx":
      return `add_header ${headerName} "${cspString}" always;`;

    case "express":
      return `app.use((req, res, next) => {\n  res.setHeader('${headerName}', '${cspString}');\n  next();\n});`;

    case "meta":
      if (strict) {
        return `<!-- Note: Report-Only can't be set via meta tag, use HTTP header instead -->\n<meta http-equiv="Content-Security-Policy" content="${cspString}">`;
      }
      return `<meta http-equiv="Content-Security-Policy" content="${cspString}">`;

    case "raw":
    default:
      return `${headerName}: ${cspString}`;
  }
}

function auditCSP(cspHeader: string): AuditFinding[] {
  const findings: AuditFinding[] = [];

  if (!cspHeader) {
    findings.push({
      directive: "(missing)",
      issue: "No Content-Security-Policy header found",
      severity: "critical",
      recommendation: "Add a CSP header. Use this tool to generate one.",
    });
    return findings;
  }

  const directives: Record<string, string> = {};
  for (const part of cspHeader.split(";")) {
    const trimmed = part.trim();
    const spaceIdx = trimmed.indexOf(" ");
    if (spaceIdx > 0) {
      directives[trimmed.slice(0, spaceIdx)] = trimmed.slice(spaceIdx + 1);
    } else if (trimmed) {
      directives[trimmed] = "";
    }
  }

  // Check for missing directives
  const importantDirectives = [
    "default-src",
    "script-src",
    "style-src",
    "object-src",
    "base-uri",
    "frame-ancestors",
  ];

  for (const dir of importantDirectives) {
    if (!directives[dir] && !directives["default-src"]) {
      findings.push({
        directive: dir,
        issue: `Missing ${dir} directive`,
        severity: "warning",
        recommendation: `Add ${dir} directive to your CSP`,
      });
    }
  }

  // Check for unsafe directives
  for (const [dir, value] of Object.entries(directives)) {
    if (value.includes("'unsafe-inline'")) {
      findings.push({
        directive: dir,
        issue: `'unsafe-inline' allows inline code execution`,
        severity: dir === "script-src" ? "critical" : "warning",
        recommendation: `Use nonce-based or hash-based CSP instead of 'unsafe-inline' in ${dir}`,
      });
    }

    if (value.includes("'unsafe-eval'")) {
      findings.push({
        directive: dir,
        issue: `'unsafe-eval' allows eval() and similar dynamic code execution`,
        severity: "critical",
        recommendation: `Remove 'unsafe-eval' from ${dir} and refactor code to avoid eval()`,
      });
    }

    if (value.includes("*") && !value.includes("*.")) {
      findings.push({
        directive: dir,
        issue: `Wildcard (*) allows any source`,
        severity: "critical",
        recommendation: `Replace wildcard with specific origins in ${dir}`,
      });
    }

    if (value.includes("http:")) {
      findings.push({
        directive: dir,
        issue: `HTTP sources allowed (insecure)`,
        severity: "warning",
        recommendation: `Use HTTPS-only sources in ${dir}`,
      });
    }

    if (value.includes("data:") && (dir === "script-src" || dir === "default-src")) {
      findings.push({
        directive: dir,
        issue: `data: URIs in ${dir} can be used for XSS`,
        severity: "critical",
        recommendation: `Remove data: from ${dir}`,
      });
    }
  }

  // Check object-src
  if (directives["object-src"] && directives["object-src"] !== "'none'") {
    findings.push({
      directive: "object-src",
      issue: "object-src should be 'none' to prevent plugin-based attacks",
      severity: "warning",
      recommendation: "Set object-src to 'none'",
    });
  }

  // Check frame-ancestors
  if (!directives["frame-ancestors"]) {
    findings.push({
      directive: "frame-ancestors",
      issue: "Missing frame-ancestors (clickjacking protection)",
      severity: "warning",
      recommendation: "Add frame-ancestors 'none' or 'self'",
    });
  }

  if (findings.length === 0) {
    findings.push({
      directive: "(all)",
      issue: "CSP looks well-configured!",
      severity: "info",
      recommendation: "Consider adding report-uri for monitoring violations",
    });
  }

  return findings;
}

function getSeverityColor(severity: string): string {
  switch (severity) {
    case "critical":
      return c.red;
    case "warning":
      return c.yellow;
    case "info":
      return c.green;
    default:
      return c.reset;
  }
}

function getSeverityEmoji(severity: string): string {
  switch (severity) {
    case "critical":
      return "🔴";
    case "warning":
      return "⚠️";
    case "info":
      return "✅";
    default:
      return "?";
  }
}

async function main() {
  const args = parseArgs(process.argv);

  if (args.help) {
    console.log(HELP);
    process.exit(0);
  }

  if (!args.url) {
    console.error(`${c.red}Error:${c.reset} Please provide a URL.`);
    console.error(`${c.dim}Usage: npx @lxgicstudios/csp-gen <url>${c.reset}`);
    process.exit(1);
  }

  let targetUrl = args.url;
  if (!targetUrl.startsWith("http://") && !targetUrl.startsWith("https://")) {
    targetUrl = "https://" + targetUrl;
  }

  if (!args.json) {
    console.log(
      `\n${c.bold}${c.cyan}csp-gen${c.reset} ${c.dim}${args.audit ? "Auditing" : "Analyzing"} ${targetUrl}...${c.reset}\n`
    );
  }

  let page;
  try {
    page = await fetchPage(targetUrl);
  } catch (err: any) {
    console.error(`${c.red}Error:${c.reset} ${err.message}`);
    process.exit(1);
  }

  if (args.audit) {
    // Audit existing CSP
    const cspHeader =
      (page.headers["content-security-policy"] as string) ||
      (page.headers["content-security-policy-report-only"] as string) ||
      "";

    const findings = auditCSP(cspHeader);

    if (args.json) {
      console.log(
        JSON.stringify(
          {
            url: targetUrl,
            existingCSP: cspHeader || null,
            findings,
          },
          null,
          2
        )
      );
    } else {
      if (cspHeader) {
        console.log(`  ${c.dim}Existing CSP:${c.reset}`);
        console.log(`  ${c.cyan}${cspHeader.substring(0, 200)}${cspHeader.length > 200 ? "..." : ""}${c.reset}\n`);
      }

      for (const finding of findings) {
        const sevColor = getSeverityColor(finding.severity);
        const emoji = getSeverityEmoji(finding.severity);
        console.log(
          `  ${emoji} ${sevColor}${c.bold}[${finding.directive}]${c.reset} ${finding.issue}`
        );
        console.log(`     ${c.cyan}>${c.reset} ${finding.recommendation}`);
      }

      const critCount = findings.filter((f) => f.severity === "critical").length;
      const warnCount = findings.filter((f) => f.severity === "warning").length;
      console.log(`\n${c.bold}${"─".repeat(50)}${c.reset}`);
      console.log(
        `${c.bold}Audit Summary${c.reset}: ${c.red}${critCount} critical${c.reset}, ${c.yellow}${warnCount} warnings${c.reset}\n`
      );
    }
    return;
  }

  // Generate CSP
  const catalog = catalogSources(page.body, targetUrl);

  if (args.verbose && !args.json) {
    console.log(`  ${c.bold}Detected Sources${c.reset}`);
    const printSet = (label: string, set: Set<string>) => {
      if (set.size > 0) {
        console.log(`    ${c.cyan}${label}:${c.reset} ${[...set].join(", ")}`);
      }
    };
    printSet("Scripts", catalog.scripts);
    printSet("Styles", catalog.styles);
    printSet("Images", catalog.images);
    printSet("Fonts", catalog.fonts);
    printSet("Frames", catalog.frames);
    printSet("Connects", catalog.connects);
    printSet("Media", catalog.media);
    console.log(
      `    ${c.dim}Inline scripts: ${catalog.hasInlineScript}  Inline styles: ${catalog.hasInlineStyle}  eval(): ${catalog.hasEvalUsage}${c.reset}`
    );
    console.log();
  }

  const directives = buildCSP(catalog, args.noUnsafe);

  if (args.includeReport && args.reportTo) {
    directives["report-uri"] = [args.reportTo];
  }

  const cspString = directivesToString(directives);
  const formatted = formatOutput(cspString, args.output, args.strict);

  if (args.json) {
    console.log(
      JSON.stringify(
        {
          url: targetUrl,
          sources: {
            scripts: [...catalog.scripts],
            styles: [...catalog.styles],
            images: [...catalog.images],
            fonts: [...catalog.fonts],
            frames: [...catalog.frames],
            connects: [...catalog.connects],
            hasInlineScript: catalog.hasInlineScript,
            hasInlineStyle: catalog.hasInlineStyle,
            hasEvalUsage: catalog.hasEvalUsage,
          },
          directives,
          csp: cspString,
          formatted,
        },
        null,
        2
      )
    );
  } else {
    console.log(`  ${c.bold}Generated CSP${c.reset} (${args.output} format):\n`);
    console.log(`${c.green}${formatted}${c.reset}\n`);

    // Warnings
    if (catalog.hasInlineScript && !args.noUnsafe) {
      console.log(
        `  ${c.yellow}!${c.reset} Inline scripts detected. 'unsafe-inline' was added. Consider using nonces instead.`
      );
    }
    if (catalog.hasInlineStyle && !args.noUnsafe) {
      console.log(
        `  ${c.yellow}!${c.reset} Inline styles detected. 'unsafe-inline' was added to style-src.`
      );
    }
    if (catalog.hasEvalUsage && !args.noUnsafe) {
      console.log(
        `  ${c.yellow}!${c.reset} eval() usage detected. 'unsafe-eval' was added. Try to refactor.`
      );
    }
    if (args.noUnsafe && (catalog.hasInlineScript || catalog.hasInlineStyle)) {
      console.log(
        `  ${c.cyan}>${c.reset} --no-unsafe: Inline scripts/styles won't be allowed. Use nonces or hashes.`
      );
    }
    console.log();
  }
}

main().catch((err) => {
  console.error(`${c.red}Error:${c.reset}`, err.message);
  process.exit(1);
});
