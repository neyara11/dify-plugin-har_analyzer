# HAR Analyzer

Dify plugin for analyzing HTTP Archive (HAR) files — network traces exported from browser DevTools. Give it a `.har` file and get a structured web performance and error report: timing metrics, resource weight, failed requests, and suspicious responses, ready to be fed into an LLM for optimization recommendations.

Source code: https://github.com/neyara11/dify-plugin-har_analyzer

## What it analyzes

A HAR file records every HTTP request a page makes: URLs, headers, timings, status codes, and response bodies. The plugin parses this trace and produces:

**Performance metrics**
- TTFB (time to first byte) and approximate FCP (first contentful paint)
- Total load time and number of loaded resources
- Per-request timing breakdown (DNS, connect, SSL, send, wait, receive)

**Resource breakdown by type**
- HTML, CSS, JavaScript, images, audio, video, JSON, other
- Size and load time per type (compression-aware: compressed and decompressed sizes are handled correctly)

**Errors and diagnostics**
- HTTP 4xx/5xx responses
- Aborted, blocked, or CORS-failed requests (status 0)
- Application-level errors hidden behind HTTP 200/3xx — JSON payloads with `error`/`exception`/`success: false` fields and text bodies containing stack traces or "Internal Server Error"
- For every error: request/response headers and a response body preview

**Warnings and insights**
- Duplicate requests (same URL fetched repeatedly)
- Top domains by request count
- Top slowest requests
- Cache and compression status per request (`Cache-Control`, `ETag`, `Last-Modified`, `Content-Encoding`, 304/cached)
- Browser name, version, hostname, and User-Agent of the captured session

## How it works

1. Record the session: open browser DevTools → **Network** tab → reproduce the issue → **Export HAR** (Chrome/Edge: download arrow; Firefox: "Save All As HAR").
2. In Dify, run the **Analyze HAR File** tool and upload the `.har` file.
3. Pick an output format and pass the result to an LLM node for analysis, or use it directly in a workflow.

All parsing happens inside your Dify deployment. See [PRIVACY.md](PRIVACY.md) for data handling details.

## Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `har_file` | file | Yes | The `.har` file exported from browser DevTools |
| `output_format` | select | No | `summary` (default), `json`, or `errors_only` |

## Output formats

### `summary` — human-readable report

```
======================================================================
📊 HAR ANALYSIS REPORT
======================================================================

👤 BROWSER & ENVIRONMENT INFO
  🌐 Browser:        Chrome 120.0.0.0
  🖥️  Hostname:       example.com
  📄 Pages Count:    1
  🔤 User-Agent:     Mozilla/5.0 ...

📈 SUMMARY STATISTICS
  📊 Total Requests: 45
  📦 Total Size:     1.50 MB (1,572,864 bytes)
  🌐 Domains:        8
  ❌ Errors:         2
  ⚠️  Warnings:       1
  🔄 Duplicates:     3

⚡ PERFORMANCE METRICS
  ⏱️  TTFB (Time to First Byte):  120 ms
  🎨 FCP (First Contentful Paint): 250 ms
  ⏰ Total Load Time:              1,500 ms
  📦 DOM Resources:                45

📋 STATUS CODES ...
📦 RESOURCE TYPES BREAKDOWN ...
🌐 TOP DOMAINS ...
🔄 DUPLICATE REQUESTS ...
❌ ERRORS (2) ...
🐌 TOP 15 SLOWEST REQUESTS ...
```

### `json` — full structured data for workflows

```json
{
  "analysis_date": "2026-02-16T12:00:00",
  "user_data": {"browser_name": "Chrome", "hostname": "example.com"},
  "summary": {"total_requests": 45, "total_size_bytes": 1572864, "errors_count": 2},
  "performance": {"ttfb": 120, "fcp": 250, "total_time": 1500},
  "status_codes": {"200": 42, "404": 2, "0": 1},
  "resource_types": {"html": {}, "css": {}, "javascript": {}, "images": {}},
  "domains": {"example.com": 30},
  "errors": [],
  "warnings": [],
  "duplicates": {},
  "top_slowest": []
}
```

Large results are truncated with a note when they exceed 50 KB; use `summary` for a complete overview.

### `errors_only` — quick diagnostics

Only errors, warnings, and duplicates, each with full request/response headers and a response body preview. Useful for failed-request triage.

## Example workflow

```
1. User uploads a .har file captured in DevTools
2. Tool: HAR Analyzer (output_format: json)
3. LLM node interprets the metrics and error list
4. Answer with prioritized optimization and fix recommendations
```

Typical use cases: website performance audits, regression analysis after a release, diagnosing failed or slow API calls, and feeding network evidence into an incident review.

## Installation

**From the Marketplace** (once published): search for "HAR Analyzer" in Dify → Plugins → Marketplace and click **Install**.

**Manual upload**: Dify → **Settings → Plugins → Install Plugin → Upload**, then select `har_analyzer-<version>.difypkg` from the [releases](https://github.com/neyara11/dify-plugin-har_analyzer) of the source repository.

No API keys, credentials, or external service accounts are required.

## Development

```
har_analyzer/
├── manifest.yaml           # Plugin metadata
├── main.py                 # Entry point
├── requirements.txt        # Pinned dependencies (dify-plugin, haralyzer, requests)
├── PRIVACY.md              # Privacy policy
├── _assets/icon.svg        # Plugin icon
├── provider/               # Tool provider
├── tools/har_analyze.*     # HAR analysis tool
└── readme/                 # Translations
```

Build the package with `python build_package.py` (or `dify plugin package . -o har_analyzer-<version>.difypkg`).

## License

Apache 2.0
