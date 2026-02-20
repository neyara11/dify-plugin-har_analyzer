#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
HAR Analyzer Tool for Dify Plugin
Расширенный анализатор HAR-файлов с детальной информацией
"""

from collections.abc import Generator
from typing import Any, Optional
import json
import re
import base64
from datetime import datetime

from dify_plugin import Tool
from dify_plugin.entities.tool import ToolInvokeMessage
from dify_plugin.file.file import File

try:
    from haralyzer import HarParser, HarPage
except ImportError:
    HarParser = None
    HarPage = None


def format_bytes(size: int) -> str:
    """Format bytes to human readable format"""
    if size == 0:
        return "0 B"
    for unit in ['B', 'KB', 'MB', 'GB']:
        if abs(size) < 1024.0:
            return f"{size:.2f} {unit}"
        size /= 1024.0
    return f"{size:.2f} TB"


def headers_to_dict(headers) -> dict:
    """Convert HAR headers list to dict"""
    if isinstance(headers, dict):
        return headers
    if isinstance(headers, list):
        return {h['name']: h['value'] for h in headers if 'name' in h and 'value' in h}
    return {}


def get_status_emoji(status: int) -> str:
    """Get emoji marker for status code"""
    if status == 0:
        return "🚫"
    elif 200 <= status < 300:
        return "✅"
    elif 300 <= status < 400:
        return "🔄"
    elif 400 <= status < 500:
        return "❌"
    elif 500 <= status < 600:
        return "💥"
    return "❓"


class HarAnalyzeTool(Tool):
    """HAR Analyzer Tool for Dify with detailed analysis"""

    def _invoke(
        self, tool_parameters: dict
    ) -> Generator[ToolInvokeMessage, None, None]:
        """Main invoke method"""
        
        if HarParser is None:
            yield self.create_text_message(
                "Error: 'haralyzer' library not installed. Add 'haralyzer' to requirements.txt"
            )
            return
        
        # Get file from parameters
        har_file = tool_parameters.get("har_file")
        output_format = tool_parameters.get("output_format", "summary")
        
        if not har_file:
            yield self.create_text_message("Error: No HAR file provided")
            return
        
        try:
            # Handle different file input formats
            if isinstance(har_file, File):
                # Dify File object - read content directly from blob
                try:
                    file_bytes = har_file.blob
                    if file_bytes is None:
                        yield self.create_text_message("Error: File blob is empty")
                        return
                    file_content = file_bytes.decode('utf-8')
                except Exception as e:
                    yield self.create_text_message(f"Error reading file: {str(e)}")
                    return
            elif isinstance(har_file, dict):
                # File object from Dify
                if 'content' in har_file:
                    # Base64 encoded content
                    file_content = base64.b64decode(har_file['content']).decode('utf-8')
                elif 'url' in har_file:
                    # File URL - read from session
                    file_content = self._read_file_from_url(har_file['url'])
                else:
                    yield self.create_text_message("Error: Invalid file format")
                    return
            elif isinstance(har_file, str):
                # Direct string content
                file_content = har_file
            else:
                yield self.create_text_message(f"Error: Unexpected file type: {type(har_file)}")
                return
            
            if not file_content or not file_content.strip():
                yield self.create_text_message("Error: HAR file is empty")
                return
            
            # Parse HAR JSON
            har_data = json.loads(file_content)
            parser = HarParser(har_data)
            
        except json.JSONDecodeError as e:
            yield self.create_text_message(f"Error parsing JSON: {str(e)}")
            return
        except Exception as e:
            yield self.create_text_message(f"Error reading HAR file: {str(e)}")
            return
        
        try:
            result = self._analyze_har_full(parser, har_data)
            
            if output_format == "json":
                # Output JSON as formatted text to avoid Dify JSON structure issues
                json_text = json.dumps(result, indent=2, ensure_ascii=False, default=str)
                # Limit size for large results
                if len(json_text) > 50000:
                    # Truncate large JSON
                    truncated = {
                        'summary': result['summary'],
                        'performance': result['performance'],
                        'user_data': result['user_data'],
                        'status_codes': result['status_codes'],
                        'resource_types': result['resource_types'],
                        'domains': result['domains'],
                        'errors_sample': result['errors'][:20] if result['errors'] else [],
                        'warnings_sample': result['warnings'][:20] if result['warnings'] else [],
                        'note': 'JSON truncated due to size. Use "summary" format for complete information.'
                    }
                    json_text = json.dumps(truncated, indent=2, ensure_ascii=False, default=str)
                yield self.create_text_message(f"```json\n{json_text}\n```")
            elif output_format == "errors_only":
                errors_text = self._format_errors_only(result)
                yield self.create_text_message(errors_text)
            else:
                summary = self._format_detailed_summary(result)
                yield self.create_text_message(summary)
                
        except Exception as e:
            yield self.create_text_message(f"Error analyzing HAR: {str(e)}")

    def _read_file_from_url(self, url: str) -> str:
        """Read file content from URL"""
        import urllib.request
        try:
            req = urllib.request.Request(url)
            with urllib.request.urlopen(req, timeout=30) as response:
                return response.read().decode('utf-8')
        except Exception as e:
            raise Exception(f"Failed to fetch file: {str(e)}")
    
    def _get_entry_size(self, entry: dict) -> int:
        """Get correct entry size handling compression"""
        response = entry.get("response", {})
        
        # Try bodySize (may be -1 for compressed responses)
        body_size = response.get("bodySize", 0)
        if body_size is not None and body_size >= 0:
            return body_size
        
        # Use content.size (real size after decompression)
        content = response.get("content", {})
        content_size = content.get("size", 0)
        if content_size is not None and content_size >= 0:
            return content_size
        
        # Fallback: look for Content-Length in headers
        headers = headers_to_dict(response.get("headers", []))
        content_length = headers.get('Content-Length') or headers.get('content-length')
        if content_length:
            try:
                return int(content_length)
            except ValueError:
                pass
        
        return 0
    
    def _get_timings(self, entry: dict) -> dict:
        """Get detailed request timings"""
        timings = entry.get("timings", {})
        return {
            'blocked': timings.get('blocked', 0) or 0,
            'dns': timings.get('dns', 0) or 0,
            'connect': timings.get('connect', 0) or 0,
            'ssl': timings.get('ssl', 0) or 0,
            'send': timings.get('send', 0) or 0,
            'wait': timings.get('wait', 0) or 0,
            'receive': timings.get('receive', 0) or 0,
        }
    
    def _analyze_caching(self, entry: dict) -> dict:
        """Analyze caching and compression"""
        request = entry.get("request", {})
        response = entry.get("response", {})
        
        req_headers = headers_to_dict(request.get("headers", []))
        resp_headers = headers_to_dict(response.get("headers", []))
        
        status = response.get("status", 0)
        
        return {
            'cache_control': resp_headers.get('Cache-Control') or resp_headers.get('cache-control', ''),
            'expires': resp_headers.get('Expires') or resp_headers.get('expires', ''),
            'etag': resp_headers.get('ETag') or resp_headers.get('etag', ''),
            'last_modified': resp_headers.get('Last-Modified') or resp_headers.get('last-modified', ''),
            'content_encoding': resp_headers.get('Content-Encoding') or resp_headers.get('content-encoding', ''),
            'cached': status == 304 or 'from disk cache' in str(response.get("headers", [])).lower(),
        }
    
    def _extract_browser_info(self, har_data: dict) -> dict:
        """Extract browser and user environment info"""
        data = {
            'browser_name': 'N/A',
            'browser_version': 'N/A',
            'hostname': 'N/A',
            'user_agent': 'N/A',
            'pages_count': 0,
        }
        
        log_data = har_data.get("log", {})
        entries = log_data.get("entries", [])
        pages = log_data.get("pages", [])
        
        data['pages_count'] = len(pages)
        
        # Get hostname from first page
        if pages:
            first_page = pages[0]
            page_url = first_page.get("title", "") or first_page.get("id", "")
            if page_url:
                match = re.search(r'https?://([^/]+)', page_url)
                if match:
                    data['hostname'] = match.group(1)
        
        # Get User-Agent from first request
        if entries:
            first_entry = entries[0]
            request = first_entry.get("request", {})
            headers = headers_to_dict(request.get("headers", []))
            user_agent = headers.get('User-Agent') or headers.get('user-agent', 'N/A')
            data['user_agent'] = user_agent
            
            # Extract browser from User-Agent
            if user_agent != 'N/A':
                # Chrome
                chrome_match = re.search(r'Chrome/(\d+\.\d+\.\d+\.\d+)', user_agent)
                if chrome_match:
                    data['browser_name'] = 'Chrome'
                    data['browser_version'] = chrome_match.group(1)
                else:
                    # Firefox
                    firefox_match = re.search(r'Firefox/(\d+\.\d+)', user_agent)
                    if firefox_match:
                        data['browser_name'] = 'Firefox'
                        data['browser_version'] = firefox_match.group(1)
                    else:
                        # Safari
                        safari_match = re.search(r'Safari/(\d+\.\d+)', user_agent)
                        if safari_match and 'Chrome' not in user_agent:
                            data['browser_name'] = 'Safari'
                            data['browser_version'] = safari_match.group(1)
                        else:
                            # Edge
                            edge_match = re.search(r'Edg/(\d+\.\d+\.\d+\.\d+)', user_agent)
                            if edge_match:
                                data['browser_name'] = 'Edge'
                                data['browser_version'] = edge_match.group(1)
        
        # Fallback to creator info
        if data['browser_name'] == 'N/A':
            creator = log_data.get("creator", {})
            if creator:
                data['browser_name'] = creator.get('name', 'N/A')
                data['browser_version'] = creator.get('version', 'N/A')
            else:
                browser = log_data.get("browser", {})
                if browser:
                    data['browser_name'] = browser.get('name', 'N/A')
                    data['browser_version'] = browser.get('version', 'N/A')
        
        return data
    
    def _calculate_perf_metrics(self, entries: list) -> dict:
        """Calculate basic performance metrics"""
        metrics = {
            'ttfb': None,
            'fcp': None,
            'dom_resources': 0,
            'total_time': 0
        }
        
        if not entries:
            return metrics
        
        # TTFB - time to first byte of first request
        first_entry = entries[0]
        timings = first_entry.get("timings", {})
        if timings:
            blocked = timings.get('blocked', 0) or 0
            dns = timings.get('dns', 0) or 0
            connect = timings.get('connect', 0) or 0
            send = timings.get('send', 0) or 0
            wait = timings.get('wait', 0) or 0
            metrics['ttfb'] = blocked + dns + connect + send + wait
        
        # Approximate FCP - time of first HTML or image
        for entry in entries:
            response = entry.get("response", {})
            content = response.get("content", {})
            mime_type = content.get("mimeType", "")
            if 'text/html' in mime_type or 'image' in mime_type:
                metrics['fcp'] = entry.get("time", 0)
                break
        
        # Total time and resource count
        metrics['total_time'] = sum(e.get("time", 0) for e in entries)
        metrics['dom_resources'] = len(entries)
        
        return metrics
    
    def _analyze_har_full(self, parser, har_data: dict) -> dict:
        """Full detailed HAR analysis"""
        
        log_data = har_data.get("log", {})
        entries = log_data.get("entries", [])
        pages = log_data.get("pages", [])
        
        # Browser and environment info
        user_data = self._extract_browser_info(har_data)
        
        # Overall statistics
        total_size = 0
        all_errors = []
        all_warnings = []
        
        # Resource types breakdown
        resource_types = {
            'html': {'size': 0, 'count': 0, 'load_time': 0},
            'css': {'size': 0, 'count': 0, 'load_time': 0},
            'javascript': {'size': 0, 'count': 0, 'load_time': 0},
            'images': {'size': 0, 'count': 0, 'load_time': 0},
            'audio': {'size': 0, 'count': 0, 'load_time': 0},
            'video': {'size': 0, 'count': 0, 'load_time': 0},
            'json': {'size': 0, 'count': 0, 'load_time': 0},
            'other': {'size': 0, 'count': 0, 'load_time': 0},
        }
        
        # Domains
        domains = {}
        status_codes = {}
        url_counts = {}
        
        # Detailed entries
        detailed_entries = []
        
        for entry in entries:
            request = entry.get("request", {})
            response = entry.get("response", {})
            content = response.get("content", {})
            
            url = request.get("url", "")
            method = request.get("method", "GET")
            status = response.get("status", 0)
            time_ms = entry.get("time", 0)
            mime_type = content.get("mimeType", "")
            
            # Size
            size = self._get_entry_size(entry)
            total_size += size
            
            # Status codes
            status_codes[status] = status_codes.get(status, 0) + 1
            
            # Domain
            domain = self._extract_domain(url)
            if domain:
                domains[domain] = domains.get(domain, 0) + 1
            
            # URL duplicates
            url_counts[url] = url_counts.get(url, 0) + 1
            
            # Resource type classification
            type_key = 'other'
            if 'text/html' in mime_type:
                type_key = 'html'
            elif 'text/css' in mime_type:
                type_key = 'css'
            elif 'javascript' in mime_type or 'ecmascript' in mime_type:
                type_key = 'javascript'
            elif 'image/' in mime_type:
                type_key = 'images'
            elif 'audio/' in mime_type:
                type_key = 'audio'
            elif 'video/' in mime_type:
                type_key = 'video'
            elif 'json' in mime_type:
                type_key = 'json'
            
            resource_types[type_key]['size'] += size
            resource_types[type_key]['count'] += 1
            resource_types[type_key]['load_time'] += time_ms
            
            # Timings
            timings = self._get_timings(entry)
            
            # Cache info
            cache_info = self._analyze_caching(entry)
            
            # Request/Response headers
            req_headers = headers_to_dict(request.get("headers", []))
            resp_headers = headers_to_dict(response.get("headers", []))
            
            # Response body (limited) + decode base64 when present
            response_body = ""
            raw_text = content.get("text")
            if raw_text:
                encoding = (content.get("encoding") or "").lower()
                if encoding == "base64":
                    try:
                        decoded = base64.b64decode(raw_text)
                        response_body = decoded.decode("utf-8", errors="replace")
                    except Exception:
                        # Fallback to raw text if decoding fails
                        response_body = str(raw_text)
                else:
                    response_body = str(raw_text)
                response_body = response_body[:2000]
            
            entry_data = {
                'url': url,
                'method': method,
                'status': status,
                'status_text': response.get("statusText", ""),
                'time': time_ms,
                'size': size,
                'mime_type': mime_type,
                'type': type_key,
                'timings': timings,
                'cache_info': cache_info,
                'request_headers': req_headers,
                'response_headers': resp_headers,
                'response_body': response_body,
            }
            detailed_entries.append(entry_data)
            
            # Errors (status >= 400 or status == 0)
            if status == 0:
                all_errors.append({
                    **entry_data,
                    'error_type': 'aborted',
                    'status_text': 'Aborted/Blocked/CORS'
                })
                all_warnings.append({
                    'type': 'aborted_request',
                    'url': url,
                    'message': 'Request aborted or blocked (possible CORS)'
                })
            elif status >= 400:
                error_type = 'server_error' if status >= 500 else 'client_error'
                all_errors.append({
                    **entry_data,
                    'error_type': error_type,
                })
            else:
                # Application-level error heuristics even for 2xx/3xx
                # (HAR from DevTools doesn't include console logs; but API responses may carry error payload)
                body_lower = response_body.lower() if response_body else ""
                app_error_type: Optional[str] = None

                # Heuristic 1: JSON with typical error fields
                if response_body and ("json" in mime_type or response_body.lstrip().startswith(("{", "["))):
                    try:
                        parsed = json.loads(response_body)
                        if isinstance(parsed, dict):
                            # Common patterns: success=false/ok=false, error/errors/exception/message
                            if parsed.get("success") is False or parsed.get("ok") is False:
                                app_error_type = "application_error"
                            elif any(k in parsed for k in ("error", "errors", "exception", "trace", "traceId", "stack", "stackTrace")):
                                # If key exists and value is non-empty
                                for k in ("error", "errors", "exception", "message"):
                                    v = parsed.get(k)
                                    if v not in (None, "", [], {}):
                                        app_error_type = "application_error"
                                        break
                                if app_error_type is None and any(parsed.get(k) not in (None, "", [], {}) for k in ("trace", "traceId", "stack", "stackTrace")):
                                    app_error_type = "application_error"
                    except Exception:
                        # ignore json parse errors
                        pass

                # Heuristic 2: text signatures of server exceptions
                if app_error_type is None and body_lower:
                    error_signatures = (
                        "exception",
                        "stack trace",
                        "stacktrace",
                        "traceback",
                        "unhandled",
                        "nullpointerexception",
                        "internal server error",
                        "fatal error",
                    )
                    if any(sig in body_lower for sig in error_signatures):
                        app_error_type = "application_error"

                if app_error_type is not None:
                    all_errors.append({
                        **entry_data,
                        'error_type': app_error_type,
                    })
        
        # Find duplicates
        duplicates = {url: count for url, count in url_counts.items() if count > 1}
        
        # Performance metrics
        perf_metrics = self._calculate_perf_metrics(entries)
        
        return {
            'analysis_date': datetime.now().isoformat(),
            'user_data': user_data,
            'summary': {
                'total_requests': len(entries),
                'total_size_bytes': total_size,
                'total_size_formatted': format_bytes(total_size),
                'pages_count': len(pages),
                'errors_count': len(all_errors),
                'warnings_count': len(all_warnings),
                'domains_count': len(domains),
                'duplicates_count': len(duplicates),
            },
            'performance': perf_metrics,
            'status_codes': status_codes,
            'resource_types': resource_types,
            'domains': domains,
            'errors': all_errors,
            'warnings': all_warnings,
            'duplicates': duplicates,
            'entries': detailed_entries,
            'top_slowest': sorted(detailed_entries, key=lambda e: e['time'], reverse=True)[:20],
        }
    
    def _extract_domain(self, url: str) -> str:
        """Extract domain from URL"""
        match = re.search(r'https?://([^/]+)', url)
        return match.group(1) if match else ""
    
    def _filter_errors(self, result: dict) -> dict:
        """Filter only errors and warnings"""
        return {
            'errors_count': result['summary']['errors_count'],
            'warnings_count': result['summary']['warnings_count'],
            'errors': result['errors'],
            'warnings': result['warnings'],
            'duplicates': result['duplicates'],
        }
    
    def _format_detailed_summary(self, result: dict) -> str:
        """Format detailed results as text summary"""
        summary = result['summary']
        user_data = result['user_data']
        perf = result['performance']
        
        lines = [
            "=" * 70,
            "📊 HAR ANALYSIS REPORT",
            "=" * 70,
            f"",
            f"📅 Analysis Date: {result['analysis_date']}",
            f"",
            "─" * 70,
            "👤 BROWSER & ENVIRONMENT INFO",
            "─" * 70,
            f"  🌐 Browser:        {user_data['browser_name']} {user_data['browser_version']}",
            f"  🖥️  Hostname:       {user_data['hostname']}",
            f"  📄 Pages Count:    {user_data['pages_count']}",
            f"  🔤 User-Agent:     {user_data['user_agent'][:70]}{'...' if len(user_data['user_agent']) > 70 else ''}",
            f"",
            "─" * 70,
            "📈 SUMMARY STATISTICS",
            "─" * 70,
            f"  📊 Total Requests: {summary['total_requests']}",
            f"  📦 Total Size:     {summary['total_size_formatted']} ({summary['total_size_bytes']:,} bytes)",
            f"  🌐 Domains:        {summary['domains_count']}",
            f"  ❌ Errors:         {summary['errors_count']}",
            f"  ⚠️  Warnings:       {summary['warnings_count']}",
            f"  🔄 Duplicates:     {summary['duplicates_count']}",
        ]
        
        # Performance metrics
        lines.extend([
            f"",
            "─" * 70,
            "⚡ PERFORMANCE METRICS",
            "─" * 70,
        ])
        
        if perf['ttfb']:
            lines.append(f"  ⏱️  TTFB (Time to First Byte):  {perf['ttfb']:,} ms")
        else:
            lines.append(f"  ⏱️  TTFB (Time to First Byte):  N/A")
        
        if perf['fcp']:
            lines.append(f"  🎨 FCP (First Contentful Paint): {perf['fcp']:,} ms")
        else:
            lines.append(f"  🎨 FCP (First Contentful Paint): N/A")
        
        lines.append(f"  ⏰ Total Load Time:              {perf['total_time']:,} ms")
        lines.append(f"  📦 DOM Resources:                {perf['dom_resources']}")
        
        # Status codes
        if result['status_codes']:
            lines.extend([
                f"",
                "─" * 70,
                "📋 STATUS CODES",
                "─" * 70,
            ])
            for status in sorted(result['status_codes'].keys()):
                count = result['status_codes'][status]
                emoji = get_status_emoji(status)
                if status == 0:
                    label = "Aborted/Blocked"
                else:
                    label = f"HTTP {status}"
                lines.append(f"  {emoji} {label}: {count} requests")
        
        # Resource types
        lines.extend([
            f"",
            "─" * 70,
            "📦 RESOURCE TYPES BREAKDOWN",
            "─" * 70,
        ])
        
        resource_emojis = {
            'html': '📄',
            'css': '🎨',
            'javascript': '⚙️',
            'images': '🖼️',
            'audio': '🔊',
            'video': '🎬',
            'json': '📋',
            'other': '📎',
        }
        
        for rtype, data in result['resource_types'].items():
            if data['count'] > 0:
                emoji = resource_emojis.get(rtype, '📎')
                lines.append(f"  {emoji} {rtype.upper():12} {data['count']:>4} requests  {format_bytes(data['size']):>12}  {data['load_time']:,} ms")
        
        # Top domains
        if result['domains']:
            lines.extend([
                f"",
                "─" * 70,
                "🌐 TOP DOMAINS",
                "─" * 70,
            ])
            sorted_domains = sorted(result['domains'].items(), key=lambda x: x[1], reverse=True)[:10]
            for i, (domain, count) in enumerate(sorted_domains, 1):
                lines.append(f"  {i:2}. {domain}: {count} requests")
        
        # Duplicates
        if result['duplicates']:
            lines.extend([
                f"",
                "─" * 70,
                "🔄 DUPLICATE REQUESTS",
                "─" * 70,
            ])
            sorted_dups = sorted(result['duplicates'].items(), key=lambda x: x[1], reverse=True)[:10]
            for url, count in sorted_dups:
                lines.append(f"  🔄 {count}x {url[:60]}{'...' if len(url) > 60 else ''}")
        
        # Warnings
        if result['warnings']:
            lines.extend([
                f"",
                "─" * 70,
                f"⚠️  WARNINGS ({len(result['warnings'])})",
                "─" * 70,
            ])
            for warning in result['warnings'][:10]:
                lines.append(f"  ⚠️  [{warning['type']}] {warning['message']}")
                lines.append(f"      URL: {warning['url'][:60]}{'...' if len(warning['url']) > 60 else ''}")
            if len(result['warnings']) > 10:
                lines.append(f"  ... and {len(result['warnings']) - 10} more warnings")
        
        # Errors
        if result['errors']:
            lines.extend([
                f"",
                "─" * 70,
                f"❌ ERRORS ({len(result['errors'])})",
                "─" * 70,
            ])
            for i, error in enumerate(result['errors'][:15], 1):
                emoji = get_status_emoji(error['status'])
                error_type = error.get('error_type', 'unknown')
                status_text = error.get('status_text', '')
                lines.append(f"")
                lines.append(f"  {emoji} Error #{i} [{error_type}]")
                lines.append(f"      URL:    {error['url'][:70]}{'...' if len(error['url']) > 70 else ''}")
                lines.append(f"      Method: {error['method']}")
                lines.append(f"      Status: {error['status']} {status_text}")
                lines.append(f"      Time:   {error['time']} ms")
                lines.append(f"      Size:   {format_bytes(error['size'])}")
                lines.append(f"      Type:   {error['mime_type'] or 'unknown'}")
                
                # Show key headers for errors
                req_headers = error.get('request_headers', {})
                if req_headers:
                    lines.append(f"      Request Headers:")
                    for key, value in list(req_headers.items())[:3]:
                        lines.append(f"        {key}: {value[:50]}{'...' if len(value) > 50 else ''}")
                
                if error.get('response_body'):
                    body_preview = error['response_body'][:200].replace('\n', ' ')
                    lines.append(f"      Response Preview: {body_preview}{'...' if len(error['response_body']) > 200 else ''}")
            
            if len(result['errors']) > 15:
                lines.append(f"")
                lines.append(f"  ... and {len(result['errors']) - 15} more errors")
        
        # Top slowest requests
        if result['top_slowest']:
            lines.extend([
                f"",
                "─" * 70,
                "🐌 TOP 15 SLOWEST REQUESTS",
                "─" * 70,
            ])
            for i, entry in enumerate(result['top_slowest'][:15], 1):
                emoji = get_status_emoji(entry['status'])
                cache_icon = '💾' if entry['cache_info'].get('cached') else ''
                compress_icon = '🗜️' if entry['cache_info'].get('content_encoding') else ''
                lines.append(f"  {i:2}. {emoji} {entry['time']:>6}ms  {format_bytes(entry['size']):>10}  [{cache_icon}{compress_icon}]  {entry['method']:>6}  {entry['url'][:50]}{'...' if len(entry['url']) > 50 else ''}")
        
        lines.extend([
            f"",
            "=" * 70,
            "End of Report",
            "=" * 70,
        ])
        
        return "\n".join(lines)
    
    def _format_errors_only(self, result: dict) -> str:
        """Format only errors and warnings"""
        lines = [
            "=" * 70,
            "❌ ERRORS & WARNINGS REPORT",
            "=" * 70,
            f"",
            f"Errors: {result['summary']['errors_count']}",
            f"Warnings: {result['summary']['warnings_count']}",
        ]
        
        # Duplicates
        if result['duplicates']:
            lines.extend([
                f"",
                "─" * 70,
                "🔄 DUPLICATE REQUESTS",
                "─" * 70,
            ])
            sorted_dups = sorted(result['duplicates'].items(), key=lambda x: x[1], reverse=True)
            for url, count in sorted_dups:
                lines.append(f"  {count}x {url}")
        
        # Warnings
        if result['warnings']:
            lines.extend([
                f"",
                "─" * 70,
                f"⚠️  WARNINGS ({len(result['warnings'])})",
                "─" * 70,
            ])
            for warning in result['warnings']:
                lines.append(f"")
                lines.append(f"  [{warning['type']}]")
                lines.append(f"  URL: {warning['url']}")
                lines.append(f"  Message: {warning['message']}")
        
        # Errors
        if result['errors']:
            lines.extend([
                f"",
                "─" * 70,
                f"❌ ERRORS ({len(result['errors'])})",
                "─" * 70,
            ])
            for i, error in enumerate(result['errors'], 1):
                lines.append(f"")
                lines.append(f"  Error #{i} [{error.get('error_type', 'unknown')}]")
                lines.append(f"  URL: {error['url']}")
                lines.append(f"  Method: {error['method']}")
                lines.append(f"  Status: {error['status']} {error.get('status_text', '')}")
                lines.append(f"  Time: {error['time']} ms")
                lines.append(f"  Size: {format_bytes(error['size'])}")
                
                # Headers
                if error.get('request_headers'):
                    lines.append(f"  Request Headers:")
                    for k, v in error['request_headers'].items():
                        lines.append(f"    {k}: {v}")
                
                if error.get('response_headers'):
                    lines.append(f"  Response Headers:")
                    for k, v in error['response_headers'].items():
                        lines.append(f"    {k}: {v}")
                
                if error.get('response_body'):
                    lines.append(f"  Response Body (preview):")
                    body = error['response_body'][:500].replace('\n', ' ')
                    lines.append(f"    {body}")
        
        lines.extend([
            f"",
            "=" * 70,
        ])
        
        return "\n".join(lines)
