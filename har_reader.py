#!/usr/bin/env python3
"""
HAR File Reader - Complete HAR Parser and Analyzer
===================================================

A robust script to read, decrypt, and analyze HAR (HTTP Archive) files completely.
Supports full extraction of requests, responses, headers, cookies, timings, and more.

Author: SOLITAIRE HACK
Version: 1.0.0
License: MIT
"""

import json
import gzip
import base64
import zlib
from typing import Dict, List, Any, Optional, Union
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
import re


class HARError(Exception):
    """Base exception for HAR-related errors."""
    pass


class HARValidationError(HARError):
    """Raised when HAR file structure is invalid."""
    pass


class HARReadError(HARError):
    """Raised when HAR file cannot be read."""
    pass


@dataclass
class HARRequest:
    """Represents a HTTP request from HAR file."""
    method: str
    url: str
    http_version: str
    headers: List[Dict[str, str]]
    cookies: List[Dict[str, str]]
    query_string: List[Dict[str, str]]
    post_data: Optional[Dict[str, Any]] = None
    headers_size: int = 0
    body_size: int = 0

    def get_header(self, name: str) -> Optional[str]:
        """Get header value by name (case-insensitive)."""
        for header in self.headers:
            if header['name'].lower() == name.lower():
                return header['value']
        return None

    def get_cookie(self, name: str) -> Optional[str]:
        """Get cookie value by name."""
        for cookie in self.cookies:
            if cookie['name'] == name:
                return cookie['value']
        return None


@dataclass
class HARResponse:
    """Represents a HTTP response from HAR file."""
    status: int
    status_text: str
    http_version: str
    headers: List[Dict[str, str]]
    cookies: List[Dict[str, str]]
    content: Dict[str, Any]
    redirect_url: str = ""
    headers_size: int = 0
    body_size: int = 0

    def get_header(self, name: str) -> Optional[str]:
        """Get header value by name (case-insensitive)."""
        for header in self.headers:
            if header['name'].lower() == name.lower():
                return header['value']
        return None

    def get_decoded_body(self) -> Optional[bytes]:
        """Get decoded response body based on encoding."""
        if not self.content or 'text' not in self.content:
            return None

        encoding = self.content.get('encoding', None)
        text = self.content['text']

        try:
            if encoding == 'base64':
                return base64.b64decode(text)
            elif encoding == 'gzip':
                return gzip.decompress(base64.b64decode(text))
            elif encoding == 'deflate':
                return zlib.decompress(base64.b64decode(text))
            else:
                # Assume plain text
                if isinstance(text, str):
                    return text.encode('utf-8')
                return text
        except Exception as e:
            raise HARError(f"Failed to decode body: {e}")


@dataclass
class HARTiming:
    """Represents timing information for a request."""
    blocked: float = 0.0
    dns: float = 0.0
    connect: float = 0.0
    send: float = 0.0
    wait: float = 0.0
    receive: float = 0.0
    ssl: float = 0.0

    @property
    def total(self) -> float:
        """Calculate total timing."""
        return sum([
            self.blocked, self.dns, self.connect,
            self.send, self.wait, self.receive, self.ssl
        ])


@dataclass
class HAREntry:
    """Represents a complete HAR entry (request/response pair)."""
    request: HARRequest
    response: HARResponse
    timing: HARTiming
    started_datetime: datetime
    time: float
    cache: Dict[str, Any] = field(default_factory=dict)
    pageref: str = ""
    server_ip_address: str = ""

    @property
    def is_https(self) -> bool:
        """Check if request is HTTPS."""
        return self.request.url.startswith('https://')

    @property
    def domain(self) -> str:
        """Extract domain from URL."""
        from urllib.parse import urlparse
        return urlparse(self.request.url).netloc


@dataclass
class HARFile:
    """Represents a complete HAR file."""
    log: Dict[str, Any]
    entries: List[HAREntry] = field(default_factory=list)
    creator: Dict[str, Any] = field(default_factory=dict)
    browser: Dict[str, Any] = field(default_factory=dict)
    pages: List[Dict[str, Any]] = field(default_factory=list)

    @property
    def version(self) -> str:
        """Get HAR version."""
        return self.log.get('version', '')

    @property
    def total_entries(self) -> int:
        """Get total number of entries."""
        return len(self.entries)

    def get_entries_by_domain(self, domain: str) -> List[HAREntry]:
        """Filter entries by domain."""
        return [entry for entry in self.entries if entry.domain == domain]

    def get_entries_by_status(self, status: int) -> List[HAREntry]:
        """Filter entries by HTTP status code."""
        return [entry for entry in self.entries if entry.response.status == status]

    def get_entries_by_content_type(self, content_type: str) -> List[HAREntry]:
        """Filter entries by content type."""
        results = []
        for entry in self.entries:
            ct = entry.response.get_header('content-type') or ''
            if content_type.lower() in ct.lower():
                results.append(entry)
        return results


class HARReader:
    """
    Complete HAR file reader and parser.
    
    Supports:
    - Reading HAR files (JSON format)
    - Gzipped HAR files
    - Base64 encoded content
    - Complete data extraction
    - Validation
    """

    def __init__(self):
        self._har_file: Optional[HARFile] = None

    def read(self, file_path: Union[str, Path]) -> HARFile:
        """
        Read and parse a HAR file.
        
        Args:
            file_path: Path to HAR file (can be .har, .har.gz, or .json)
            
        Returns:
            HARFile object containing all parsed data
            
        Raises:
            HARReadError: If file cannot be read
            HARValidationError: If HAR structure is invalid
        """
        file_path = Path(file_path)

        if not file_path.exists():
            raise HARReadError(f"File not found: {file_path}")

        try:
            # Handle gzipped files
            if file_path.suffix == '.gz':
                with gzip.open(file_path, 'rt', encoding='utf-8') as f:
                    data = json.load(f)
            else:
                with open(file_path, 'r', encoding='utf-8') as f:
                    data = json.load(f)

            return self._parse_har(data)

        except json.JSONDecodeError as e:
            raise HARReadError(f"Invalid JSON in HAR file: {e}")
        except Exception as e:
            raise HARReadError(f"Failed to read HAR file: {e}")

    def _parse_har(self, data: Dict[str, Any]) -> HARFile:
        """Parse HAR data structure."""
        # Validate basic structure
        if 'log' not in data:
            raise HARValidationError("HAR file missing 'log' section")

        log = data['log']

        # Validate version
        if 'version' not in log:
            raise HARValidationError("HAR file missing version information")

        # Extract metadata
        creator = log.get('creator', {})
        browser = log.get('browser', {})
        pages = log.get('pages', [])
        entries_data = log.get('entries', [])

        # Parse entries
        entries = []
        for entry_data in entries_data:
            try:
                entry = self._parse_entry(entry_data)
                entries.append(entry)
            except Exception as e:
                # Log but continue parsing other entries
                print(f"Warning: Failed to parse entry: {e}")

        har_file = HARFile(
            log=log,
            entries=entries,
            creator=creator,
            browser=browser,
            pages=pages
        )

        self._har_file = har_file
        return har_file

    def _parse_entry(self, entry_data: Dict[str, Any]) -> HAREntry:
        """Parse a single HAR entry."""
        # Parse request
        request_data = entry_data.get('request', {})
        request = HARRequest(
            method=request_data.get('method', ''),
            url=request_data.get('url', ''),
            http_version=request_data.get('httpVersion', ''),
            headers=request_data.get('headers', []),
            cookies=request_data.get('cookies', []),
            query_string=request_data.get('queryString', []),
            post_data=request_data.get('postData'),
            headers_size=request_data.get('headersSize', 0),
            body_size=request_data.get('bodySize', 0)
        )

        # Parse response
        response_data = entry_data.get('response', {})
        response = HARResponse(
            status=response_data.get('status', 0),
            status_text=response_data.get('statusText', ''),
            http_version=response_data.get('httpVersion', ''),
            headers=response_data.get('headers', []),
            cookies=response_data.get('cookies', []),
            content=response_data.get('content', {}),
            redirect_url=response_data.get('redirectURL', ''),
            headers_size=response_data.get('headersSize', 0),
            body_size=response_data.get('bodySize', 0)
        )

        # Parse timing
        timing_data = entry_data.get('timings', {})
        timing = HARTiming(
            blocked=timing_data.get('blocked', 0),
            dns=timing_data.get('dns', 0),
            connect=timing_data.get('connect', 0),
            send=timing_data.get('send', 0),
            wait=timing_data.get('wait', 0),
            receive=timing_data.get('receive', 0),
            ssl=timing_data.get('ssl', 0)
        )

        # Parse datetime
        started_datetime_str = entry_data.get('startedDateTime', '')
        try:
            started_datetime = datetime.fromisoformat(started_datetime_str.replace('Z', '+00:00'))
        except (ValueError, AttributeError):
            started_datetime = datetime.now()

        return HAREntry(
            request=request,
            response=response,
            timing=timing,
            started_datetime=started_datetime,
            time=entry_data.get('time', 0),
            cache=entry_data.get('cache', {}),
            pageref=entry_data.get('pageref', ''),
            server_ip_address=entry_data.get('serverIPAddress', '')
        )

    def analyze(self, har_file: Optional[HARFile] = None) -> Dict[str, Any]:
        """
        Perform comprehensive analysis of HAR file.
        
        Returns:
            Dictionary containing analysis results
        """
        if har_file is None:
            har_file = self._har_file

        if har_file is None:
            raise HARError("No HAR file loaded. Call read() first.")

        entries = har_file.entries

        # Basic statistics
        total_requests = len(entries)
        total_size = sum(e.response.body_size for e in entries if e.response.body_size > 0)
        total_time = sum(e.time for e in entries)

        # Status code distribution
        status_codes = {}
        for entry in entries:
            status = entry.response.status
            status_codes[status] = status_codes.get(status, 0) + 1

        # Content type distribution
        content_types = {}
        for entry in entries:
            ct = entry.response.get_header('content-type') or 'unknown'
            content_types[ct] = content_types.get(ct, 0) + 1

        # Domain distribution
        domains = {}
        for entry in entries:
            domain = entry.domain
            domains[domain] = domains.get(domain, 0) + 1

        # Method distribution
        methods = {}
        for entry in entries:
            method = entry.request.method
            methods[method] = methods.get(method, 0) + 1

        return {
            'summary': {
                'total_requests': total_requests,
                'total_size_bytes': total_size,
                'total_time_ms': total_time,
                'unique_domains': len(domains),
                'har_version': har_file.version
            },
            'status_codes': status_codes,
            'content_types': content_types,
            'domains': domains,
            'methods': methods,
            'creator': har_file.creator,
            'browser': har_file.browser
        }

    def export_to_csv(self, output_path: Union[str, Path], 
                     har_file: Optional[HARFile] = None) -> None:
        """
        Export HAR entries to CSV format.
        
        Args:
            output_path: Path for output CSV file
            har_file: HARFile to export (uses loaded file if None)
        """
        if har_file is None:
            har_file = self._har_file

        if har_file is None:
            raise HARError("No HAR file loaded. Call read() first.")

        import csv

        output_path = Path(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)

        with open(output_path, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            
            # Write header
            writer.writerow([
                'Started DateTime', 'Method', 'URL', 'Domain', 'Status',
                'Status Text', 'Content Type', 'Size (bytes)', 'Time (ms)',
                'Blocked', 'DNS', 'Connect', 'Send', 'Wait', 'Receive', 'SSL'
            ])

            # Write entries
            for entry in har_file.entries:
                writer.writerow([
                    entry.started_datetime.isoformat(),
                    entry.request.method,
                    entry.request.url,
                    entry.domain,
                    entry.response.status,
                    entry.response.status_text,
                    entry.response.get_header('content-type') or '',
                    entry.response.body_size,
                    entry.time,
                    entry.timing.blocked,
                    entry.timing.dns,
                    entry.timing.connect,
                    entry.timing.send,
                    entry.timing.wait,
                    entry.timing.receive,
                    entry.timing.ssl
                ])

    def extract_bodies(self, output_dir: Union[str, Path],
                      content_type_filter: Optional[str] = None,
                      har_file: Optional[HARFile] = None) -> int:
        """
        Extract response bodies to files.
        
        Args:
            output_dir: Directory to save extracted bodies
            content_type_filter: Optional content type filter (e.g., 'application/json')
            har_file: HARFile to extract from (uses loaded file if None)
            
        Returns:
            Number of files extracted
        """
        if har_file is None:
            har_file = self._har_file

        if har_file is None:
            raise HARError("No HAR file loaded. Call read() first.")

        output_dir = Path(output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)

        extracted = 0

        for idx, entry in enumerate(har_file.entries):
            # Apply content type filter if specified
            if content_type_filter:
                ct = entry.response.get_header('content-type') or ''
                if content_type_filter.lower() not in ct.lower():
                    continue

            try:
                body = entry.response.get_decoded_body()
                if body is None:
                    continue

                # Determine file extension
                ct = entry.response.get_header('content-type') or ''
                ext = self._get_extension_from_content_type(ct)

                # Create filename
                filename = f"entry_{idx:04d}_{entry.response.status}{ext}"
                filepath = output_dir / filename

                # Write file
                mode = 'wb' if isinstance(body, bytes) else 'w'
                encoding = None if isinstance(body, bytes) else 'utf-8'
                with open(filepath, mode, encoding=encoding) as f:
                    f.write(body)

                extracted += 1

            except Exception as e:
                print(f"Warning: Failed to extract body for entry {idx}: {e}")

        return extracted

    def _get_extension_from_content_type(self, content_type: str) -> str:
        """Map content type to file extension."""
        content_type = content_type.lower()
        
        extensions = {
            'application/json': '.json',
            'application/xml': '.xml',
            'text/html': '.html',
            'text/css': '.css',
            'text/javascript': '.js',
            'application/javascript': '.js',
            'image/jpeg': '.jpg',
            'image/png': '.png',
            'image/gif': '.gif',
            'image/svg+xml': '.svg',
            'application/pdf': '.pdf',
            'text/plain': '.txt',
        }

        for ct, ext in extensions.items():
            if ct in content_type:
                return ext

        return '.bin'


def main():
    """Command-line interface for HAR reader."""
    import argparse
    import sys

    parser = argparse.ArgumentParser(
        description='HAR File Reader - Complete HAR Parser and Analyzer',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Read and analyze a HAR file
  python har_reader.py analyze file.har

  # Export to CSV
  python har_reader.py export-csv file.har output.csv

  # Extract response bodies
  python har_reader.py extract-bodies file.har output_dir/

  # Extract only JSON responses
  python har_reader.py extract-bodies file.har output_dir/ --content-type application/json
        """
    )

    subparsers = parser.add_subparsers(dest='command', help='Available commands')

    # Analyze command
    analyze_parser = subparsers.add_parser('analyze', help='Analyze HAR file')
    analyze_parser.add_argument('file', help='HAR file path')

    # Export CSV command
    csv_parser = subparsers.add_parser('export-csv', help='Export to CSV')
    csv_parser.add_argument('file', help='HAR file path')
    csv_parser.add_argument('output', help='Output CSV file path')

    # Extract bodies command
    extract_parser = subparsers.add_parser('extract-bodies', help='Extract response bodies')
    extract_parser.add_argument('file', help='HAR file path')
    extract_parser.add_argument('output_dir', help='Output directory')
    extract_parser.add_argument('--content-type', help='Filter by content type')

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(1)

    try:
        reader = HARReader()
        har_file = reader.read(args.file)

        if args.command == 'analyze':
            analysis = reader.analyze(har_file)
            print("\n" + "="*60)
            print("HAR FILE ANALYSIS")
            print("="*60)
            
            print("\nSUMMARY:")
            for key, value in analysis['summary'].items():
                print(f"  {key}: {value}")

            print("\nSTATUS CODES:")
            for status, count in sorted(analysis['status_codes'].items()):
                print(f"  {status}: {count}")

            print("\nMETHODS:")
            for method, count in sorted(analysis['methods'].items()):
                print(f"  {method}: {count}")

            print("\nTOP DOMAINS:")
            for domain, count in sorted(analysis['domains'].items(), 
                                        key=lambda x: x[1], reverse=True)[:10]:
                print(f"  {domain}: {count}")

        elif args.command == 'export-csv':
            reader.export_to_csv(args.output, har_file)
            print(f"Exported {har_file.total_entries} entries to {args.output}")

        elif args.command == 'extract-bodies':
            count = reader.extract_bodies(
                args.output_dir,
                args.content_type,
                har_file
            )
            print(f"Extracted {count} response bodies to {args.output_dir}")

    except HARError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)
    except KeyboardInterrupt:
        print("\nInterrupted by user", file=sys.stderr)
        sys.exit(130)


if __name__ == '__main__':
    main()
