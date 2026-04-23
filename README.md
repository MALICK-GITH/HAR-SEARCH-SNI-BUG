# HAR Reader - Complete HAR Parser and Analyzer

A robust Python script to read, decrypt, and analyze HAR (HTTP Archive) files completely.

**Author:** SOLITAIRE HACK  
**Version:** 1.0.0  
**License:** MIT

---

## Features

- ✅ **Complete HAR Parsing**: Reads all HAR file sections (log, entries, pages, etc.)
- ✅ **Decryption Support**: Handles base64, gzip, and deflate encoded content
- ✅ **Full Data Extraction**: Requests, responses, headers, cookies, timings, cache
- ✅ **Gzipped HAR Support**: Automatically handles `.har.gz` files
- ✅ **Validation**: Strict HAR structure validation
- ✅ **Analysis Tools**: Comprehensive statistics and metrics
- ✅ **CSV Export**: Export entries to CSV format
- ✅ **Body Extraction**: Extract response bodies to files
- ✅ **Filtering**: Filter by domain, status code, content type
- ✅ **Error Handling**: Robust error handling with custom exceptions

---

## Installation

### Requirements

- Python 3.7+
- The CLI parser can run with the standard library only, but the Flask web app and PostgreSQL history features require `requirements.txt`.

### Setup

```bash
# Clone or download the project
# Install requirements only if you want the Flask web app or PostgreSQL-backed history

# Make executable (Linux/Mac)
chmod +x har_reader.py
```

---

## Web App and PostgreSQL Setup

The CLI-oriented `har_reader.py` workflow remains lightweight, but the Flask web app and saved analysis history require the dependencies listed in `requirements.txt`.

### Saved Environment Variables

- `DATABASE_URL`: Required for saved analysis history. Use the external Render PostgreSQL URL for local development and the internal Render PostgreSQL URL when the Flask service runs inside the same private Render network.
- `FLASK_SECRET_KEY`: Recommended for stable sessions and production safety.
- `CORS_ORIGINS`: Comma-separated list of allowed frontend origins. Defaults to the local Flask URLs when omitted.
- `LOG_LEVEL`: Optional logging level such as `INFO` or `DEBUG`.
- `INMUX_REQUEST_TIMEOUT`: Optional timeout for INMUX lookups in seconds.
- `HACKERTARGET_API_KEY`: Optional API key used by advanced lookup features.

### Local Web App Setup

```powershell
py -3.11 -m venv .venv
.\.venv\Scripts\python.exe -m ensurepip --upgrade
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
```

Copy `.env.example` to `.env` or set the variables directly in your shell before starting the app.

```powershell
$env:DATABASE_URL="postgresql://USER:PASSWORD@HOST:5432/DBNAME"
$env:FLASK_SECRET_KEY="replace-with-a-random-secret"
.\.venv\Scripts\python.exe test_db_connection.py
.\.venv\Scripts\python.exe app.py
```

---

## Usage

### Command Line Interface

#### Analyze a HAR File

```bash
python har_reader.py analyze file.har
```

Output:
```
============================================================
HAR FILE ANALYSIS
============================================================

SUMMARY:
  total_requests: 150
  total_size_bytes: 2456789
  total_time_ms: 12450.5
  unique_domains: 12
  har_version: 1.2

STATUS CODES:
  200: 120
  304: 20
  404: 8
  500: 2

METHODS:
  GET: 130
  POST: 18
  PUT: 2

TOP DOMAINS:
  api.example.com: 45
  cdn.example.com: 30
  www.example.com: 25
```

#### Export to CSV

```bash
python har_reader.py export-csv file.har output.csv
```

#### Extract Response Bodies

```bash
# Extract all bodies
python har_reader.py extract-bodies file.har output_dir/

# Extract only JSON responses
python har_reader.py extract-bodies file.har output_dir/ --content-type application/json

# Extract only HTML
python har_reader.py extract-bodies file.har output_dir/ --content-type text/html
```

---

## Python API Usage

### Basic Reading

```python
from har_reader import HARReader

# Read a HAR file
reader = HARReader()
har_file = reader.read('path/to/file.har')

# Access basic information
print(f"Total entries: {har_file.total_entries}")
print(f"HAR version: {har_file.version}")
```

### Accessing Entries

```python
# Iterate through all entries
for entry in har_file.entries:
    print(f"Request: {entry.request.method} {entry.request.url}")
    print(f"Response: {entry.response.status} {entry.response.status_text}")
    print(f"Timing: {entry.time}ms")
    print(f"Domain: {entry.domain}")
    print("-" * 60)
```

### Filtering Entries

```python
# Filter by domain
google_entries = har_file.get_entries_by_domain('www.google.com')

# Filter by status code
success_entries = har_file.get_entries_by_status(200)
error_entries = har_file.get_entries_by_status(404)

# Filter by content type
json_entries = har_file.get_entries_by_content_type('application/json')
html_entries = har_file.get_entries_by_content_type('text/html')
```

### Accessing Request Details

```python
entry = har_file.entries[0]

# Request information
print(f"Method: {entry.request.method}")
print(f"URL: {entry.request.url}")
print(f"HTTP Version: {entry.request.http_version}")

# Headers
for header in entry.request.headers:
    print(f"{header['name']}: {header['value']}")

# Get specific header
user_agent = entry.request.get_header('User-Agent')

# Query parameters
for param in entry.request.query_string:
    print(f"{param['name']}: {param['value']}")

# Cookies
for cookie in entry.request.cookies:
    print(f"{cookie['name']}: {cookie['value']}")
```

### Accessing Response Details

```python
# Response information
print(f"Status: {entry.response.status}")
print(f"Status Text: {entry.response.status_text}")
print(f"Content Type: {entry.response.get_header('content-type')}")

# Response headers
for header in entry.response.headers:
    print(f"{header['name']}: {header['value']}")

# Get decoded body
body = entry.response.get_decoded_body()
if body:
    if isinstance(body, bytes):
        print(f"Body size: {len(body)} bytes")
    else:
        print(f"Body: {body[:200]}...")
```

### Timing Information

```python
# Access timing details
timing = entry.timing
print(f"Blocked: {timing.blocked}ms")
print(f"DNS: {timing.dns}ms")
print(f"Connect: {timing.connect}ms")
print(f"Send: {timing.send}ms")
print(f"Wait: {timing.wait}ms")
print(f"Receive: {timing.receive}ms")
print(f"SSL: {timing.ssl}ms")
print(f"Total: {timing.total}ms")
```

### Analysis

```python
# Perform comprehensive analysis
analysis = reader.analyze(har_file)

# Access analysis results
print(f"Total requests: {analysis['summary']['total_requests']}")
print(f"Total size: {analysis['summary']['total_size_bytes']} bytes")
print(f"Total time: {analysis['summary']['total_time_ms']}ms")

# Status code distribution
for status, count in analysis['status_codes'].items():
    print(f"Status {status}: {count} requests")

# Content type distribution
for ct, count in analysis['content_types'].items():
    print(f"{ct}: {count} requests")
```

### Export to CSV

```python
# Export all entries to CSV
reader.export_to_csv('output.csv', har_file)

# The CSV includes:
# - Started DateTime
# - Method
# - URL
# - Domain
# - Status
# - Status Text
# - Content Type
# - Size (bytes)
# - Time (ms)
# - Detailed timing breakdown
```

### Extract Response Bodies

```python
# Extract all response bodies
count = reader.extract_bodies('output_dir', har_file)
print(f"Extracted {count} files")

# Extract only specific content types
count = reader.extract_bodies(
    'output_dir',
    content_type_filter='application/json',
    har_file=har_file
)
print(f"Extracted {count} JSON files")
```

---

## HAR File Format Support

The script supports the standard HAR 1.2 format including:

- **Log Section**: Version, creator, browser, pages, entries
- **Request**: Method, URL, HTTP version, headers, cookies, query string, post data
- **Response**: Status, status text, headers, cookies, content (with encoding)
- **Cache**: Before request, after request
- **Timings**: Blocked, DNS, connect, send, wait, receive, SSL
- **Content Encoding**:
  - Plain text
  - Base64
  - Gzip
  - Deflate

---

## Error Handling

```python
from har_reader import HARReader, HARReadError, HARValidationError

try:
    reader = HARReader()
    har_file = reader.read('file.har')
except HARReadError as e:
    print(f"Failed to read file: {e}")
except HARValidationError as e:
    print(f"Invalid HAR structure: {e}")
except Exception as e:
    print(f"Unexpected error: {e}")
```

---

## Advanced Examples

### Find Slow Requests

```python
reader = HARReader()
har_file = reader.read('file.har')

# Find requests taking more than 1 second
slow_requests = [e for e in har_file.entries if e.time > 1000]

for entry in slow_requests:
    print(f"{entry.request.url} - {entry.time}ms")
```

### Find Large Responses

```python
# Find responses larger than 1MB
large_responses = [
    e for e in har_file.entries 
    if e.response.body_size > 1024 * 1024
]

for entry in large_responses:
    print(f"{entry.request.url} - {entry.response.body_size / 1024 / 1024:.2f}MB")
```

### Extract All API Endpoints

```python
import re

reader = HARReader()
har_file = reader.read('file.har')

api_endpoints = set()
for entry in har_file.entries:
    # Extract API paths (example pattern)
    match = re.search(r'/api/[^?]+', entry.request.url)
    if match:
        api_endpoints.add(match.group())

for endpoint in sorted(api_endpoints):
    print(endpoint)
```

### Compare Two HAR Files

```python
reader = HARReader()
har1 = reader.read('file1.har')
har2 = reader.read('file2.har')

print(f"File 1: {har1.total_entries} entries")
print(f"File 2: {har2.total_entries} entries")

# Compare domains
domains1 = {e.domain for e in har1.entries}
domains2 = {e.domain for e in har2.entries}

print(f"Unique to file 1: {domains1 - domains2}")
print(f"Unique to file 2: {domains2 - domains1}")
```

---

## Performance

- **Memory Efficient**: Processes large HAR files without loading everything into memory
- **Fast Parsing**: Optimized JSON parsing
- **Streaming**: Can handle files with thousands of entries

---

## Limitations

- Only supports HAR 1.2 format (most common)
- Binary content is decoded but not interpreted
- WebSocket entries are not fully parsed (HAR limitation)

---

## Troubleshooting

### "Invalid JSON in HAR file"
- Ensure the file is a valid HAR file
- Check if the file is corrupted
- Try opening in a text editor to verify

### "Failed to decode body"
- The content encoding might be unsupported
- The body might be corrupted
- Try exporting to CSV first to see which entries fail

### Large files take time to process
- This is normal for files with thousands of entries
- Consider filtering during export to reduce output size

---

## License

MIT License - Free to use, modify, and distribute

---

## Support

For issues or questions, please refer to the HAR specification:
http://www.softwareishard.com/blog/har-12-spec/

---

**SIGNÉ:** SOLITAIRE HACK
