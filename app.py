#!/usr/bin/env python3
"""
HAR Reader Web Application - Flask
===================================

A web application to read, decrypt, and analyze HAR (HTTP Archive) files.
Built with Flask for easy browser-based analysis.

Author: SOLITAIRE HACK
Version: 1.0.0
License: MIT
"""

import atexit
import ipaddress
import logging
import os
import re
import secrets
import shutil
import tempfile
from collections import Counter
from functools import lru_cache
from urllib.parse import urlparse
from flask import Flask, render_template, request, jsonify, send_file, after_this_request
from flask_cors import CORS
import psycopg2
from werkzeug.exceptions import HTTPException
from werkzeug.utils import secure_filename

from env_config import load_local_env
from har_reader import HARReader, HARError, HARReadError, HARValidationError
from har_analyzer import HARAdvancedAnalyzer
from database import AnalysisDatabase

ALLOWED_EXTENSIONS = {'har', 'har.gz', 'json', 'gz'}
KNOWN_APP_EXCEPTIONS = (HARError, OSError, ValueError)
DOMAIN_LABEL_RE = re.compile(r'^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$')
DEFAULT_CORS_ORIGINS = ('http://localhost:5000', 'http://127.0.0.1:5000')


load_local_env()


logger = logging.getLogger(__name__)


class APIError(Exception):
    """Application error with a client-facing status code."""

    def __init__(self, message: str, status_code: int = 400):
        super().__init__(message)
        self.message = message
        self.status_code = status_code


def configure_logging():
    """Configure application logging from environment."""
    level_name = os.getenv('LOG_LEVEL', 'INFO').upper()
    level = getattr(logging, level_name, logging.INFO)
    logging.basicConfig(
        level=level,
        format='%(asctime)s %(levelname)s [%(name)s] %(message)s'
    )


def get_env_int(name: str, default: int, *, minimum: int = 1) -> int:
    """Read an integer environment variable with sane bounds."""
    raw_value = os.getenv(name)
    if raw_value is None:
        return default

    try:
        return max(int(raw_value), minimum)
    except ValueError:
        logger.warning("Invalid integer for %s=%r. Falling back to %s.", name, raw_value, default)
        return default


def get_cors_origins():
    """Return allowed CORS origins from environment or safe local defaults."""
    raw_origins = os.getenv('CORS_ORIGINS')
    if not raw_origins:
        return list(DEFAULT_CORS_ORIGINS)

    origins = [origin.strip() for origin in raw_origins.split(',') if origin.strip()]
    if origins:
        return origins

    logger.warning("CORS_ORIGINS was set but empty after parsing. Falling back to local defaults.")
    return list(DEFAULT_CORS_ORIGINS)


configure_logging()

app = Flask(__name__)
CORS(app, resources={r"/api/*": {"origins": get_cors_origins()}})
app.config['MAX_CONTENT_LENGTH'] = 50 * 1024 * 1024  # 50MB max file size
app.config['UPLOAD_FOLDER'] = tempfile.mkdtemp(prefix='har-reader-')
app.config['SECRET_KEY'] = os.getenv('FLASK_SECRET_KEY') or secrets.token_hex(32)
app.config['INMUX_REQUEST_TIMEOUT'] = get_env_int('INMUX_REQUEST_TIMEOUT', 45, minimum=5)

if not os.getenv('FLASK_SECRET_KEY'):
    logger.warning("FLASK_SECRET_KEY not set. Using an ephemeral development secret key.")


def get_database_url() -> str:
    """Return DATABASE_URL or raise a clear configuration error."""
    database_url = os.getenv('DATABASE_URL')
    if database_url:
        return database_url

    raise RuntimeError(
        "DATABASE_URL environment variable is required. "
        "Set it in Render or your local environment before using database-backed routes."
    )


@lru_cache(maxsize=1)
def get_database() -> AnalysisDatabase:
    """Lazily initialize the PostgreSQL database used by history endpoints."""
    database = AnalysisDatabase(get_database_url())
    logger.info("Database initialized with PostgreSQL")
    return database


def cleanup_upload_folder():
    """Remove the temporary upload directory created for this process."""
    upload_folder = app.config.get('UPLOAD_FOLDER')
    if not upload_folder or not os.path.isdir(upload_folder):
        return

    try:
        shutil.rmtree(upload_folder)
    except OSError:
        logger.warning("Failed to clean upload directory %s during shutdown.", upload_folder, exc_info=True)


atexit.register(cleanup_upload_folder)


def build_error_response(error):
    """Convert known exceptions into API responses."""
    if isinstance(error, (HARError, ValueError)):
        logger.warning("Request failed: %s", error)
        return jsonify({'error': str(error)}), 400

    logger.exception("Filesystem operation failed during request handling.")
    return jsonify({'error': str(error)}), 500


def remove_path(path: str):
    """Delete a file or directory and log failures instead of hiding them."""
    if not path:
        return

    try:
        if os.path.isdir(path):
            shutil.rmtree(path)
        elif os.path.exists(path):
            os.remove(path)
    except OSError:
        logger.warning("Failed to clean temporary path %s.", path, exc_info=True)


def schedule_cleanup(*paths: str):
    """Schedule file-system cleanup after the current request completes."""
    @after_this_request
    def cleanup(response):
        for path in paths:
            remove_path(path)
        return response


def is_valid_ip_address(value: str) -> bool:
    """Return True when value is a valid IP address."""
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def is_valid_cidr(value: str) -> bool:
    """Return True when value is a valid CIDR notation."""
    try:
        ipaddress.ip_network(value, strict=False)
        return True
    except ValueError:
        return False


def is_valid_domain(value: str) -> bool:
    """Validate a public-looking domain name."""
    candidate = value.rstrip('.').lower()
    if not candidate or len(candidate) > 253 or '..' in candidate:
        return False

    labels = candidate.split('.')
    if len(labels) < 2:
        return False

    return all(DOMAIN_LABEL_RE.fullmatch(label) for label in labels)


def is_valid_http_url(value: str) -> bool:
    """Validate a basic HTTP or HTTPS URL with a domain or IP host."""
    try:
        parsed = urlparse(value)
    except ValueError:
        return False

    hostname = parsed.hostname or ''
    if parsed.scheme not in {'http', 'https'} or not parsed.netloc or parsed.username or parsed.password:
        return False

    return is_valid_domain(hostname) or is_valid_ip_address(hostname)


def validate_inmux_target(
    raw_target: str,
    *,
    allow_domain: bool = False,
    allow_ip: bool = False,
    allow_url: bool = False,
    allow_cidr: bool = False,
) -> str:
    """Validate and normalize INMUX input targets."""
    target = (raw_target or '').strip()
    if not target:
        raise APIError('Target is required', 400)

    if allow_url and is_valid_http_url(target):
        return target

    if allow_cidr and is_valid_cidr(target):
        return target

    if allow_ip and is_valid_ip_address(target):
        return target

    if allow_domain and is_valid_domain(target):
        return target.rstrip('.').lower()

    allowed_formats = []
    if allow_domain:
        allowed_formats.append('a valid domain')
    if allow_ip:
        allowed_formats.append('a valid IP address')
    if allow_url:
        allowed_formats.append('a valid HTTP/HTTPS URL')
    if allow_cidr:
        allowed_formats.append('a valid CIDR block')

    expected = ', '.join(allowed_formats) if allowed_formats else 'a valid target'
    raise APIError(f'Invalid target format. Expected {expected}.', 400)


def get_inmux_target(**validation_rules) -> str:
    """Extract and validate the INMUX target from a JSON payload."""
    payload = request.get_json(silent=True) or {}
    return validate_inmux_target(payload.get('target', ''), **validation_rules)


def run_inmux_lookup(method_name: str, **validation_rules):
    """Execute an INMUX lookup after validating its target."""
    target = get_inmux_target(**validation_rules)
    analyzer = HARAdvancedAnalyzer(request_timeout=app.config['INMUX_REQUEST_TIMEOUT'])
    result = getattr(analyzer, method_name)(target)
    if isinstance(result, str) and result.startswith('ERROR:'):
        error_message = result.split('ERROR:', 1)[1].strip()
        status_code = 503 if 'api key' in error_message.lower() else 502
        return jsonify({'error': error_message}), status_code
    return jsonify({'success': True, 'result': result})


@app.errorhandler(APIError)
def handle_api_error(error):
    """Return client errors as JSON."""
    logger.warning("Client error: %s", error.message)
    return jsonify({'error': error.message}), error.status_code


@app.errorhandler(Exception)
def handle_unexpected_error(error):
    """Return consistent JSON responses for uncaught exceptions."""
    if isinstance(error, HTTPException):
        return jsonify({'error': error.description}), error.code

    logger.exception("Unhandled application error.")
    return jsonify({'error': 'Internal server error'}), 500


def allowed_file(filename):
    """Check if file has allowed extension."""
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


@app.route('/')
def index():
    """Render main page."""
    return render_template('index.html')


@app.route('/api/upload', methods=['POST'])
def upload_file():
    """Upload and analyze HAR file."""
    if 'file' not in request.files:
        return jsonify({'error': 'No file provided'}), 400

    file = request.files['file']

    if file.filename == '':
        return jsonify({'error': 'No file selected'}), 400

    if not allowed_file(file.filename):
        return jsonify({'error': 'Invalid file type. Allowed: .har, .har.gz, .json'}), 400

    try:
        # Save uploaded file
        filename = secure_filename(file.filename)
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)
        schedule_cleanup(filepath)

        # Read and analyze HAR file
        reader = HARReader()
        har_file = reader.read(filepath)
        analysis = reader.analyze(har_file)

        # Prepare response data
        entries_data = []
        for entry in har_file.entries[:100]:  # Limit to first 100 for performance
            entries_data.append({
                'method': entry.request.method,
                'url': entry.request.url,
                'domain': entry.domain,
                'status': entry.response.status,
                'status_text': entry.response.status_text,
                'content_type': entry.response.get_header('content-type') or '',
                'size': entry.response.body_size,
                'time': entry.time,
                'started_datetime': entry.started_datetime.isoformat()
            })

        response_data = {
            'success': True,
            'filename': filename,
            'analysis': {
                'summary': analysis['summary'],
                'status_codes': analysis['status_codes'],
                'methods': analysis['methods'],
                'domains': dict(sorted(analysis['domains'].items(), key=lambda x: x[1], reverse=True)[:20]),
                'content_types': dict(sorted(analysis['content_types'].items(), key=lambda x: x[1], reverse=True)[:20])
            },
            'entries': entries_data,
            'total_entries': har_file.total_entries
        }

        return jsonify(response_data)

    except HARReadError as e:
        return jsonify({'error': f'Failed to read file: {str(e)}'}), 400
    except HARValidationError as e:
        return jsonify({'error': f'Invalid HAR structure: {str(e)}'}), 400
    except OSError as e:
        return build_error_response(e)


@app.route('/api/entries', methods=['POST'])
def get_entries():
    """Get filtered entries from HAR file."""
    if 'file' not in request.files:
        return jsonify({'error': 'No file provided'}), 400

    file = request.files['file']

    if file.filename == '' or not allowed_file(file.filename):
        return jsonify({'error': 'Invalid file'}), 400

    try:
        # Get filter parameters
        domain_filter = request.form.get('domain', '')
        status_filter = request.form.get('status', '')
        content_type_filter = request.form.get('content_type', '')
        limit = max(1, min(int(request.form.get('limit', 100)), 1000))
        offset = max(0, int(request.form.get('offset', 0)))

        # Save and read file
        filename = secure_filename(file.filename)
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)
        schedule_cleanup(filepath)

        reader = HARReader()
        har_file = reader.read(filepath)

        # Apply filters
        entries = har_file.entries

        if domain_filter:
            entries = [e for e in entries if e.domain == domain_filter]

        if status_filter:
            try:
                status = int(status_filter)
                entries = [e for e in entries if e.response.status == status]
            except ValueError:
                raise APIError('Invalid status filter. Expected an integer HTTP status code.', 400)

        if content_type_filter:
            entries = [e for e in entries if content_type_filter.lower() in 
                      (e.response.get_header('content-type') or '').lower()]

        # Apply pagination
        total = len(entries)
        entries = entries[offset:offset + limit]

        # Prepare response
        entries_data = []
        for entry in entries:
            entries_data.append({
                'method': entry.request.method,
                'url': entry.request.url,
                'domain': entry.domain,
                'status': entry.response.status,
                'status_text': entry.response.status_text,
                'content_type': entry.response.get_header('content-type') or '',
                'size': entry.response.body_size,
                'time': entry.time,
                'started_datetime': entry.started_datetime.isoformat(),
                'request_headers': entry.request.headers,
                'response_headers': entry.response.headers
            })

        return jsonify({
            'success': True,
            'entries': entries_data,
            'total': total,
            'offset': offset,
            'limit': limit
        })

    except KNOWN_APP_EXCEPTIONS as e:
        return build_error_response(e)


@app.route('/api/export/csv', methods=['POST'])
def export_csv():
    """Export HAR data to CSV."""
    if 'file' not in request.files:
        return jsonify({'error': 'No file provided'}), 400

    file = request.files['file']

    if file.filename == '' or not allowed_file(file.filename):
        return jsonify({'error': 'Invalid file'}), 400

    try:
        # Save and read file
        filename = secure_filename(file.filename)
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)
        schedule_cleanup(filepath)

        reader = HARReader()
        har_file = reader.read(filepath)

        # Generate CSV
        csv_path = os.path.join(app.config['UPLOAD_FOLDER'], f'{filename}.csv')
        reader.export_to_csv(csv_path, har_file)
        schedule_cleanup(csv_path)

        return send_file(csv_path, as_attachment=True, 
                        download_name=f'{filename}.csv',
                        mimetype='text/csv')

    except KNOWN_APP_EXCEPTIONS as e:
        return build_error_response(e)


@app.route('/api/extract/bodies', methods=['POST'])
def extract_bodies():
    """Extract response bodies from HAR file."""
    if 'file' not in request.files:
        return jsonify({'error': 'No file provided'}), 400

    file = request.files['file']

    if file.filename == '' or not allowed_file(file.filename):
        return jsonify({'error': 'Invalid file'}), 400

    try:
        content_type_filter = request.form.get('content_type', '')

        # Save and read file
        filename = secure_filename(file.filename)
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)
        schedule_cleanup(filepath)

        reader = HARReader()
        har_file = reader.read(filepath)

        # Create output directory
        output_dir = os.path.join(app.config['UPLOAD_FOLDER'], f'{filename}_extracted')
        count = reader.extract_bodies(output_dir, content_type_filter, har_file)

        # Create zip file
        import zipfile
        zip_path = os.path.join(app.config['UPLOAD_FOLDER'], f'{filename}_bodies.zip')
        with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
            for root, dirs, files in os.walk(output_dir):
                for file in files:
                    file_path = os.path.join(root, file)
                    arcname = os.path.relpath(file_path, output_dir)
                    zipf.write(file_path, arcname)
        schedule_cleanup(zip_path, output_dir)

        return send_file(zip_path, as_attachment=True,
                        download_name=f'{filename}_bodies.zip',
                        mimetype='application/zip')

    except KNOWN_APP_EXCEPTIONS as e:
        return build_error_response(e)


@app.route('/api/entry/<int:index>', methods=['POST'])
def get_entry_detail(index):
    """Get detailed information for a specific entry."""
    if 'file' not in request.files:
        return jsonify({'error': 'No file provided'}), 400

    file = request.files['file']

    if file.filename == '' or not allowed_file(file.filename):
        return jsonify({'error': 'Invalid file'}), 400

    try:
        # Save and read file
        filename = secure_filename(file.filename)
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)
        schedule_cleanup(filepath)

        reader = HARReader()
        har_file = reader.read(filepath)

        if index < 0 or index >= len(har_file.entries):
            return jsonify({'error': 'Entry index out of range'}), 400

        entry = har_file.entries[index]

        # Get decoded body
        try:
            body = entry.response.get_decoded_body()
            body_preview = body[:1000].decode('utf-8', errors='ignore') if body else ''
        except (AttributeError, TypeError, UnicodeDecodeError, ValueError):
            body_preview = ''

        entry_data = {
            'request': {
                'method': entry.request.method,
                'url': entry.request.url,
                'http_version': entry.request.http_version,
                'headers': entry.request.headers,
                'cookies': entry.request.cookies,
                'query_string': entry.request.query_string,
                'post_data': entry.request.post_data,
                'headers_size': entry.request.headers_size,
                'body_size': entry.request.body_size
            },
            'response': {
                'status': entry.response.status,
                'status_text': entry.response.status_text,
                'http_version': entry.response.http_version,
                'headers': entry.response.headers,
                'cookies': entry.response.cookies,
                'content': entry.response.content,
                'redirect_url': entry.response.redirect_url,
                'headers_size': entry.response.headers_size,
                'body_size': entry.response.body_size,
                'body_preview': body_preview
            },
            'timing': {
                'blocked': entry.timing.blocked,
                'dns': entry.timing.dns,
                'connect': entry.timing.connect,
                'send': entry.timing.send,
                'wait': entry.timing.wait,
                'receive': entry.timing.receive,
                'ssl': entry.timing.ssl,
                'total': entry.timing.total
            },
            'cache': entry.cache,
            'started_datetime': entry.started_datetime.isoformat(),
            'time': entry.time,
            'pageref': entry.pageref,
            'server_ip_address': entry.server_ip_address
        }

        return jsonify({'success': True, 'entry': entry_data})

    except KNOWN_APP_EXCEPTIONS as e:
        return build_error_response(e)


@app.route('/api/analyze/security', methods=['POST'])
def analyze_security():
    """Perform security analysis on HAR file."""
    if 'file' not in request.files:
        return jsonify({'error': 'No file provided'}), 400

    file = request.files['file']
    if file.filename == '' or not allowed_file(file.filename):
        return jsonify({'error': 'Invalid file'}), 400

    try:
        filename = secure_filename(file.filename)
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)
        schedule_cleanup(filepath)

        reader = HARReader()
        har_file = reader.read(filepath)
        analyzer = HARAdvancedAnalyzer()
        security_issues = analyzer.analyze_security(har_file)

        return jsonify({
            'success': True,
            'total_issues': len(security_issues),
            'issues': [
                {
                    'severity': i.severity,
                    'category': i.category,
                    'title': i.title,
                    'description': i.description,
                    'entry_index': i.entry_index,
                    'evidence': i.evidence,
                    'recommendation': i.recommendation
                }
                for i in security_issues
            ]
        })

    except KNOWN_APP_EXCEPTIONS as e:
        return build_error_response(e)


@app.route('/api/analyze/performance', methods=['POST'])
def analyze_performance():
    """Perform performance analysis on HAR file."""
    if 'file' not in request.files:
        return jsonify({'error': 'No file provided'}), 400

    file = request.files['file']
    if file.filename == '' or not allowed_file(file.filename):
        return jsonify({'error': 'Invalid file'}), 400

    try:
        filename = secure_filename(file.filename)
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)
        schedule_cleanup(filepath)

        reader = HARReader()
        har_file = reader.read(filepath)
        analyzer = HARAdvancedAnalyzer()
        performance_issues = analyzer.analyze_performance(har_file)

        return jsonify({
            'success': True,
            'total_issues': len(performance_issues),
            'issues': [
                {
                    'severity': i.severity,
                    'category': i.category,
                    'title': i.title,
                    'description': i.description,
                    'entry_index': i.entry_index,
                    'value': i.value,
                    'threshold': i.threshold,
                    'recommendation': i.recommendation
                }
                for i in performance_issues
            ]
        })

    except KNOWN_APP_EXCEPTIONS as e:
        return build_error_response(e)


@app.route('/api/analyze/patterns', methods=['POST'])
def analyze_patterns():
    """Detect suspicious patterns in HAR file."""
    if 'file' not in request.files:
        return jsonify({'error': 'No file provided'}), 400

    file = request.files['file']
    if file.filename == '' or not allowed_file(file.filename):
        return jsonify({'error': 'Invalid file'}), 400

    try:
        filename = secure_filename(file.filename)
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)
        schedule_cleanup(filepath)

        reader = HARReader()
        har_file = reader.read(filepath)
        analyzer = HARAdvancedAnalyzer()
        pattern_matches = analyzer.detect_patterns(har_file)

        return jsonify({
            'success': True,
            'total_matches': len(pattern_matches),
            'matches': [
                {
                    'pattern_type': m.pattern_type,
                    'description': m.description,
                    'entry_index': m.entry_index,
                    'matched_text': m.matched_text,
                    'context': m.context
                }
                for m in pattern_matches[:200]
            ]
        })

    except KNOWN_APP_EXCEPTIONS as e:
        return build_error_response(e)


@app.route('/api/analyze/full', methods=['POST'])
def analyze_full():
    """Perform complete analysis (security, performance, patterns)."""
    if 'file' not in request.files:
        return jsonify({'error': 'No file provided'}), 400

    file = request.files['file']
    if file.filename == '' or not allowed_file(file.filename):
        return jsonify({'error': 'Invalid file'}), 400

    try:
        filename = secure_filename(file.filename)
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)
        schedule_cleanup(filepath)

        reader = HARReader()
        har_file = reader.read(filepath)
        analyzer = HARAdvancedAnalyzer()
        report = analyzer.generate_report(har_file)

        return jsonify({
            'success': True,
            'report': report
        })

    except KNOWN_APP_EXCEPTIONS as e:
        return build_error_response(e)


@app.route('/api/search', methods=['POST'])
def search_entries():
    """Search for entries in HAR file."""
    if 'file' not in request.files:
        return jsonify({'error': 'No file provided'}), 400

    file = request.files['file']
    if file.filename == '' or not allowed_file(file.filename):
        return jsonify({'error': 'Invalid file'}), 400

    try:
        query = request.form.get('query', '')
        search_type = request.form.get('search_type', 'all')

        filename = secure_filename(file.filename)
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)
        schedule_cleanup(filepath)

        reader = HARReader()
        har_file = reader.read(filepath)
        analyzer = HARAdvancedAnalyzer()
        matches = analyzer.search(har_file, query, search_type)

        # Get matched entries
        matched_entries = []
        for idx in matches[:100]:
            entry = har_file.entries[idx]
            matched_entries.append({
                'index': idx,
                'method': entry.request.method,
                'url': entry.request.url,
                'domain': entry.domain,
                'status': entry.response.status,
                'time': entry.time
            })

        return jsonify({
            'success': True,
            'query': query,
            'search_type': search_type,
            'total_matches': len(matches),
            'entries': matched_entries
        })

    except KNOWN_APP_EXCEPTIONS as e:
        return build_error_response(e)


@app.route('/api/compare', methods=['POST'])
def compare_files():
    """Compare two HAR files."""
    if 'file1' not in request.files or 'file2' not in request.files:
        return jsonify({'error': 'Both files required'}), 400

    file1 = request.files['file1']
    file2 = request.files['file2']

    if file1.filename == '' or file2.filename == '':
        return jsonify({'error': 'Both files required'}), 400

    if not allowed_file(file1.filename) or not allowed_file(file2.filename):
        return jsonify({'error': 'Invalid file type'}), 400

    try:
        filename1 = secure_filename(file1.filename)
        filename2 = secure_filename(file2.filename)
        filepath1 = os.path.join(app.config['UPLOAD_FOLDER'], filename1)
        filepath2 = os.path.join(app.config['UPLOAD_FOLDER'], filename2)
        file1.save(filepath1)
        file2.save(filepath2)
        schedule_cleanup(filepath1, filepath2)

        reader = HARReader()
        har_file1 = reader.read(filepath1)
        har_file2 = reader.read(filepath2)
        analyzer = HARAdvancedAnalyzer()
        comparison = analyzer.compare_har_files(har_file1, har_file2)

        return jsonify({
            'success': True,
            'comparison': comparison
        })

    except KNOWN_APP_EXCEPTIONS as e:
        return build_error_response(e)


@app.route('/api/analyze/domains', methods=['POST'])
def analyze_domains():
    """Analyze unique domains contacted in HAR file."""
    if 'file' not in request.files:
        return jsonify({'error': 'No file provided'}), 400

    file = request.files['file']
    if file.filename == '' or not allowed_file(file.filename):
        return jsonify({'error': 'Invalid file'}), 400

    try:
        filename = secure_filename(file.filename)
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)
        schedule_cleanup(filepath)

        reader = HARReader()
        har_file = reader.read(filepath)
        analyzer = HARAdvancedAnalyzer()
        domains = analyzer.analyze_domains(har_file)

        # Convert DomainInfo objects to dictionaries
        domains_data = {
            domain: {
                'request_count': info.request_count,
                'total_size': info.total_size,
                'avg_response_time': info.avg_response_time,
                'status_codes': info.status_codes,
                'content_types': info.content_types,
                'is_https': info.is_https,
                'first_seen': info.first_seen,
                'last_seen': info.last_seen
            }
            for domain, info in domains.items()
        }

        return jsonify({
            'success': True,
            'total_domains': len(domains),
            'domains': domains_data
        })

    except KNOWN_APP_EXCEPTIONS as e:
        return build_error_response(e)


@app.route('/api/analyze/javascript', methods=['POST'])
def analyze_javascript():
    """Analyze JavaScript code for security vulnerabilities."""
    code = request.form.get('code', '')
    
    if not code:
        return jsonify({'error': 'No JavaScript code provided'}), 400
    
    try:
        analyzer = HARAdvancedAnalyzer()
        vulnerabilities = analyzer.analyze_javascript(code)
        
        # Count vulnerabilities by severity and category
        by_severity = Counter(v.severity for v in vulnerabilities)
        by_category = Counter(v.category for v in vulnerabilities)
        
        return jsonify({
            'success': True,
            'total_vulnerabilities': len(vulnerabilities),
            'by_severity': dict(by_severity),
            'by_category': dict(by_category),
            'vulnerabilities': [
                {
                    'severity': v.severity,
                    'category': v.category,
                    'title': v.title,
                    'description': v.description,
                    'line_number': v.line_number,
                    'code_snippet': v.code_snippet,
                    'recommendation': v.recommendation,
                    'cwe_id': v.cwe_id
                }
                for v in vulnerabilities[:500]  # Limit to 500
            ]
        })
    
    except ValueError as e:
        return build_error_response(e)


@app.route('/api/analyze/network', methods=['POST'])
def analyze_network():
    """Analyze network security issues including SSL/TLS and domain security."""
    if 'file' not in request.files:
        return jsonify({'error': 'No file provided'}), 400

    file = request.files['file']
    if file.filename == '' or not allowed_file(file.filename):
        return jsonify({'error': 'Invalid file'}), 400

    try:
        filename = secure_filename(file.filename)
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)
        schedule_cleanup(filepath)

        reader = HARReader()
        har_file = reader.read(filepath)
        analyzer = HARAdvancedAnalyzer()
        network_issues = analyzer.analyze_network(har_file)
        free_surf_summary = analyzer.summarize_free_internet_issues(network_issues)
        host_proxy_tls_summary = analyzer.summarize_host_proxy_tls_issues(network_issues)

        # Count issues by severity and category
        by_severity = Counter(i.severity for i in network_issues)
        by_category = Counter(i.category for i in network_issues)

        return jsonify({
            'success': True,
            'total_issues': len(network_issues),
            'by_severity': dict(by_severity),
            'by_category': dict(by_category),
            'free_surf': free_surf_summary,
            'host_proxy_tls': host_proxy_tls_summary,
            'issues': [
                {
                    'severity': i.severity,
                    'category': i.category,
                    'title': i.title,
                    'description': i.description,
                    'domain': i.domain,
                    'entry_index': i.entry_index,
                    'evidence': i.evidence,
                    'score': i.score,
                    'confidence': i.confidence,
                    'indicators': i.indicators,
                    'recommendation': i.recommendation,
                    'alert_recipient': i.alert_recipient
                }
                for i in network_issues
            ]
        })

    except KNOWN_APP_EXCEPTIONS as e:
        return build_error_response(e)


@app.route('/api/network/alert-report', methods=['POST'])
def generate_network_alert():
    """Generate a network alert report for notifying network administrators."""
    if 'file' not in request.files:
        return jsonify({'error': 'No file provided'}), 400

    file = request.files['file']
    if file.filename == '' or not allowed_file(file.filename):
        return jsonify({'error': 'Invalid file'}), 400

    try:
        filename = secure_filename(file.filename)
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)
        schedule_cleanup(filepath)

        reader = HARReader()
        har_file = reader.read(filepath)
        analyzer = HARAdvancedAnalyzer()
        network_issues = analyzer.analyze_network(har_file)
        report = analyzer.generate_network_alert_report(network_issues)

        return jsonify({
            'success': True,
            'report': report,
            'total_issues': len(network_issues)
        })

    except KNOWN_APP_EXCEPTIONS as e:
        return build_error_response(e)


@app.route('/api/analyze/ports', methods=['POST'])
def analyze_ports():
    """Analyze ports used in network connections."""
    if 'file' not in request.files:
        return jsonify({'error': 'No file provided'}), 400

    file = request.files['file']
    if file.filename == '' or not allowed_file(file.filename):
        return jsonify({'error': 'Invalid file'}), 400

    try:
        filename = secure_filename(file.filename)
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)
        schedule_cleanup(filepath)

        reader = HARReader()
        har_file = reader.read(filepath)
        analyzer = HARAdvancedAnalyzer()
        ports = analyzer.analyze_ports(har_file)

        # Count ports by security risk
        by_risk = Counter(port.security_risk for port in ports.values())
        suspicious_ports = [p for p in ports.values() if p.is_suspicious]

        return jsonify({
            'success': True,
            'total_ports': len(ports),
            'by_risk': dict(by_risk),
            'suspicious_ports_count': len(suspicious_ports),
            'ports': [
                {
                    'port': p.port,
                    'protocol': p.protocol,
                    'domain': p.domain,
                    'connection_count': p.connection_count,
                    'is_standard': p.is_standard,
                    'is_suspicious': p.is_suspicious,
                    'security_risk': p.security_risk
                }
                for p in ports.values()
            ]
        })

    except KNOWN_APP_EXCEPTIONS as e:
        return build_error_response(e)


@app.route('/api/analyze/user-agents', methods=['POST'])
def analyze_user_agents():
    """Analyze User Agents in network requests."""
    if 'file' not in request.files:
        return jsonify({'error': 'No file provided'}), 400

    file = request.files['file']
    if file.filename == '' or not allowed_file(file.filename):
        return jsonify({'error': 'Invalid file'}), 400

    try:
        filename = secure_filename(file.filename)
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)
        schedule_cleanup(filepath)

        reader = HARReader()
        har_file = reader.read(filepath)
        analyzer = HARAdvancedAnalyzer()
        user_agents = analyzer.analyze_user_agents(har_file)

        # Count user agents by security risk
        by_risk = Counter(ua.security_risk for ua in user_agents.values())
        bots = [ua for ua in user_agents.values() if ua.is_bot]
        suspicious = [ua for ua in user_agents.values() if ua.is_suspicious]

        return jsonify({
            'success': True,
            'total_user_agents': len(user_agents),
            'by_risk': dict(by_risk),
            'bots_count': len(bots),
            'suspicious_count': len(suspicious),
            'user_agents': [
                {
                    'user_agent': ua.user_agent[:200],  # Limit length
                    'connection_count': ua.connection_count,
                    'is_bot': ua.is_bot,
                    'is_suspicious': ua.is_suspicious,
                    'browser': ua.browser,
                    'os': ua.os,
                    'security_risk': ua.security_risk
                }
                for ua in user_agents.values()
            ]
        })

    except KNOWN_APP_EXCEPTIONS as e:
        return build_error_response(e)


@app.route('/api/analyze/network-deep', methods=['POST'])
def analyze_network_deep():
    """Perform deep network analysis including ports and user agents."""
    if 'file' not in request.files:
        return jsonify({'error': 'No file provided'}), 400

    file = request.files['file']
    if file.filename == '' or not allowed_file(file.filename):
        return jsonify({'error': 'Invalid file'}), 400

    try:
        filename = secure_filename(file.filename)
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)
        schedule_cleanup(filepath)

        reader = HARReader()
        har_file = reader.read(filepath)
        analyzer = HARAdvancedAnalyzer()
        
        # Run all network analyses
        network_issues = analyzer.analyze_network(har_file)
        ports = analyzer.analyze_ports(har_file)
        user_agents = analyzer.analyze_user_agents(har_file)
        free_surf_summary = analyzer.summarize_free_internet_issues(network_issues)
        host_proxy_tls_summary = analyzer.summarize_host_proxy_tls_issues(network_issues)
        method_counts = Counter(
            entry.request.method
            for entry in har_file.entries
            if getattr(entry, 'request', None) and getattr(entry.request, 'method', None)
        )

        return jsonify({
            'success': True,
            'network_issues': {
                'total': len(network_issues),
                'by_severity': dict(Counter(i.severity for i in network_issues)),
                'by_category': dict(Counter(i.category for i in network_issues))
            },
            'free_surf': free_surf_summary,
            'host_proxy_tls': host_proxy_tls_summary,
            'http_methods': {
                'total_unique': len(method_counts),
                'by_method': dict(method_counts),
                'methods': [
                    {'method': method, 'count': count}
                    for method, count in sorted(method_counts.items(), key=lambda item: (-item[1], item[0]))
                ]
            },
            'ports': {
                'total': len(ports),
                'suspicious': sum(1 for p in ports.values() if p.is_suspicious),
                'by_risk': dict(Counter(p.security_risk for p in ports.values())),
                'observation_scope': 'observed_in_har_only',
                'note': 'Le HAR confirme les ports réellement utilisés par le trafic capturé, pas les ports fermés du réseau.',
                'details': [
                    {
                        'port': p.port,
                        'protocol': p.protocol,
                        'domain': p.domain,
                        'connection_count': p.connection_count,
                        'is_standard': p.is_standard,
                        'is_suspicious': p.is_suspicious,
                        'security_risk': p.security_risk
                    }
                    for p in sorted(ports.values(), key=lambda port: (-port.connection_count, port.port))
                ]
            },
            'user_agents': {
                'total': len(user_agents),
                'bots': sum(1 for ua in user_agents.values() if ua.is_bot),
                'suspicious': sum(1 for ua in user_agents.values() if ua.is_suspicious),
                'by_risk': dict(Counter(ua.security_risk for ua in user_agents.values()))
            }
        })

    except KNOWN_APP_EXCEPTIONS as e:
        return build_error_response(e)


@app.route('/api/inmux/dns', methods=['POST'])
def inmux_dns():
    """DNS lookup using HackerTarget API."""
    return run_inmux_lookup('dns_lookup', allow_domain=True, allow_ip=True)


@app.route('/api/inmux/reverse-dns', methods=['POST'])
def inmux_reverse_dns():
    """Reverse DNS lookup using HackerTarget API."""
    return run_inmux_lookup('reverse_dns_lookup', allow_domain=True, allow_ip=True, allow_cidr=True)


@app.route('/api/inmux/whois', methods=['POST'])
def inmux_whois():
    """Whois lookup using HackerTarget API."""
    return run_inmux_lookup('whois_lookup', allow_domain=True, allow_ip=True)


@app.route('/api/inmux/geoip', methods=['POST'])
def inmux_geoip():
    """GeoIP lookup using HackerTarget API."""
    return run_inmux_lookup('geoip_lookup', allow_domain=True, allow_ip=True)


@app.route('/api/inmux/host-finder', methods=['POST'])
def inmux_host_finder():
    """Host finder using HackerTarget API."""
    return run_inmux_lookup('host_finder', allow_domain=True)


@app.route('/api/inmux/http-headers', methods=['POST'])
def inmux_http_headers():
    """HTTP headers lookup using HackerTarget API."""
    return run_inmux_lookup('http_headers', allow_domain=True, allow_url=True)


@app.route('/api/inmux/host-dns', methods=['POST'])
def inmux_host_dns():
    """Host DNS finder using HackerTarget API."""
    return run_inmux_lookup('host_dns_finder', allow_domain=True)


@app.route('/api/inmux/port-scan', methods=['POST'])
def inmux_port_scan():
    """Port scan using HackerTarget API."""
    return run_inmux_lookup('port_scan', allow_domain=True, allow_ip=True)


@app.route('/api/inmux/subnet', methods=['POST'])
def inmux_subnet():
    """Subnet lookup using HackerTarget API."""
    return run_inmux_lookup('subnet_lookup', allow_ip=True, allow_cidr=True)


@app.route('/api/inmux/zone-transfer', methods=['POST'])
def inmux_zone_transfer():
    """Zone transfer using HackerTarget API."""
    return run_inmux_lookup('zone_transfer', allow_domain=True)


@app.route('/api/inmux/extract-links', methods=['POST'])
def inmux_extract_links():
    """Extract links using HackerTarget API."""
    return run_inmux_lookup('extract_links', allow_domain=True, allow_url=True)


@app.route('/api/inmux/active-port-scan', methods=['POST'])
def inmux_active_port_scan():
    """Active port scan using HackerTarget API (requires API key)."""
    return run_inmux_lookup('active_port_scan', allow_domain=True, allow_ip=True)


@app.route('/api/inmux/active-port-scan-african', methods=['POST'])
def inmux_active_port_scan_african():
    """African-focused active port scan using HackerTarget API (requires API key)."""
    target = get_inmux_target(allow_domain=True, allow_ip=True)
    
    try:
        analyzer = HARAdvancedAnalyzer(request_timeout=app.config['INMUX_REQUEST_TIMEOUT'])
        result = analyzer.active_port_scan_african(target)
        
        if isinstance(result, dict) and 'error' in result:
            return jsonify({'error': result['error']}), 500
            
        return jsonify({'success': True, 'result': result})
    except Exception as e:
        logger.exception("African port scan failed")
        return jsonify({'error': str(e)}), 500


@app.errorhandler(413)
def request_entity_too_large(error):
    """Handle file too large error."""
    return jsonify({'error': 'File too large. Maximum size is 50MB'}), 413


@app.errorhandler(500)
def internal_error(error):
    """Handle internal server error."""
    return jsonify({'error': 'Internal server error'}), 500


# ==================== HISTORY ENDPOINTS ====================

@app.route('/api/history/save', methods=['POST'])
def save_analysis_history():
    """Save the current analysis to the database."""
    try:
        data = request.get_json()
        if not data:
            raise ValueError("No data provided")
        
        filename = data.get('filename')
        file_size = data.get('file_size', 0)
        analysis_data = data.get('analysis_data')
        metadata = data.get('metadata')
        
        if not filename or not analysis_data:
            raise ValueError("filename and analysis_data are required")
        
        analysis_id = get_database().save_analysis(filename, file_size, analysis_data, metadata)
        return jsonify({'success': True, 'analysis_id': analysis_id})
    except ValueError as e:
        logger.error(f"Failed to save analysis: {e}")
        return jsonify({'error': str(e)}), 400
    except (RuntimeError, psycopg2.Error) as e:
        logger.error(f"Failed to save analysis: {e}")
        return jsonify({'error': str(e)}), 500
    except Exception as e:
        logger.exception("Unexpected error saving analysis")
        return jsonify({'error': str(e)}), 500


@app.route('/api/history/list', methods=['GET'])
def get_analysis_history():
    """Get the list of all saved analyses."""
    try:
        limit = request.args.get('limit', 50, type=int)
        database = get_database()
        analyses = database.get_all_analyses(limit)
        stats = database.get_statistics()
        return jsonify({'success': True, 'analyses': analyses, 'statistics': stats})
    except (RuntimeError, psycopg2.Error) as e:
        logger.error(f"Failed to get history: {e}")
        return jsonify({'error': str(e)}), 500
    except Exception as e:
        logger.exception("Unexpected error getting history")
        return jsonify({'error': str(e)}), 500


@app.route('/api/history/<int:analysis_id>', methods=['GET'])
def get_analysis_by_id(analysis_id):
    """Get a specific analysis by ID."""
    try:
        analysis = get_database().get_analysis(analysis_id)
        if not analysis:
            return jsonify({'error': 'Analysis not found'}), 404
        return jsonify({'success': True, 'analysis': analysis})
    except (RuntimeError, psycopg2.Error) as e:
        logger.error(f"Failed to get analysis {analysis_id}: {e}")
        return jsonify({'error': str(e)}), 500
    except Exception as e:
        logger.exception("Unexpected error getting analysis")
        return jsonify({'error': str(e)}), 500


@app.route('/api/history/<int:analysis_id>', methods=['DELETE'])
def delete_analysis_by_id(analysis_id):
    """Delete a specific analysis by ID."""
    try:
        deleted = get_database().delete_analysis(analysis_id)
        if not deleted:
            return jsonify({'error': 'Analysis not found'}), 404
        return jsonify({'success': True, 'message': 'Analysis deleted'})
    except (RuntimeError, psycopg2.Error) as e:
        logger.error(f"Failed to delete analysis {analysis_id}: {e}")
        return jsonify({'error': str(e)}), 500
    except Exception as e:
        logger.exception("Unexpected error deleting analysis")
        return jsonify({'error': str(e)}), 500


@app.route('/api/history/search', methods=['GET'])
def search_analyses():
    """Search analyses by filename."""
    try:
        query = request.args.get('query', '')
        limit = request.args.get('limit', 50, type=int)
        analyses = get_database().search_analyses(query, limit)
        return jsonify({'success': True, 'analyses': analyses})
    except (RuntimeError, psycopg2.Error) as e:
        logger.error(f"Failed to search analyses: {e}")
        return jsonify({'error': str(e)}), 500
    except Exception as e:
        logger.exception("Unexpected error searching analyses")
        return jsonify({'error': str(e)}), 500


if __name__ == '__main__':
    try:
        get_database()
    except (RuntimeError, ValueError, psycopg2.Error) as error:
        raise SystemExit(f"Database startup check failed: {error}") from error

    print("=" * 60)
    print("HAR Reader Web Application")
    print("=" * 60)
    print("Starting Flask server...")
    print("Open your browser to: http://localhost:5000")
    print("=" * 60)
    app.run(debug=True, host='0.0.0.0', port=5000)
