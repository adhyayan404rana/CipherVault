"""On-demand HTTPS receiver; single-use capabilities and browser-side decryption."""
import datetime
import base64
import hashlib
import ipaddress
import json
import math
import re
import secrets
import socket
import ssl
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from crypto_service import parse_package, measured, generate_keys, sign_file


def lan_ipv4():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.connect(('192.0.2.1', 80))  # Routing lookup, no packet is sent.
        return sock.getsockname()[0]
    except OSError:
        return '127.0.0.1'
    finally:
        sock.close()


class TransferService:
    def __init__(self, host='127.0.0.1', port=0, lan_ip=None):
        self.lock = threading.Lock()
        self.pending = {}
        self.receipts = {}
        self.last_result = None
        self.temp = tempfile.TemporaryDirectory(prefix='ciphervault-')
        self.lan_ip = str(ipaddress.IPv4Address(lan_ip or lan_ipv4()))
        self.setup = measured(self._certificate)
        self.signing_setup = generate_keys()
        self._signing_key = self.signing_setup.value
        self.signing_public = self._signing_key.public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
        self.signing_fingerprint = hashlib.sha256(self.signing_public).hexdigest()
        self.last_proof = None
        service = self

        class Handler(BaseHTTPRequestHandler):
            def setup(self):
                super().setup()
                self.connection.settimeout(15)

            def log_message(self, *args):
                pass

            def reply(self, code, body, kind='application/json', extra=None):
                self.send_response(code)
                self.send_header('Content-Type', kind)
                self.send_header('Content-Length', str(len(body)))
                self.send_header('Cache-Control', 'no-store')
                self.send_header('Referrer-Policy', 'no-referrer')
                self.send_header('X-Content-Type-Options', 'nosniff')
                self.send_header('Content-Security-Policy', "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; form-action 'none'; base-uri 'none'; frame-ancestors 'none'")
                for k, v in (extra or {}).items():
                    self.send_header(k, v)
                self.end_headers()
                self.wfile.write(body)

            def do_GET(self):
                assets = {'/': ('receiver.html', 'text/html; charset=utf-8'),
                          '/receiver.js': ('receiver.js','text/javascript; charset=utf-8'),
                          '/receiver.css': ('receiver.css','text/css; charset=utf-8')}
                if self.path not in assets:
                    self.reply(404, b'{"error":"Not found"}')
                    return
                name, kind = assets[self.path]
                self.reply(200, (Path(__file__).parent / 'receiver' / name).read_bytes(), kind)

            def do_POST(self):
                if self.headers.get('Transfer-Encoding'):
                    self.reply(400, b'{"error":"Unsupported request encoding"}')
                    return
                try:
                    size = int(self.headers.get('Content-Length', '-1'))
                except ValueError:
                    size = -1
                if not 0 <= size <= 2048:
                    self.reply(413, b'{"error":"Invalid request size"}')
                    return
                token = self.headers.get('Authorization', '').removeprefix('Bearer ')
                if len(token) != 43:
                    self.reply(403, b'{"error":"Unauthorized"}')
                    return
                if self.path == '/claim':
                    if size != 0:
                        self.reply(400, b'{"error":"Expected empty request"}')
                        return
                    with service.lock:
                        service._purge()
                        entry = service.pending.pop(token, None)
                        if entry is not None:
                            receipt = secrets.token_urlsafe(32)
                            service.receipts[receipt] = entry
                    if entry is None:
                        self.reply(403, b'{"error":"Token invalid, expired or already used"}')
                        return
                    start = time.perf_counter()
                    try:
                        self.reply(200, entry['package'], 'application/octet-stream',
                                   {'X-Receipt-Token': receipt})
                        self.wfile.flush()
                    except (OSError, TimeoutError):
                        with service.lock:
                            service.receipts.pop(receipt, None)
                        return
                    with service.lock:
                        entry['server_write_seconds'] = time.perf_counter() - start
                    return
                if self.path == '/proof':
                    with service.lock:
                        service._purge()
                        entry = service.receipts.get(token)
                    if entry is None:
                        self.reply(403, b'{"error":"Unauthorized or expired proof"}')
                    elif size != 0:
                        self.reply(400, b'{"error":"Expected empty request"}')
                    else:
                        self.reply(200,json.dumps(entry['proof']).encode())
                    return
                if self.path == '/receipt':
                    with service.lock:
                        service._purge()
                        entry = service.receipts.get(token)
                    if entry is None:
                        self.reply(403, b'{"error":"Unauthorized or expired receipt"}')
                        return
                    try:
                        report = json.loads(self.rfile.read(size))
                        fields = {'sha256','network_seconds','decrypt_seconds','hash_seconds','receive_seconds'}
                        optional = {'signature_valid','signature_seconds','received_at'}
                        if not isinstance(report, dict) or not fields <= set(report) or set(report)-fields-optional or not isinstance(report['sha256'], str) or re.fullmatch('[0-9a-f]{64}', report['sha256']) is None:
                            raise ValueError()
                        if any(type(report[k]) not in (int, float) or not math.isfinite(report[k]) or not 0 <= report[k] <= 3600 for k in fields - {'sha256'}):
                            raise ValueError()
                        if ('signature_valid' in report) != ('signature_seconds' in report):
                            raise ValueError()
                        if 'signature_valid' in report and (type(report['signature_valid']) is not bool or type(report.get('signature_seconds')) not in (int,float) or not math.isfinite(report['signature_seconds']) or not 0 <= report['signature_seconds'] <= 3600):
                            raise ValueError()
                        if 'received_at' in report:
                            if not isinstance(report['received_at'],str) or len(report['received_at'])>40:
                                raise ValueError()
                            datetime.datetime.fromisoformat(report['received_at'].replace('Z','+00:00'))
                    except (ValueError, TypeError, UnicodeError):
                        self.reply(400, b'{"error":"Invalid receipt"}')
                        return
                    with service.lock:
                        if service.receipts.pop(token, None) is None:
                            self.reply(403, b'{"error":"Receipt already consumed"}')
                            return
                        service.last_result = {**report, 'hash_matches': secrets.compare_digest(report['sha256'], entry['sha256']),
                                               'size_bytes': entry['size'], 'package_bytes': len(entry['package']),
                                               'encryption_seconds': entry['encryption_seconds'],
                                               'published_at': entry['published_at'],
                                               'receipt_at': datetime.datetime.now(datetime.timezone.utc).isoformat(),
                                               'original_sha256': entry['sha256'],
                                               'active_total_seconds': entry['encryption_seconds'] + report['receive_seconds'] + entry['proof']['sign_seconds'] + entry['proof']['hash_seconds'] + entry['proof']['package_hash_seconds'],
                                               'wall_total_seconds': time.perf_counter() - entry['start'],
                                               'server_write_seconds': entry.get('server_write_seconds')}
                    self.reply(200, b'{"ok":true}')
                    return
                self.reply(404, b'{"error":"Not found"}')

        try:
            self.server = ThreadingHTTPServer((host, port), Handler)
            self.server.daemon_threads = True
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.minimum_version = ssl.TLSVersion.TLSv1_2
            context.load_cert_chain(str(Path(self.temp.name)/'cert.pem'), str(Path(self.temp.name)/'key.pem'),
                                    password=self._tls_password)
            del self._tls_password
            self.server.socket = context.wrap_socket(self.server.socket, server_side=True)
            self.port = self.server.server_port
            self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
            self.thread.start()
        except Exception:
            if hasattr(self, 'server'):
                self.server.server_close()
            self.temp.cleanup()
            raise

    def _certificate(self):
        key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'CipherVault local demo')])
        now = datetime.datetime.now(datetime.timezone.utc)
        cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
                .serial_number(x509.random_serial_number()).not_valid_before(now-datetime.timedelta(minutes=5))
                .not_valid_after(now+datetime.timedelta(days=2))
                .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
                .add_extension(x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address('127.0.0.1')),
                                                          x509.IPAddress(ipaddress.ip_address(self.lan_ip)),
                                                          x509.DNSName('localhost')]), critical=False)
                .sign(key, hashes.SHA256()))
        self.certificate = cert.public_bytes(serialization.Encoding.PEM)
        self.fingerprint = cert.fingerprint(hashes.SHA256()).hex()
        self._tls_password = secrets.token_urlsafe(32)
        (Path(self.temp.name)/'cert.pem').write_bytes(self.certificate)
        (Path(self.temp.name)/'key.pem').write_bytes(key.private_bytes(serialization.Encoding.PEM,
                                       serialization.PrivateFormat.PKCS8,
                                       serialization.BestAvailableEncryption(self._tls_password.encode())))

    @property
    def certificate_path(self):
        return str(Path(self.temp.name)/'cert.pem')

    def _purge(self):
        now = time.monotonic()
        for store in (self.pending, self.receipts):
            for token in list(store):
                if store[token]['expiry'] <= now:
                    del store[token]

    def publish(self, package, encryption_seconds, ttl=300, start=None):
        meta, *_ = parse_package(package)
        if meta['kdf'] != 'PBKDF2-SHA256':
            raise ValueError('The browser transfer receiver requires a password-based package.')
        if not 1 <= ttl <= 600 or not math.isfinite(encryption_seconds) or encryption_seconds < 0:
            raise ValueError('Invalid transfer lifetime or timing.')
        token = secrets.token_urlsafe(32)
        published_at = datetime.datetime.now(datetime.timezone.utc).isoformat()
        package_hash = measured(lambda: hashlib.sha256(package).hexdigest())
        message = json.dumps({'package_sha256':package_hash.value,'original_sha256':meta['sha256'],
                              'filename':meta['filename'],'published_at':published_at},
                             sort_keys=True,separators=(',',':')).encode()
        signed = sign_file(message,self._signing_key)
        proof = {'message':base64.b64encode(message).decode(),
                 'signature':base64.b64encode(signed['signature']).decode(),
                 'public_key':base64.b64encode(self.signing_public).decode(),
                 'salt_length':350,'sign_seconds':signed['sign_seconds'],
                 'hash_seconds':signed['hash_seconds'], 'package_hash_seconds':package_hash.seconds}
        with self.lock:
            # One outstanding transfer per server. Publishing revokes earlier capabilities.
            self.pending.clear()
            self.receipts.clear()
            self.last_result = None
            self.last_proof = proof
            self.pending[token] = {'package': package, 'sha256': meta['sha256'], 'size': meta['size'],
                                   'encryption_seconds': encryption_seconds,
                                   'proof':proof,'published_at':published_at,
                                   'expiry': time.monotonic()+ttl,
                                   'start': start if start is not None else time.perf_counter()}
        return token

    def status(self):
        with self.lock:
            self._purge()
            return dict(self.last_result) if self.last_result else None

    def stop(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)
        with self.lock:
            self.pending.clear()
            self.receipts.clear()
            self.last_proof = None
        self.temp.cleanup()
