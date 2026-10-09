"""Versioned, authenticated AES packages and timed cryptographic operations."""
import base64
import hashlib
import json
import os
import re
import struct
import time
from dataclasses import dataclass

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa, utils
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

MAX_FILE = 20 * 1024 * 1024
MAX_PACKAGE = MAX_FILE + 4096
ITERATIONS = 600_000
MAGIC = b'CVLT1'


@dataclass
class Result:
    value: object
    seconds: float


class OperationError(ValueError):
    def __init__(self, message, seconds=0):
        super().__init__(message)
        self.seconds = seconds


def measured(fn, *args, **kwargs):
    start = time.perf_counter()
    try:
        return Result(fn(*args, **kwargs), time.perf_counter() - start)
    except Exception as exc:
        raise OperationError(str(exc), time.perf_counter() - start) from exc


def safe_filename(name):
    name = str(name).replace('\\', '/').split('/')[-1]
    name = re.sub(r'[^A-Za-z0-9._ -]', '_', name).strip(' .')[:120]
    if not name or name.split('.')[0].upper() in {'CON', 'PRN', 'AUX', 'NUL', *(f'COM{i}' for i in range(10)), *(f'LPT{i}' for i in range(10))}:
        return 'file.bin'
    return name


def check_data(data):
    if not isinstance(data, bytes) or len(data) > MAX_FILE:
        raise ValueError('Input must be bytes and at most 20 MiB.')


def derive_key(password, salt):
    if not isinstance(password, str) or not 12 <= len(password) <= 1024:
        raise ValueError('Use a password of 12–1024 characters.')
    return PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt,
                     iterations=ITERATIONS).derive(password.encode('utf-8'))


def hash_file(data):
    def work():
        check_data(data)
        return hashlib.sha256(data).hexdigest()
    return measured(work)


def compare_files(a, b):
    def work():
        check_data(a)
        check_data(b)
        ha, hb = hash_file(a), hash_file(b)
        return {'first': ha, 'second': hb, 'hash_equal': ha.value == hb.value,
                'bytes_equal': a == b}
    return measured(work)


def validate_aes_key(key):
    if not isinstance(key, bytes) or len(key) != 32:
        raise ValueError('An AES-256 key file must contain exactly 32 raw bytes.')
    return key


def encrypt_file(data, password=None, filename='file.bin', *, key=None):
    def work():
        check_data(data)
        if key is not None:
            if password is not None:
                raise ValueError('Choose a password or a key file, not both.')
            salt = b''
            setup = measured(validate_aes_key,key)
            kdf, iterations = 'RAW-KEY', 0
        else:
            salt = os.urandom(16)
            setup = measured(derive_key,password,salt)
            kdf, iterations = 'PBKDF2-SHA256', ITERATIONS
        nonce = os.urandom(12)
        digest = hash_file(data)
        meta = {'version': 1, 'algorithm': 'AES-256-GCM', 'kdf': kdf,
                'iterations': iterations, 'salt': base64.b64encode(salt).decode(),
                'nonce': base64.b64encode(nonce).decode(), 'filename': safe_filename(filename),
                'size': len(data), 'sha256': digest.value}
        header = json.dumps(meta, sort_keys=True, separators=(',', ':')).encode()
        aad = MAGIC + struct.pack('>I', len(header)) + header
        aes = measured(AESGCM(setup.value).encrypt, nonce, data, aad)
        return {'package': aad + aes.value, 'metadata': meta, 'aes_seconds': aes.seconds,
                'hash_seconds': digest.seconds, 'key_setup_seconds':setup.seconds}
    return measured(work)


def parse_package(package):
    if not isinstance(package, bytes) or not 25 <= len(package) <= MAX_PACKAGE or package[:5] != MAGIC:
        raise ValueError('Invalid CipherVault package or size limit exceeded.')
    length = struct.unpack('>I', package[5:9])[0]
    if not 1 <= length <= 2048 or len(package) < 9 + length + 16:
        raise ValueError('Invalid metadata length.')
    try:
        def unique(pairs):
            d = {}
            for k, v in pairs:
                if k in d:
                    raise ValueError('Duplicate metadata field.')
                d[k] = v
            return d
        meta = json.loads(package[9:9+length], object_pairs_hook=unique)
        expected = {'version','algorithm','kdf','iterations','salt','nonce','filename','size','sha256'}
        if not isinstance(meta, dict) or set(meta) != expected:
            raise ValueError('Unexpected metadata fields.')
        if type(meta['version']) is not int or meta['version'] != 1 or meta['algorithm'] != 'AES-256-GCM' or meta['kdf'] not in ('PBKDF2-SHA256','RAW-KEY') or type(meta['iterations']) is not int:
            raise ValueError('Unsupported format or KDF parameters.')
        salt = base64.b64decode(meta['salt'], validate=True)
        nonce = base64.b64decode(meta['nonce'], validate=True)
        if (meta['kdf'] == 'PBKDF2-SHA256' and (len(salt) != 16 or meta['iterations'] != ITERATIONS)) or (meta['kdf'] == 'RAW-KEY' and (len(salt) != 0 or meta['iterations'] != 0)):
            raise ValueError('Invalid KDF parameters.')
        if len(nonce) != 12:
            raise ValueError('Invalid salt or nonce.')
        if type(meta['size']) is not int or not 0 <= meta['size'] <= MAX_FILE or len(package) != 9 + length + meta['size'] + 16:
            raise ValueError('Invalid payload size.')
        if not isinstance(meta['filename'], str) or meta['filename'] != safe_filename(meta['filename']):
            raise ValueError('Unsafe filename.')
        if not isinstance(meta['sha256'], str) or re.fullmatch('[0-9a-f]{64}', meta['sha256']) is None:
            raise ValueError('Invalid digest.')
    except (TypeError, KeyError, UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError('Malformed metadata.') from exc
    return meta, salt, nonce, package[:9+length], package[9+length:]


def decrypt_file(package, password=None, *, key=None):
    def work():
        meta, salt, nonce, aad, ciphertext = parse_package(package)
        if meta['kdf'] == 'RAW-KEY':
            if password is not None:
                raise ValueError('This package requires its AES key file, not a password.')
            setup = measured(validate_aes_key,key)
        else:
            if key is not None:
                raise ValueError('This package requires its original password, not a key file.')
            setup = measured(derive_key,password,salt)
        try:
            aes = measured(AESGCM(setup.value).decrypt, nonce, ciphertext, aad)
        except OperationError as exc:
            if isinstance(exc.__cause__, InvalidTag):
                raise ValueError('Authentication failed: wrong password/key file or modified package.') from exc
            raise
        digest = hash_file(aes.value)
        if digest.value != meta['sha256']:
            raise ValueError('Authenticated metadata hash does not match recovered bytes.')
        return {'data': aes.value, 'metadata': meta, 'aes_seconds': aes.seconds,
                'hash_seconds': digest.seconds, 'sha256': digest.value, 'key_setup_seconds':setup.seconds}
    return measured(work)


def generate_keys():
    return measured(rsa.generate_private_key, public_exponent=65537, key_size=3072)


def public_pem(key):
    return key.public_key().public_bytes(serialization.Encoding.PEM,
                                       serialization.PublicFormat.SubjectPublicKeyInfo)


def private_pem(key, password):
    if len(password) < 12:
        raise ValueError('Private-key export password must have at least 12 characters.')
    return measured(key.private_bytes, serialization.Encoding.PEM,
                    serialization.PrivateFormat.PKCS8,
                    serialization.BestAvailableEncryption(password.encode()))


def load_public(pem):
    if len(pem) > 8192:
        raise ValueError('Public key too large.')
    key = serialization.load_pem_public_key(pem)
    if not isinstance(key, rsa.RSAPublicKey) or not 2048 <= key.key_size <= 4096:
        raise ValueError('Expected a 2048–4096-bit RSA public key.')
    return key


def sign_file(data, key):
    check_data(data)
    digest = measured(lambda: hashlib.sha256(data).digest())
    sign = measured(key.sign, digest.value,
                    padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
                    utils.Prehashed(hashes.SHA256()))
    return {'signature': sign.value, 'hash_seconds': digest.seconds, 'sign_seconds': sign.seconds}


def verify_file(data, signature, key):
    check_data(data)
    if len(signature) > 512:
        raise ValueError('Invalid RSA signature size.')
    digest = measured(lambda: hashlib.sha256(data).digest())
    def work():
        try:
            key.verify(signature, digest.value,
                       padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
                       utils.Prehashed(hashes.SHA256()))
            return True
        except InvalidSignature:
            return False
    verify = measured(work)
    return {'valid': verify.value, 'hash_seconds': digest.seconds, 'verify_seconds': verify.seconds}


def avalanche(block, bit):
    def work():
        if len(block) != 16 or not 0 <= bit < 128:
            raise ValueError('Use exactly 16 bytes and a bit index from 0 to 127.')
        other = bytearray(block)
        other[bit // 8] ^= 1 << (bit % 8)
        key = os.urandom(32)
        def one(value):
            encryptor = Cipher(algorithms.AES(key), modes.ECB()).encryptor()
            return encryptor.update(value) + encryptor.finalize()
        a, b = one(block), one(bytes(other))
        changed = sum((x ^ y).bit_count() for x, y in zip(a, b))
        return {'original': a.hex(), 'modified': b.hex(), 'changed': changed,
                'percentage': changed / 128 * 100}
    return measured(work)
