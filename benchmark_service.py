"""Actual median measurements; password KDF and RSA setup excluded from curves."""
import hashlib
import os
import statistics
import time
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from crypto_service import MAX_FILE, generate_keys, hash_file, measured, sign_file, verify_file

SIZES = [1024, 10*1024, 100*1024, 1024*1024, 5*1024*1024, 10*1024*1024]


def throughput(size, seconds):
    return size / 1_000_000 / seconds if seconds > 0 else 0.0


def run_benchmarks(sizes=None, repeats=3):
    start = time.perf_counter()
    sizes = SIZES if sizes is None else list(sizes)
    if not sizes or len(sizes) > 12 or any(type(s) is not int or not 0 <= s <= MAX_FILE for s in sizes) or not 1 <= repeats <= 5:
        raise ValueError('Invalid benchmark sizes or repeat count.')
    keys = generate_keys()
    rows = []
    for size in sizes:
        data = os.urandom(size)
        trials = []
        for _ in range(repeats):
            aes = AESGCM(AESGCM.generate_key(bit_length=256))
            nonce = os.urandom(12)
            enc = measured(aes.encrypt, nonce, data, None)
            dec = measured(aes.decrypt, nonce, enc.value, None)
            digest = hash_file(data)
            signed = sign_file(data, keys.value)
            verified = verify_file(data, signed['signature'], keys.value.public_key())
            if dec.value != data or digest.value != hashlib.sha256(data).hexdigest() or not verified['valid']:
                raise RuntimeError('Benchmark correctness check failed.')
            trials.append({'aes_encrypt_ms': enc.seconds*1000, 'aes_decrypt_ms': dec.seconds*1000,
                           'sha256_ms': digest.seconds*1000, 'rsa_sign_ms': signed['sign_seconds']*1000,
                           'rsa_verify_ms': verified['verify_seconds']*1000,
                           'rsa_sign_hash_ms': signed['hash_seconds']*1000,
                           'rsa_verify_hash_ms': verified['hash_seconds']*1000,
                           'aes_encrypt_MB_s': throughput(size, enc.seconds),
                           'aes_decrypt_MB_s': throughput(size, dec.seconds),
                           'sha256_MB_s': throughput(size, digest.seconds)})
        rows.append({'size_bytes': size, 'size_KiB': size/1024, 'repeats': repeats,
                     **{k: statistics.median(t[k] for t in trials) for k in trials[0]}})
    return {'rows': rows, 'key_generation_seconds': keys.seconds,
            'total_seconds': time.perf_counter()-start}
