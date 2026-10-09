"""Bounded educational experiments, isolated from production AES-256 file workflows."""
import hashlib
import os
import statistics
import time

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from benchmark_service import SIZES, throughput
from crypto_service import MAX_FILE, measured


def flip_bit(value, bit):
    if not isinstance(value, bytes) or type(bit) is not int or not 0 <= bit < len(value)*8:
        raise ValueError('Bit position is outside the input.')
    changed = bytearray(value)
    changed[bit//8] ^= 1 << (bit % 8)
    return bytes(changed)


def bit_distance(a, b):
    if len(a) != len(b):
        raise ValueError('Bit comparisons need equally sized values.')
    return sum((x ^ y).bit_count() for x, y in zip(a, b))


def _block_encrypt(key, block):
    # Single-block AES primitive only. No ECB file workflow and no GCM nonce reuse.
    encryptor = Cipher(algorithms.AES(key), modes.ECB()).encryptor()
    return encryptor.update(block) + encryptor.finalize()


def confusion_diffusion(block, samples=32):
    def work():
        if not isinstance(block, bytes) or len(block) != 16 or type(samples) is not int or not 2 <= samples <= 128:
            raise ValueError('Use one 16-byte block and 2–128 sample positions.')
        key_setup = measured(os.urandom, 32)
        key = key_setup.value
        baseline = measured(_block_encrypt, key, block)
        rows = []
        masks = {}
        for kind, maximum in [('Plaintext bit flip', 127), ('Key bit flip', 255)]:
            for index in range(samples):
                bit = round(index*maximum/(samples-1))
                changed_input = flip_bit(block, bit) if kind == 'Plaintext bit flip' else block
                changed_key = flip_bit(key, bit) if kind == 'Key bit flip' else key
                output = measured(_block_encrypt, changed_key, changed_input)
                changed = bit_distance(baseline.value, output.value)
                rows.append({'experiment':kind, 'flipped_bit':bit, 'changed_output_bits':changed,
                             'changed_percent':changed/128*100, 'encryption_ms':output.seconds*1000})
                if index == 0:
                    masks[kind] = [(x ^ y) >> k & 1 for x, y in zip(baseline.value, output.value) for k in range(8)]
        return {'rows':rows, 'first_trial_masks':masks, 'baseline_hex':baseline.value.hex(),
                'baseline_encryption_seconds':baseline.seconds, 'key_setup_seconds':key_setup.seconds}
    return measured(work)


def aes_length_analysis(sizes=None, repeats=3):
    def work():
        inputs = SIZES if sizes is None else list(sizes)
        if not inputs or len(inputs) > 12 or any(type(n) is not int or not 0 < n <= MAX_FILE for n in inputs) or type(repeats) is not int or not 1 <= repeats <= 5:
            raise ValueError('Invalid analysis sizes or repeat count.')
        rows = []
        for size in inputs:
            data = os.urandom(size)  # Identical bytes for all key sizes at this input size.
            for bits in (128,192,256):
                trials = []
                for _ in range(repeats):
                    setup = measured(lambda: AESGCM(AESGCM.generate_key(bit_length=bits)))
                    nonce = os.urandom(12)  # A fresh nonce and key on every trial.
                    encrypted = measured(setup.value.encrypt, nonce, data, b'CipherVault isolated timing analysis')
                    decrypted = measured(setup.value.decrypt, nonce, encrypted.value, b'CipherVault isolated timing analysis')
                    if decrypted.value != data:
                        raise RuntimeError('AES analysis recovery validation failed.')
                    trials.append({'encrypt_ms':encrypted.seconds*1000, 'decrypt_ms':decrypted.seconds*1000,
                                   'key_setup_ms':setup.seconds*1000,
                                   'encrypt_MB_s':throughput(size, encrypted.seconds),
                                   'decrypt_MB_s':throughput(size, decrypted.seconds)})
                rows.append({'size_bytes':size,'size_KiB':size/1024,'key_bits':bits,'repeats':repeats,
                             **{k:statistics.median(t[k] for t in trials) for k in trials[0]}})
        return {'rows':rows}
    return measured(work)


def password_length_analysis(lengths=None, size=1024*1024, repeats=3):
    """Compare character counts with the production password-to-AES-256 workflow."""
    from crypto_service import encrypt_file, decrypt_file
    import secrets
    import string
    def work():
        counts = [12,16,24,32,64] if lengths is None else list(lengths)
        if (not counts or len(counts)>12 or any(type(n) is not int or not 12<=n<=256 for n in counts)
                or type(size) is not int or not 0<=size<=MAX_FILE
                or type(repeats) is not int or not 1<=repeats<=5):
            raise ValueError('Invalid password lengths, plaintext size or repeat count.')
        data = os.urandom(size)
        rows = []
        for count in counts:
            trials = []
            for _ in range(repeats):
                password = ''.join(secrets.choice(string.ascii_letters+string.digits) for _ in range(count))
                encrypted = encrypt_file(data,password,'analysis.bin')
                decrypted = decrypt_file(encrypted.value['package'],password)
                if decrypted.value['data'] != data:
                    raise RuntimeError('Password length analysis recovery validation failed.')
                trials.append({'encrypt_ms':encrypted.seconds*1000,'decrypt_ms':decrypted.seconds*1000,
                               'aes_encrypt_ms':encrypted.value['aes_seconds']*1000,
                               'aes_decrypt_ms':decrypted.value['aes_seconds']*1000,
                               'encrypt_kdf_ms':encrypted.value['key_setup_seconds']*1000,
                               'decrypt_kdf_ms':decrypted.value['key_setup_seconds']*1000})
            rows.append({'password_characters':count,'key_bits':256,'size_bytes':size,'repeats':repeats,
                         **{k:statistics.median(t[k] for t in trials) for k in trials[0]}})
        return {'rows':rows}
    return measured(work)


def digest_prefix(digest, bits):
    return int.from_bytes(digest, 'big') >> (len(digest)*8-bits)


def _search(property_name, bits, limit, target, original, progress=False):
    """Unique candidate inputs, exact digest/prefix equality, explicit budget exhaustion."""
    start = time.perf_counter()
    namespace = os.urandom(24)
    target_value = digest_prefix(target, bits)
    seen = {}
    hash_seconds = 0.0
    found = False
    witness = None
    trace = [{'attempts':0,'matches':0,'elapsed_ms':(time.perf_counter()-start)*1000}] if progress else []
    step = max(1, limit//20)
    for attempts in range(1, limit+1):
        candidate = namespace + attempts.to_bytes(8, 'big')
        if candidate == original:
            candidate += b'\x00'
        hash_start = time.perf_counter()
        digest = hashlib.sha256(candidate).digest()
        hash_seconds += time.perf_counter()-hash_start
        value = digest_prefix(digest, bits)
        if property_name == 'Collision':
            previous = seen.get(value)
            if previous is not None:
                left, left_digest = previous
                found = left != candidate
            else:
                seen[value] = (candidate, digest)
        else:
            found = value == target_value
            left, left_digest = (original, target) if property_name == 'Second preimage' else (None, target)
        if found:
            witness = {'left_message_hex':left.hex() if left is not None else None,
                       'right_message_hex':candidate.hex(), 'left_digest_hex':left_digest.hex(),
                       'right_digest_hex':digest.hex()}
        if progress and (attempts % step == 0 or attempts == limit or found):
            trace.append({'attempts':attempts,'matches':int(found),'elapsed_ms':(time.perf_counter()-start)*1000})
        if found:
            break
    return {'attempts':attempts, 'found':found, 'seconds':time.perf_counter()-start,
            'hash_seconds':hash_seconds, 'witness':witness,'progress':trace}


def hashing_resistance_analysis(original=b'CipherVault hash analysis', attempts=20_000, repeats=3):
    def work():
        if not isinstance(original, bytes) or len(original) > 4096 or type(attempts) is not int or not 1 <= attempts <= 50_000 or type(repeats) is not int or not 1 <= repeats <= 5:
            raise ValueError('Use at most 4096 input bytes, 1–50,000 attempts and 1–5 repeats.')
        pre_input = os.urandom(32)
        pre_target = measured(lambda: hashlib.sha256(pre_input).digest())
        second_target = measured(lambda: hashlib.sha256(original).digest())
        properties = ['Preimage','Second preimage','Collision']
        full = []
        toy = []
        for kind in properties:
            target = pre_target.value if kind == 'Preimage' else second_target.value
            actual = _search(kind, 256, attempts, target, original, progress=True)
            full.append({'property':kind,'digest_bits':256, **actual})
            for bits in (8,12,16):
                trials = [_search(kind,bits,attempts,target,original) for _ in range(repeats)]
                toy.append({'property':kind,'retained_bits':bits,'budget_per_trial':attempts,'repeats':repeats,
                            'median_attempts_used':statistics.median(t['attempts'] for t in trials),
                            'successes':sum(t['found'] for t in trials),
                            'median_search_ms':statistics.median(t['seconds'] for t in trials)*1000,
                            'median_hash_ms':statistics.median(t['hash_seconds'] for t in trials)*1000,
                            'trials':trials})
        return {'full':full,'toy':toy,'budget':attempts,'target_hash_seconds':pre_target.seconds+second_target.seconds,
                'original_sha256':second_target.value.hex(),
                'theory':[{'property':'Preimage','log2_generic_work':256},
                          {'property':'Second preimage','log2_generic_work':256},
                          {'property':'Collision','log2_generic_work':128}]}
    return measured(work)
