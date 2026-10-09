import hashlib
import struct
import pytest
from cryptography.hazmat.primitives import serialization
import crypto_service as c

PASSWORD = 'a separate strong test password'


@pytest.mark.parametrize('data', [b'', b'hello CipherVault', bytes(range(256))*10])
def test_roundtrip(data):
    encrypted = c.encrypt_file(data, PASSWORD, '../../example.bin')
    recovered = c.decrypt_file(encrypted.value['package'], PASSWORD)
    assert recovered.value['data'] == data
    assert recovered.value['metadata']['filename'] == 'example.bin'
    assert recovered.value['sha256'] == hashlib.sha256(data).hexdigest()
    assert encrypted.seconds >= 0 and recovered.seconds >= 0
    assert encrypted.value['aes_seconds'] >= 0 and recovered.value['hash_seconds'] >= 0


def test_wrong_password():
    package = c.encrypt_file(b'secret', PASSWORD).value['package']
    with pytest.raises(c.OperationError, match='Authentication failed') as exc:
        c.decrypt_file(package, 'wrong but sufficiently long')
    assert exc.value.seconds >= 0


@pytest.mark.parametrize('offset', [-1,-17])
def test_tampered_tag_or_ciphertext(offset):
    package = bytearray(c.encrypt_file(b'secret content', PASSWORD).value['package'])
    package[offset] ^= 1
    with pytest.raises(c.OperationError, match='Authentication failed'):
        c.decrypt_file(bytes(package), PASSWORD)


def test_header_authenticated():
    package = c.encrypt_file(b'secret', PASSWORD, 'test.bin').value['package']
    package = package.replace(b'test.bin', b'best.bin')
    with pytest.raises(c.OperationError, match='Authentication failed'):
        c.decrypt_file(package, PASSWORD)


@pytest.mark.parametrize('package', [b'', b'garbage', b'CVLT1'+struct.pack('>I', 999999)+b'x'*30,
    b'CVLT1'+struct.pack('>I', 2)+b'[]'+b'x'*16,
    b'CVLT1'+struct.pack('>I', 1)+b'\xff'+b'x'*16])
def test_malformed(package):
    with pytest.raises(c.OperationError):
        c.decrypt_file(package, PASSWORD)


def test_nonce_and_salt_fresh():
    a = c.encrypt_file(b'hello', PASSWORD).value['metadata']
    b = c.encrypt_file(b'hello', PASSWORD).value['metadata']
    assert a['nonce'] != b['nonce'] and a['salt'] != b['salt']


def test_hash_and_comparison():
    result = c.hash_file(b'abc')
    assert result.value == 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad'
    assert result.seconds >= 0
    equal = c.compare_files(b'abc', b'abc')
    assert equal.value['hash_equal'] and equal.value['bytes_equal'] and equal.seconds >= 0
    assert not c.compare_files(b'abc', b'abd').value['hash_equal']


@pytest.fixture(scope='module')
def keys():
    result = c.generate_keys()
    assert result.seconds >= 0 and result.value.key_size == 3072
    return result.value


def test_signatures(keys):
    signed = c.sign_file(b'original', keys)
    assert signed['hash_seconds'] >= 0 and signed['sign_seconds'] >= 0
    verified = c.verify_file(b'original', signed['signature'], c.load_public(c.public_pem(keys)))
    assert verified['valid'] and verified['verify_seconds'] >= 0
    assert not c.verify_file(b'modified', signed['signature'], keys.public_key())['valid']
    wrong = c.generate_keys().value
    assert not c.verify_file(b'original', signed['signature'], wrong.public_key())['valid']


def test_private_export_encrypted(keys):
    exported = c.private_pem(keys, PASSWORD)
    assert b'ENCRYPTED PRIVATE KEY' in exported.value
    loaded = serialization.load_pem_private_key(exported.value, PASSWORD.encode())
    assert loaded.public_key().public_numbers() == keys.public_key().public_numbers()


def test_avalanche():
    result = c.avalanche(bytes(16), 43)
    assert 0 <= result.value['changed'] <= 128
    assert result.value['percentage'] == result.value['changed']/128*100
    assert result.seconds >= 0
    with pytest.raises(c.OperationError): c.avalanche(b'bad', 0)


def test_size_and_password_limits():
    with pytest.raises(c.OperationError): c.encrypt_file(b'x', 'short')
    with pytest.raises(c.OperationError): c.hash_file(bytes(c.MAX_FILE+1))
