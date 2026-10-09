import os
import pytest
from crypto_service import encrypt_file,decrypt_file,OperationError,parse_package
from storage_service import ResultStore
from transfer_service import TransferService


@pytest.mark.parametrize('data',[b'',b'File using a supplied AES key',bytes(range(256))*20])
def test_key_file_roundtrip(data):
    key = os.urandom(32)
    encrypted = encrypt_file(data,filename='sample.txt',key=key)
    recovered = decrypt_file(encrypted.value['package'],key=key)
    assert recovered.value['data'] == data
    assert encrypted.value['metadata']['kdf'] == 'RAW-KEY'
    assert encrypted.value['metadata']['iterations'] == 0
    assert encrypted.value['metadata']['salt'] == ''
    assert encrypted.seconds >= 0 and recovered.seconds >= 0
    assert encrypted.value['key_setup_seconds'] >= 0
    assert 'key' not in encrypted.value and 'key' not in encrypted.value['metadata']


def test_wrong_key_and_tampering_reject_without_plaintext():
    key = os.urandom(32)
    package = encrypt_file(b'private content',key=key).value['package']
    with pytest.raises(OperationError,match='Authentication failed'):
        decrypt_file(package,key=os.urandom(32))
    for offset in (-1,-17):
        changed = bytearray(package)
        changed[offset] ^= 1
        with pytest.raises(OperationError,match='Authentication failed'):
            decrypt_file(bytes(changed),key=key)


@pytest.mark.parametrize('key',[b'',bytes(16),bytes(24),bytes(33),'not bytes'])
def test_only_256_bit_raw_keys_accepted(key):
    with pytest.raises(OperationError,match='32 raw bytes'):
        encrypt_file(b'data',key=key)


def test_key_file_nonce_fresh_and_modes_not_interchangeable():
    key = os.urandom(32)
    first = encrypt_file(b'data',key=key).value['package']
    second = encrypt_file(b'data',key=key).value['package']
    assert parse_package(first)[0]['nonce'] != parse_package(second)[0]['nonce']
    with pytest.raises(OperationError,match='requires its AES key file'):
        decrypt_file(first,'a long demo password')
    password_package = encrypt_file(b'data','a long demo password').value['package']
    with pytest.raises(OperationError,match='requires its original password'):
        decrypt_file(password_package,key=key)
    with pytest.raises(OperationError,match='not both'):
        encrypt_file(b'data','a long demo password',key=key)


def test_key_file_values_are_never_saved(tmp_path):
    key = os.urandom(32)
    encrypted = encrypt_file(b'file',key=key)
    store = ResultStore(tmp_path/'saved.sqlite3')
    store.sync({'enc_result':encrypted,'enc_key_file':key,'aes_key':key})
    restored = store.load()
    assert set(restored) == {'enc_result'}
    assert decrypt_file(restored['enc_result'].value['package'],key=key).value['data'] == b'file'


def test_password_only_browser_receiver_rejects_raw_key_package():
    service = TransferService(lan_ip='127.0.0.1')
    try:
        encrypted = encrypt_file(b'file',key=os.urandom(32))
        with pytest.raises(ValueError,match='password-based'):
            service.publish(encrypted.value['package'],encrypted.seconds)
    finally:
        service.stop()
