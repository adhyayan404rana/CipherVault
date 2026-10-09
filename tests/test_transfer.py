import hashlib
import time
import pytest
import requests
import crypto_service as c
from transfer_service import TransferService

PASSWORD = 'receiver separate test password'


@pytest.fixture
def server(tmp_path):
    service = TransferService(lan_ip='127.0.0.1')
    # Explicit trusted certificate, never disable TLS verification.
    certificate = tmp_path/'trusted.pem'
    certificate.write_bytes(service.certificate)
    yield service, f'https://127.0.0.1:{service.port}', str(certificate)
    service.stop()


def claim(base, token, cert):
    return requests.post(base+'/claim', headers={'Authorization':'Bearer '+token}, data=b'', verify=cert, timeout=10)


def test_transfer_roundtrip_receipt_and_replay(server):
    service, base, cert = server
    data = b'a small real network transfer'
    start = time.perf_counter()
    encrypted = c.encrypt_file(data, PASSWORD, 'sample.txt')
    token = service.publish(encrypted.value['package'], encrypted.seconds, start=start)
    network_start = time.perf_counter()
    response = claim(base, token, cert)
    network_seconds = time.perf_counter()-network_start
    assert response.status_code == 200
    decrypted = c.decrypt_file(response.content, PASSWORD)
    assert decrypted.value['data'] == data
    assert decrypted.value['sha256'] == hashlib.sha256(data).hexdigest()
    assert claim(base, token, cert).status_code == 403
    receipt = {'sha256':decrypted.value['sha256'], 'network_seconds':network_seconds,
               'decrypt_seconds':decrypted.seconds, 'hash_seconds':decrypted.value['hash_seconds'],
               'receive_seconds':time.perf_counter()-network_start}
    headers = {'Authorization':'Bearer '+response.headers['X-Receipt-Token']}
    ack = requests.post(base+'/receipt', headers=headers, json=receipt, verify=cert, timeout=10)
    assert ack.status_code == 200
    assert service.status()['hash_matches']
    assert service.status()['active_total_seconds'] >= decrypted.seconds
    assert requests.post(base+'/receipt', headers=headers, json=receipt, verify=cert, timeout=10).status_code == 403


def test_unauthorized_and_routes(server):
    _, base, cert = server
    assert claim(base, 'a'*43, cert).status_code == 403
    assert requests.post(base+'/claim', verify=cert, timeout=10).status_code == 403
    assert requests.get(base+'/../../secret', verify=cert, timeout=10).status_code == 404
    page = requests.get(base+'/', verify=cert, timeout=10)
    assert page.status_code == 200 and 'password' in page.text
    assert 'no-store' in page.headers['Cache-Control']
    assert requests.post(base+'/proof',headers={'Authorization':'Bearer '+'a'*43},data=b'',verify=cert,timeout=10).status_code == 403


def test_signed_manifest_binds_package_hash_filename_and_timestamp(server):
    import base64
    import json
    service,base,cert = server
    encrypted = c.encrypt_file(b'signed real transfer',PASSWORD,'signed.txt')
    response = claim(base,service.publish(encrypted.value['package'],encrypted.seconds),cert)
    headers = {'Authorization':'Bearer '+response.headers['X-Receipt-Token']}
    proof = requests.post(base+'/proof',headers=headers,data=b'',verify=cert,timeout=10).json()
    message = base64.b64decode(proof['message'])
    public = service._signing_key.public_key()
    signature = base64.b64decode(proof['signature'])
    assert c.verify_file(message,signature,public)['valid']
    assert not c.verify_file(message+b'changed',signature,public)['valid']
    manifest = json.loads(message)
    assert manifest['package_sha256'] == hashlib.sha256(response.content).hexdigest()
    assert manifest['original_sha256'] == hashlib.sha256(b'signed real transfer').hexdigest()
    assert manifest['filename'] == 'signed.txt'
    assert '+00:00' in manifest['published_at']
    assert hashlib.sha256(base64.b64decode(proof['public_key'])).hexdigest() == service.signing_fingerprint
    assert proof['sign_seconds'] >= 0 and proof['hash_seconds'] >= 0 and proof['package_hash_seconds'] >= 0


def test_tampered_transfer_rejected(server):
    service, base, cert = server
    package = bytearray(c.encrypt_file(b'transfer', PASSWORD).value['package'])
    package[-1] ^= 1
    token = service.publish(bytes(package), 0)
    response = claim(base, token, cert)
    assert response.status_code == 200
    with pytest.raises(c.OperationError, match='Authentication failed'):
        c.decrypt_file(response.content, PASSWORD)


def test_expiry_revocation_and_invalid_receipt(server):
    service, base, cert = server
    package = c.encrypt_file(b'x', PASSWORD).value['package']
    first = service.publish(package, 0)
    second = service.publish(package, 0)
    assert claim(base, first, cert).status_code == 403
    with service.lock: service.pending[second]['expiry'] = time.monotonic()-1
    assert claim(base, second, cert).status_code == 403
    response = claim(base, service.publish(package, 0), cert)
    assert requests.post(base+'/receipt', headers={'Authorization':'Bearer '+response.headers['X-Receipt-Token']}, json={'network_seconds':-1}, verify=cert, timeout=10).status_code == 400
