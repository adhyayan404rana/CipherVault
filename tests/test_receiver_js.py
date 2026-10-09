import base64
import json
import os
from pathlib import Path
import shutil
import subprocess
import pytest
from crypto_service import encrypt_file
from transfer_service import TransferService


@pytest.mark.skipif(shutil.which('node') is None, reason='Optional Node Web Crypto interoperability check requires Node 22+.')
@pytest.mark.parametrize('mode', ['success', 'empty', 'tampered', 'wrong_password','bad_signature','wrong_signing_key'])
def test_actual_receiver_javascript(mode, tmp_path):
    password = 'browser separate strong password'
    data = b'' if mode == 'empty' else b'Browser Web Crypto recovers Python AES-GCM bytes.\x00\xff'
    package = encrypt_file(data, password, 'browser.bin').value['package']
    if mode == 'tampered':
        package = package[:-1]+bytes([package[-1]^1])
    service = TransferService(lan_ip='127.0.0.1')
    try:
        token = service.publish(package, 0)
        certificate = tmp_path/'receiver.pem'
        certificate.write_bytes(service.certificate)
        environment = dict(os.environ, NODE_EXTRA_CA_CERTS=str(certificate))
        run = subprocess.run(['node', str(Path(__file__).with_name('receiver_harness.cjs'))],
            input=json.dumps({'base':f'https://127.0.0.1:{service.port}', 'token':token,
                              'mode':mode,'fingerprint':'0'*64 if mode == 'wrong_signing_key' else service.signing_fingerprint,
                              'password':'incorrect but long password' if mode == 'wrong_password' else password}),
            text=True, capture_output=True, env=environment, timeout=30, check=True)
        result = json.loads(run.stdout)
        assert result['passwordCleared']
        if mode in ('success','empty'):
            assert not result['hidden'] and base64.b64decode(result['recovered']) == data
            assert 'Sender hash matches: YES' in result['status']
            assert service.status()['hash_matches']
            assert service.status()['signature_valid']
            assert service.status()['signature_seconds'] >= 0
            assert 'Digital signature: VERIFIED' in result['status']
            assert 'Recovered at (receiver UTC)' in result['status']
            assert result['decryptedPreview']
            assert result['signaturePreview']
            assert result['encryptedPreview']
        else:
            assert result['hidden'] and result['recovered'] is None
            assert result['decryptedPreview'] == ''
            assert ('Digital signature verification failed' if mode == 'bad_signature' else
                    'trusted fingerprint' if mode == 'wrong_signing_key' else 'Authentication failed') in result['status']
            assert service.status() is None
    finally:
        service.stop()
