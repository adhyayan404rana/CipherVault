import base64
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess

import pytest
from cryptography.hazmat.primitives import serialization
import crypto_service as c


@pytest.fixture(scope='module')
def signing_pair():
    return c.generate_keys().value


@pytest.mark.skipif(not shutil.which('node'),reason='Browser crypto interoperability needs Node Web Crypto')
@pytest.mark.parametrize('mode',['password','key'])
@pytest.mark.parametrize('data',[b'',bytes(range(256))*8])
def test_existing_python_packages_and_rsa_interoperate_with_web_edition(mode,data,signing_pair):
    password='test interop password 2026!'
    key=os.urandom(32) if mode=='key' else None
    encrypted=c.encrypt_file(data,None if key else password,'interop.bin',key=key)
    signature=c.sign_file(data,signing_pair)['signature']
    b64=lambda value:base64.b64encode(value).decode()
    request={'data':b64(data),'package':b64(encrypted.value['package']),'password':password,'key':b64(key) if key else None,
             'signature':b64(signature),
             'public_key':b64(signing_pair.public_key().public_bytes(serialization.Encoding.DER,serialization.PublicFormat.SubjectPublicKeyInfo)),
             'private_key':b64(signing_pair.private_bytes(serialization.Encoding.DER,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()))}
    run=subprocess.run(['node',str(Path(__file__).with_name('hosted_crypto.cjs'))],input=json.dumps(request),text=True,capture_output=True,check=True,timeout=30)
    result=json.loads(run.stdout)
    assert base64.b64decode(result['recovered'])==data
    python_recovery=c.decrypt_file(base64.b64decode(result['package']),None if key else password,key=key)
    assert python_recovery.value['data']==data
    assert result['digest']==hashlib.sha256(data).hexdigest()
    assert result['valid'] and result['wrongRejected']
    assert c.verify_file(data,base64.b64decode(result['signature']),signing_pair.public_key())['valid']
    assert all(result[k]>=0 for k in ('encrypt_seconds','decrypt_seconds','hash_seconds','sign_seconds','verify_seconds'))
