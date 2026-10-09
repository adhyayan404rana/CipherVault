import base64
import datetime as dt
import hashlib
import json
import time
import uuid

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

import crypto_service as crypto
from hosted_app import create_app

ACCOUNT_PASSWORD = 'test account password 2026!'
SIGNING_PASSWORD = 'separate signing password 2026!'
FILE_PASSWORD = 'separate file password 2026!'


@pytest.fixture
def web(tmp_path):
    return create_app({'TESTING':True,'DATABASE':tmp_path/'accounts.sqlite3','SECRET_KEY':'test-only-session-secret-at-least-32-characters'})


def csrf(client):
    return client.get('/api/session').json['csrf']


def post(client,path,data,method='POST'):
    return client.open('/api/'+path,method=method,json=data,headers={'X-CSRF-Token':csrf(client)})


def register(client,email):
    assert post(client,'register',{'email':email,'password':ACCOUNT_PASSWORD}).status_code==200
    assert post(client,'login',{'email':email,'password':ACCOUNT_PASSWORD}).status_code==200
    return client.get('/api/session').json['user']['id']


def enroll(client,username,key):
    public=key.public_key().public_bytes(serialization.Encoding.DER,serialization.PublicFormat.SubjectPublicKeyInfo)
    private=key.private_bytes(serialization.Encoding.DER,serialization.PrivateFormat.PKCS8,serialization.NoEncryption())
    salt,nonce=bytes(range(16)),bytes(range(12))
    user_id=client.get('/api/session').json['user']['id']
    encrypted=AESGCM(crypto.derive_key(SIGNING_PASSWORD,salt)).encrypt(nonce,private,('CipherVault signing identity:'+user_id).encode())
    b64=lambda value:base64.b64encode(value).decode()
    response=post(client,'identity',{'username':username,'public_key':b64(public),'fingerprint':hashlib.sha256(public).hexdigest(),
                                   'wrapped_key':{'salt':b64(salt),'nonce':b64(nonce),'ciphertext':b64(encrypted),'iterations':600000}})
    assert response.status_code==200,response.json


@pytest.fixture
def pair(web):
    alice,bob,outsider=web.test_client(),web.test_client(),web.test_client()
    aid=register(alice,'alice@example.test');bid=register(bob,'bob@example.test')
    register(outsider,'eve@example.test')
    key=crypto.generate_keys().value
    enroll(alice,'alice',key);enroll(bob,'bob',crypto.generate_keys().value)
    return alice,bob,outsider,aid,bid,key


def draft(pair,data=b'Account-to-account confidential demo'):
    alice,bob,outsider,aid,bid,key=pair
    encrypted=crypto.encrypt_file(data,FILE_PASSWORD,'demo.txt')
    tid=str(uuid.uuid4())
    manifest={'id':tid,'sender_id':aid,'recipient_id':bid,'filename':'demo.txt','size_bytes':len(data),
              'package_bytes':len(encrypted.value['package']),'original_sha256':hashlib.sha256(data).hexdigest(),
              'package_sha256':hashlib.sha256(encrypted.value['package']).hexdigest(),
              'published_at':dt.datetime.now(dt.timezone.utc).isoformat()}
    message=json.dumps(manifest,separators=(',',':')).encode();signed=crypto.sign_file(message,key)
    request={'message':base64.b64encode(message).decode(),'signature':base64.b64encode(signed['signature']).decode(),
             'timings':{'encryption_seconds':encrypted.seconds,'aes_seconds':encrypted.value['aes_seconds'],
                        'hash_seconds':encrypted.value['hash_seconds'],'sign_seconds':signed['sign_seconds'],
                        'key_setup_seconds':encrypted.value['key_setup_seconds']}}
    response=post(alice,'transfers',request)
    assert response.status_code==200,response.json
    return tid,encrypted.value['package'],manifest,request


def test_login_csrf_and_hashed_passwords(web):
    client=web.test_client()
    assert client.get('/api/transfers').status_code==401
    assert client.post('/api/register',json={}).status_code==403
    register(client,'alice@example.test')
    assert client.post('/api/logout',headers={'X-CSRF-Token':csrf(client),'Origin':'https://evil.example'},json={}).status_code==403
    store=web.extensions['accounts']
    with store.db() as connection:
        row=connection.execute('SELECT password,salt FROM users').fetchone()
        assert row['password']!=ACCOUNT_PASSWORD.encode() and len(row['salt'])==16
    assert post(client,'logout',{}).status_code==200
    assert client.get('/api/results').status_code==401
    assert post(client,'login',{'email':'alice@example.test','password':'incorrect password 2026!'}).status_code==400


def test_two_accounts_transfer_signature_hash_receipt_and_isolation(pair):
    alice,bob,eve,aid,bid,key=pair
    tid,package,manifest,_=draft(pair)
    assert eve.get('/api/transfers').json['transfers']==[]
    assert eve.get('/api/transfers/'+tid+'/download').status_code==404
    assert bob.get('/api/transfers/'+tid+'/download').status_code==409
    start=time.perf_counter()
    upload=alice.put('/api/transfers/'+tid+'/upload',data=package,headers={'X-CSRF-Token':csrf(alice),'Content-Type':'application/octet-stream'})
    assert upload.status_code==200,upload.json
    assert post(alice,'transfers/'+tid+'/publish',{'upload_seconds':time.perf_counter()-start}).status_code==200
    assert bob.put('/api/transfers/'+tid+'/upload',data=package,headers={'X-CSRF-Token':csrf(bob)}).status_code==404
    network_start=time.perf_counter();received=bob.get('/api/transfers/'+tid+'/download');network_seconds=time.perf_counter()-network_start
    recovered=crypto.decrypt_file(received.data,FILE_PASSWORD)
    assert recovered.value['data']==b'Account-to-account confidential demo'
    report={'sha256':recovered.value['sha256'],'signature_valid':True,'network_seconds':network_seconds,
            'decrypt_seconds':recovered.seconds,'aes_seconds':recovered.value['aes_seconds'],
            'hash_seconds':recovered.value['hash_seconds'],'signature_seconds':crypto.verify_file(json.dumps(manifest,separators=(',',':')).encode(),base64.b64decode(alice.get('/api/transfers').json['transfers'][0]['signature']),key.public_key())['verify_seconds'],
            'receive_seconds':time.perf_counter()-network_start,'recovered_at':dt.datetime.now(dt.timezone.utc).isoformat()}
    assert post(alice,'transfers/'+tid+'/receipt',report).status_code==404
    assert post(eve,'transfers/'+tid+'/receipt',report).status_code==404
    assert post(bob,'transfers/'+tid+'/receipt',report).status_code==200
    assert post(bob,'transfers/'+tid+'/receipt',report).status_code==400
    receipt=alice.get('/api/transfers').json['transfers'][0]
    assert receipt['status']=='verified' and receipt['receipt']['sha256']==manifest['original_sha256']
    assert 'recorded_at' in receipt['receipt']
    assert post(bob,'transfers/'+tid,None,method='DELETE').status_code==404
    assert post(alice,'transfers/'+tid,None,method='DELETE').status_code==200
    assert bob.get('/api/transfers/'+tid+'/download').status_code==404


def test_tampered_upload_invalid_signature_and_private_key_separation(pair):
    alice,bob,eve,aid,bid,key=pair
    tid,package,_,signed=draft(pair)
    corrupted=package[:-1]+bytes([package[-1]^1])
    response=alice.put('/api/transfers/'+tid+'/upload',data=corrupted,headers={'X-CSRF-Token':csrf(alice)})
    assert response.status_code==400
    changed=dict(signed);signature=bytearray(base64.b64decode(changed['signature']));signature[0]^=1;changed['signature']=base64.b64encode(signature).decode()
    assert post(alice,'transfers',changed).status_code==400
    assert 'wrapped_key' in alice.get('/api/identity').json['profile']
    assert all('wrapped_key' not in profile for profile in bob.get('/api/directory').json['users'])
    assert bob.get('/api/identity').json['profile']['user_id']==bid
    assert eve.get('/api/identity').json['profile'] is None


def test_account_results_survive_login_without_leaking(pair):
    alice,bob,eve,*_=pair
    assert post(alice,'results/vault_metrics',{'rows':[{'aes_ms':.2,'size_bytes':1024}],'password':'never save','plaintext':'never save','key':'never save'}).status_code==200
    assert bob.get('/api/results').json['results']=={}
    assert eve.get('/api/results').json['results']=={}
    post(alice,'logout',{})
    post(alice,'login',{'email':'alice@example.test','password':ACCOUNT_PASSWORD})
    assert alice.get('/api/results').json['results']['vault_metrics']=={'rows':[{'aes_ms':.2,'size_bytes':1024}]}
    assert post(alice,'results/arbitrary',{}).status_code==404


def test_transfer_expiry_and_no_overwrite(pair,web):
    alice,bob,*_=pair
    tid,package,_,_=draft(pair)
    headers={'X-CSRF-Token':csrf(alice)}
    assert alice.put('/api/transfers/'+tid+'/upload',data=package,headers=headers).status_code==200
    assert alice.put('/api/transfers/'+tid+'/upload',data=package,headers=headers).status_code==400
    post(alice,'transfers/'+tid+'/publish',{'upload_seconds':0})
    store=web.extensions['accounts']
    with store.db() as connection:
        row=connection.execute('SELECT record FROM transfers WHERE id=?',(tid,)).fetchone()
        record=json.loads(row['record']);record['expires_at']=(dt.datetime.now(dt.timezone.utc)-dt.timedelta(seconds=1)).isoformat()
        connection.execute('UPDATE transfers SET record=? WHERE id=?',(json.dumps(record),tid))
    assert bob.get('/api/transfers/'+tid+'/download').status_code==410
    assert post(alice,'transfers/'+tid,None,method='DELETE').status_code==200


def test_hosted_analysis_runs_real_measurements_without_ai_key(web,monkeypatch):
    monkeypatch.delenv('GEMINI_API_KEY',raising=False)
    client=web.test_client();register(client,'analyst@example.test')
    response=post(client,'analysis/avalanche',{'block':'00112233445566778899aabbccddeeff'})
    assert response.status_code==200
    assert response.json['result']['total_seconds']>=0
    assert len(response.json['result']['rows'])==64
    assert 'avalanche' in client.get('/api/results').json['results']
    assert post(client,'ai',{'question':'Explain AES-GCM'}).status_code==400
    assert client.get('/health').status_code==200
