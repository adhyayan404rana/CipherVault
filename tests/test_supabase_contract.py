"""REST request contract tests; these do not claim to test live Supabase RLS."""
from unittest.mock import Mock
import pytest
from hosted_store import SupabaseAccounts, StoreError


def test_cloud_calls_use_user_jwt_and_publishable_key_not_service_role(monkeypatch):
    call=Mock(return_value=Mock(ok=True,content=b'[]',json=lambda:[]))
    monkeypatch.setattr('hosted_store.requests.request',call)
    store=SupabaseAccounts('https://test.supabase.co','publishable-test-key')
    assert store.directory('user-test-jwt')==[]
    args,kwargs=call.call_args
    assert args==('GET','https://test.supabase.co/rest/v1/cv_profiles?select=*&order=username&limit=100')
    assert kwargs['headers']=={'apikey':'publishable-test-key','Authorization':'Bearer user-test-jwt'}
    assert kwargs['timeout']==30


def test_direct_signed_storage_upload_and_download_contract(monkeypatch):
    responses=[{}, {'url':'/object/upload/sign/cipher-packages/user/id.cvault?token=capability'},
               {'signedURL':'/object/sign/cipher-packages/user/id.cvault?token=download-capability'}]
    call=Mock(side_effect=[Mock(ok=True,content=b'{}',json=lambda value=value:value) for value in responses])
    monkeypatch.setattr('hosted_store.requests.request',call)
    store=SupabaseAccounts('https://test.supabase.co','publishable-test-key')
    record={'object_path':'user/id.cvault'}
    created=store.create_transfer('user-jwt',record)
    assert created['upload_method']=='PUT'
    assert created['upload_url']=='https://test.supabase.co/storage/v1/object/upload/sign/cipher-packages/user/id.cvault?token=capability'
    assert store.download_url('user-jwt',record)=='https://test.supabase.co/storage/v1/object/sign/cipher-packages/user/id.cvault?token=download-capability'
    assert call.call_args.kwargs['json']=={'expiresIn':60}


def test_remote_errors_never_expose_credentials_or_error_bodies(monkeypatch):
    response=Mock(ok=False,status_code=403,content=b'private-token-or-error-body')
    monkeypatch.setattr('hosted_store.requests.request',Mock(return_value=response))
    with pytest.raises(StoreError,match='access denied') as error:
        SupabaseAccounts('https://test.supabase.co','publishable-test-key').directory('private-token')
    assert 'private-token' not in str(error.value)


def test_vercel_cannot_use_ephemeral_local_sqlite(monkeypatch):
    monkeypatch.setenv('VERCEL','1')
    from hosted_app import create_app
    with pytest.raises(RuntimeError,match='Supabase persistence'):
        create_app({'MODE':'local'})


@pytest.mark.parametrize('code,expected',[
    ('invalid_credentials','Invalid email or password'),
    ('email_not_confirmed','Confirm your email'),
    ('email_address_not_authorized','default Supabase mailer'),
    ('over_email_send_rate_limit','rate limit reached'),
    ('email_address_invalid','rejected this email'),
])
def test_auth_codes_provide_safe_actionable_errors(monkeypatch,code,expected):
    response=Mock(ok=False,status_code=400,json=lambda:{'code':code,'msg':'PRIVATE password and token'})
    monkeypatch.setattr('hosted_store.requests.request',Mock(return_value=response))
    with pytest.raises(StoreError,match=expected) as error:
        SupabaseAccounts('https://test.supabase.co','test-key').login('user@example.test','private password')
    assert 'PRIVATE' not in str(error.value)
    assert 'private password' not in str(error.value)


@pytest.mark.parametrize('payload',[{'code':'unknown','msg':'PRIVATE'}, {'code':['invalid_credentials']}, ['PRIVATE']])
def test_unknown_auth_errors_do_not_leak_provider_bodies(monkeypatch,payload):
    response=Mock(ok=False,status_code=400,json=lambda:payload)
    monkeypatch.setattr('hosted_store.requests.request',Mock(return_value=response))
    with pytest.raises(StoreError,match='Cloud request failed') as error:
        SupabaseAccounts('https://test.supabase.co','test-key').login('user@example.test','password')
    assert 'PRIVATE' not in str(error.value)
