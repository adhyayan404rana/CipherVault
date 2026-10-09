import sqlite3
from crypto_service import Result, encrypt_file, decrypt_file, hash_file
from storage_service import ResultStore
from vault_charts import record_measurement


def test_roundtrip_persists_only_ciphertext_and_measurements(tmp_path):
    path = tmp_path/'saved.sqlite3'
    plaintext = b'PRIVATE_PLAINTEXT_NEVER_SAVED_4930'
    password = 'PRIVATE_PASSWORD_NEVER_SAVED_8492'
    encrypted = encrypt_file(plaintext,password,'sample.txt')
    package = encrypted.value['package']
    decrypted = decrypt_file(package,password)
    state = {'enc_result':encrypted,'dec_result':decrypted,'dec_package':package,
             'vault_measurements':record_measurement([],encrypted,'Encryption'),
             'dec_password':password,'rsa_key':object(),'transfer_token':'SECRET_TOKEN',
             'hash_result':hash_file(plaintext),'hash_size':len(plaintext)}
    store = ResultStore(path)
    store.sync(state)
    fresh = {}
    ResultStore(path).restore(fresh)
    assert fresh['enc_result'].value['package'] == package
    assert fresh['dec_package'] == package
    assert fresh['dec_result'].value['_restored']
    assert 'data' not in fresh['dec_result'].value
    assert fresh['dec_result'].seconds == decrypted.seconds
    assert fresh['vault_measurements'] == state['vault_measurements']
    assert not {'dec_password','rsa_key','transfer_token'} & fresh.keys()
    assert plaintext not in path.read_bytes() and password.encode() not in path.read_bytes()
    assert decrypt_file(fresh['dec_package'],password).value['data'] == plaintext


def test_nested_results_and_analysis_examples_are_sanitized(tmp_path):
    store = ResultStore(tmp_path/'saved.sqlite3')
    state = {'hash_comparison':Result({'first':hash_file(b'a'),'second':hash_file(b'b'),'hash_equal':False,'bytes_equal':False},.01),
             'analysis_hashes':Result({'trial':{'left_message_hex':b'private input'.hex(),
                'right_message_hex':b'candidate'.hex(),'left_digest_hex':'ab'*32}},.01)}
    store.sync(state)
    fresh = store.load()
    assert isinstance(fresh['hash_comparison'].value['first'],Result)
    assert not fresh['hash_comparison'].value['hash_equal']
    assert fresh['analysis_hashes'].value['trial'] == {'left_digest_hex':'ab'*32}


def test_deleted_output_stays_deleted_and_clear_resets_store(tmp_path):
    store = ResultStore(tmp_path/'saved.sqlite3')
    state = {'hash_result':hash_file(b'abc'),'workspace_section':'Overview'}
    store.sync(state)
    state.pop('hash_result')
    store.sync(state)
    assert 'hash_result' not in store.load()
    store.clear(state)
    store.sync(state)
    assert store.load() == {}
    assert 'workspace_section' not in state


def test_unchanged_old_tab_does_not_overwrite_new_results(tmp_path):
    store = ResultStore(tmp_path/'saved.sqlite3')
    first = {'hash_result':hash_file(b'old')}
    store.sync(first)
    second = {}
    store.restore(second)
    first['hash_result'] = hash_file(b'new')
    store.sync(first)
    store.sync(second)
    assert store.load()['hash_result'].value == first['hash_result'].value


def test_malformed_json_is_reported_without_execution(tmp_path):
    import pytest
    store = ResultStore(tmp_path/'saved.sqlite3')
    with sqlite3.connect(store.path) as database:
        database.execute('INSERT INTO results VALUES (?,?)',('enc_result','not json'))
    with pytest.raises(ValueError,match='damaged'):
        store.load()
    store.clear({})
    assert store.load() == {}
