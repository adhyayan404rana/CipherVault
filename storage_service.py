"""Local single-user results store. JSON only; no passwords, plaintext or private keys."""
import base64
import hashlib
import json
import math
import os
from pathlib import Path
import sqlite3
from contextlib import contextmanager

from crypto_service import MAX_PACKAGE, Result

KEYS = {'workspace_section','enc_result','dec_result','dec_package','vault_measurements',
        'benchmarks','analysis_avalanche','analysis_lengths','analysis_hashes','signature',
        'signature_public','hash_result','hash_size','hash_comparison','hash_byte_demo',
        'verification_result','avalanche_result','transfer_encrypted','vault_key_analysis','vault_password_analysis'}
FORBIDDEN = {'data','password','private_key','rsa_key','plaintext','api_key',
             'left_message_hex','right_message_hex','key','aes_key','key_file','enc_key_file','dec_key_file'}
MAX_JSON = MAX_PACKAGE*2 + 1024*1024


def _encode(value):
    if isinstance(value, Result):
        return {'__type__':'result','value':_encode(value.value),'seconds':value.seconds}
    if isinstance(value, bytes):
        if len(value) > MAX_PACKAGE:
            raise ValueError('Saved artifact exceeds size limit.')
        return {'__type__':'bytes','base64':base64.b64encode(value).decode('ascii')}
    if isinstance(value, dict):
        return {k:_encode(v) for k,v in value.items() if k not in FORBIDDEN and not k.startswith('_')}
    if isinstance(value, list):
        return [_encode(v) for v in value]
    if value is None or type(value) in (str,int,bool):
        return value
    if type(value) is float and math.isfinite(value):
        return value
    raise ValueError('Unsupported saved-result type.')


def _decode(value, depth=0):
    if depth > 30:
        raise ValueError('Saved result nesting exceeds limit.')
    if isinstance(value, dict):
        if value.get('__type__') == 'bytes':
            data = base64.b64decode(value['base64'],validate=True)
            if len(data) > MAX_PACKAGE:
                raise ValueError('Saved artifact too large.')
            return data
        if value.get('__type__') == 'result':
            seconds = value['seconds']
            if type(seconds) not in (int,float) or not math.isfinite(seconds) or seconds < 0:
                raise ValueError('Invalid saved timing.')
            return Result(_decode(value['value'],depth+1),seconds)
        return {k:_decode(v,depth+1) for k,v in value.items() if k not in FORBIDDEN and not k.startswith('_')}
    if isinstance(value,list):
        return [_decode(v,depth+1) for v in value]
    return value


def _payload(value):
    payload = json.dumps(_encode(value),sort_keys=True,separators=(',',':'),allow_nan=False)
    if len(payload.encode()) > MAX_JSON:
        raise ValueError('Saved result exceeds limit.')
    return payload


def _fingerprint(value):
    return hashlib.sha256(_payload(value).encode()).hexdigest()


class ResultStore:
    def __init__(self, path=None):
        self.path = Path(path or os.getenv('CIPHERVAULT_DB_PATH') or Path(__file__).parent/'local_data'/'results.sqlite3')
        self.path.parent.mkdir(parents=True,exist_ok=True)
        with self._connect() as database:
            database.execute('CREATE TABLE IF NOT EXISTS results (name TEXT PRIMARY KEY, payload TEXT NOT NULL)')

    @contextmanager
    def _connect(self):
        database = sqlite3.connect(self.path,timeout=10)
        try:
            database.execute('PRAGMA secure_delete=ON')
            with database:
                yield database
        finally:
            database.close()

    def load(self):
        values = {}
        with self._connect() as database:
            rows = database.execute('SELECT name,payload FROM results WHERE length(payload) <= ?', (MAX_JSON,))
            for name,payload in rows:
                if name not in KEYS:
                    continue
                try:
                    values[name] = _decode(json.loads(payload))
                except (ValueError,KeyError,TypeError,RecursionError):
                    raise ValueError(f'Saved result {name} is damaged; clear saved results to reset it.') from None
        if 'dec_result' in values:
            values['dec_result'].value['_restored'] = True
        return values

    def sync(self, state):
        baseline = state.get('_saved_fingerprints',{})
        payloads = {name:_payload(state[name]) for name in KEYS if name in state}
        fingerprints = {name:hashlib.sha256(payload.encode()).hexdigest() for name,payload in payloads.items()}
        changed = {name:payload for name,payload in payloads.items() if baseline.get(name) != fingerprints[name]}
        removed = set(baseline)-set(payloads)
        if changed or removed:
            with self._connect() as database:
                database.executemany('INSERT INTO results(name,payload) VALUES (?,?) ON CONFLICT(name) DO UPDATE SET payload=excluded.payload',changed.items())
                database.executemany('DELETE FROM results WHERE name=?',[(name,) for name in removed])
        state['_saved_fingerprints'] = fingerprints

    def restore(self,state):
        if state.get('_results_loaded'):
            return
        values = self.load()
        for name,value in values.items():
            if name not in state:
                state[name] = value
        state['_saved_fingerprints'] = {name:_fingerprint(value) for name,value in values.items()}
        state['_results_loaded'] = True

    def clear(self,state):
        with self._connect() as database:
            database.execute('DELETE FROM results')
        for name in KEYS:
            state.pop(name,None)
        state['_saved_fingerprints'] = {}
        state['_results_loaded'] = True
