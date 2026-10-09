"""Account-isolated local persistence and Supabase RLS persistence for the web edition."""
import base64
import hashlib
import hmac
import json
import os
import secrets
import sqlite3
import time
import uuid
from contextlib import contextmanager
from pathlib import Path
from urllib.parse import quote

import requests


class StoreError(ValueError):
    pass


class LocalAccounts:
    mode = 'local'

    def __init__(self,path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True,exist_ok=True)
        with self.db() as db:
            db.executescript('''
              CREATE TABLE IF NOT EXISTS users(id TEXT PRIMARY KEY,email TEXT UNIQUE,salt BLOB,password BLOB);
              CREATE TABLE IF NOT EXISTS sessions(token TEXT PRIMARY KEY,user_id TEXT,expires REAL);
              CREATE TABLE IF NOT EXISTS profiles(user_id TEXT PRIMARY KEY,username TEXT UNIQUE,public_key TEXT,fingerprint TEXT,wrapped_key TEXT);
              CREATE TABLE IF NOT EXISTS transfers(id TEXT PRIMARY KEY,sender_id TEXT,recipient_id TEXT,record TEXT,package BLOB,status TEXT,receipt TEXT);
              CREATE TABLE IF NOT EXISTS results(user_id TEXT,kind TEXT,value TEXT,PRIMARY KEY(user_id,kind));
              CREATE TABLE IF NOT EXISTS attempts(bucket TEXT PRIMARY KEY,count INTEGER,reset REAL);
            ''')

    @contextmanager
    def db(self):
        connection = sqlite3.connect(self.path,timeout=20)
        connection.row_factory = sqlite3.Row
        try:
            with connection:
                yield connection
        finally:
            connection.close()

    def throttle(self,bucket,limit=20):
        now = time.time()
        with self.db() as db:
            db.execute('DELETE FROM attempts WHERE reset<?',(now,))
            db.execute('INSERT INTO attempts VALUES (?,1,?) ON CONFLICT(bucket) DO UPDATE SET count=count+1',(bucket,now+300))
            row = db.execute('SELECT count FROM attempts WHERE bucket=?',(bucket,)).fetchone()
            if row['count']>limit:
                raise StoreError('Too many attempts. Wait five minutes.')

    def register(self,email,password):
        salt = os.urandom(16)
        digest = hashlib.scrypt(password.encode(),salt=salt,n=32768,r=8,p=1,maxmem=64*1024*1024)
        try:
            with self.db() as db:
                db.execute('INSERT INTO users VALUES (?,?,?,?)',(str(uuid.uuid4()),email,salt,digest))
        except sqlite3.IntegrityError as exc:
            raise StoreError('Registration could not complete; try signing in.') from exc
        return {'message':'Account created. Sign in to continue.'}

    def login(self,email,password):
        with self.db() as db:
            row = db.execute('SELECT * FROM users WHERE email=?',(email,)).fetchone()
            digest = hashlib.scrypt(password.encode(),salt=row['salt'] if row else bytes(16),n=32768,r=8,p=1,maxmem=64*1024*1024)
            if row is None or not hmac.compare_digest(digest,row['password']):
                raise StoreError('Invalid email or password.')
            token = secrets.token_urlsafe(32)
            db.execute('DELETE FROM sessions WHERE expires<?',(time.time(),))
            db.execute('INSERT INTO sessions VALUES (?,?,?)',(hashlib.sha256(token.encode()).hexdigest(),row['id'],time.time()+8*3600))
        return token

    def user(self,token):
        with self.db() as db:
            row = db.execute('SELECT users.id,users.email FROM sessions JOIN users ON users.id=sessions.user_id WHERE token=? AND expires>?',
                             (hashlib.sha256(token.encode()).hexdigest(),time.time())).fetchone()
        return dict(row) if row else None

    def logout(self,token):
        with self.db() as db:
            db.execute('DELETE FROM sessions WHERE token=?',(hashlib.sha256(token.encode()).hexdigest(),))

    def profile(self,token,user_id,private=False):
        with self.db() as db:
            row = db.execute('SELECT * FROM profiles WHERE user_id=?',(user_id,)).fetchone()
        if row is None:
            return None
        result = dict(row)
        wrapped = result.pop('wrapped_key')
        if private:
            if self.user(token)['id'] != user_id:
                raise StoreError('Access denied.')
            result['wrapped_key'] = json.loads(wrapped)
        return result

    def enroll(self,token,profile):
        uid = self.user(token)['id']
        try:
            with self.db() as db:
                db.execute('INSERT INTO profiles VALUES (?,?,?,?,?)',(uid,profile['username'],profile['public_key'],profile['fingerprint'],json.dumps(profile['wrapped_key'])))
        except sqlite3.IntegrityError as exc:
            raise StoreError('A signing identity already exists or that username is taken.') from exc

    def directory(self,token):
        with self.db() as db:
            return [dict(r) for r in db.execute('SELECT user_id,username,public_key,fingerprint FROM profiles ORDER BY username LIMIT 100')]

    def create_transfer(self,token,record):
        with self.db() as db:
            if db.execute('SELECT count(*) FROM transfers WHERE sender_id=?',(record['sender_id'],)).fetchone()[0]>=100:
                raise StoreError('Delete an older transfer before creating another (100-transfer limit).')
            db.execute('INSERT INTO transfers(id,sender_id,recipient_id,record,status) VALUES (?,?,?,?,?)',
                       (record['id'],record['sender_id'],record['recipient_id'],json.dumps(record),'draft'))
        return {'upload_url':f'/api/transfers/{record["id"]}/upload','upload_method':'PUT'}

    def get_transfer(self,token,tid):
        uid = self.user(token)['id']
        with self.db() as db:
            row = db.execute('SELECT record,status,receipt FROM transfers WHERE id=? AND (sender_id=? OR recipient_id=?)',(tid,uid,uid)).fetchone()
        if not row:
            return None
        record = json.loads(row['record'])
        record.update(status=row['status'],receipt=json.loads(row['receipt']) if row['receipt'] else None)
        return record

    def transfers(self,token):
        uid = self.user(token)['id']
        with self.db() as db:
            ids = [r['id'] for r in db.execute('SELECT id FROM transfers WHERE sender_id=? OR recipient_id=? ORDER BY rowid DESC LIMIT 100',(uid,uid))]
        return [self.get_transfer(token,tid) for tid in ids]

    def upload(self,token,tid,package):
        with self.db() as db:
            result = db.execute('UPDATE transfers SET package=? WHERE id=? AND sender_id=? AND status=? AND package IS NULL',(package,tid,self.user(token)['id'],'draft'))
            if result.rowcount != 1:
                raise StoreError('Upload denied or already used.')

    def publish(self,token,tid,upload_seconds):
        record = self.get_transfer(token,tid)
        record['upload_seconds'] = upload_seconds
        with self.db() as db:
            result = db.execute('UPDATE transfers SET status=?,record=? WHERE id=? AND sender_id=? AND status=? AND package IS NOT NULL',
                                ('sent',json.dumps(record),tid,self.user(token)['id'],'draft'))
            if result.rowcount != 1:
                raise StoreError('Transfer is not ready or already published.')

    def download(self,token,tid):
        with self.db() as db:
            row = db.execute('SELECT package FROM transfers WHERE id=?',(tid,)).fetchone()
            return row['package']

    def receipt(self,token,tid,report):
        with self.db() as db:
            result = db.execute('UPDATE transfers SET status=?,receipt=? WHERE id=? AND recipient_id=? AND status=?',
                                ('verified',json.dumps(report),tid,self.user(token)['id'],'sent'))
            if result.rowcount != 1:
                raise StoreError('Receipt denied or already recorded.')

    def delete(self,token,tid):
        uid = self.user(token)['id']
        with self.db() as db:
            db.execute('DELETE FROM transfers WHERE id=? AND sender_id=?',(tid,uid))

    def results(self,token):
        with self.db() as db:
            return {r['kind']:json.loads(r['value']) for r in db.execute('SELECT kind,value FROM results WHERE user_id=?',(self.user(token)['id'],))}

    def save_result(self,token,kind,value):
        with self.db() as db:
            db.execute('INSERT INTO results VALUES (?,?,?) ON CONFLICT(user_id,kind) DO UPDATE SET value=excluded.value',
                       (self.user(token)['id'],kind,json.dumps(value)))


class SupabaseAccounts:
    mode = 'supabase'
    bucket = 'cipher-packages'

    def __init__(self,url,key):
        if not url.startswith('https://') or not key:
            raise StoreError('Set SUPABASE_URL and SUPABASE_PUBLISHABLE_KEY.')
        self.url,self.key = url.rstrip('/'),key

    def call(self,method,path,token=None,body=None,headers=None):
        request_headers = {'apikey':self.key,**(headers or {})}
        if token:
            request_headers['Authorization'] = 'Bearer '+token
        try:
            response = requests.request(method,self.url+path,headers=request_headers,json=body,timeout=30)
        except requests.RequestException as exc:
            raise StoreError('Cloud service could not be reached.') from exc
        if not response.ok:
            # Do not expose remote error bodies, tokens or credentials.
            if response.status_code in (401,403):
                raise StoreError('Authentication or access denied. Sign in again.')
            raise StoreError(f'Cloud request failed ({response.status_code}). Check schema, configuration, confirmation email or account details.')
        return response.json() if response.content else None

    def register(self,email,password):
        self.call('POST','/auth/v1/signup',body={'email':email,'password':password})
        return {'message':'Account registered. Confirm your email if required, then sign in.'}

    def login(self,email,password):
        result = self.call('POST','/auth/v1/token?grant_type=password',body={'email':email,'password':password})
        return result['access_token']

    def user(self,token):
        try:
            result = self.call('GET','/auth/v1/user',token)
            return {'id':result['id'],'email':result.get('email','')}
        except StoreError:
            return None

    def logout(self,token):
        self.call('POST','/auth/v1/logout',token)

    def profile(self,token,user_id,private=False):
        rows = self.call('GET','/rest/v1/cv_profiles?user_id=eq.'+quote(user_id)+'&select=*',token)
        if not rows:
            return None
        result = rows[0]
        if private:
            rows = self.call('GET','/rest/v1/cv_private_keys?user_id=eq.'+quote(user_id)+'&select=wrapped_key',token)
            if not rows:
                raise StoreError('Signing identity unavailable.')
            result['wrapped_key'] = rows[0]['wrapped_key']
        return result

    def enroll(self,token,profile):
        self.call('POST','/rest/v1/rpc/cv_enroll',token,{'p_username':profile['username'],'p_public_key':profile['public_key'],
                    'p_fingerprint':profile['fingerprint'],'p_wrapped_key':profile['wrapped_key']})

    def directory(self,token):
        return self.call('GET','/rest/v1/cv_profiles?select=*&order=username&limit=100',token)

    def create_transfer(self,token,record):
        self.call('POST','/rest/v1/cv_transfers',token,record)
        result = self.call('POST',f'/storage/v1/object/upload/sign/{self.bucket}/{record["object_path"]}',token,{})
        return {'upload_url':self.url+'/storage/v1'+result['url'],'upload_method':'PUT'}

    def get_transfer(self,token,tid):
        rows = self.call('GET','/rest/v1/cv_transfers?id=eq.'+quote(tid)+'&select=*',token)
        return rows[0] if rows else None

    def transfers(self,token):
        return self.call('GET','/rest/v1/cv_transfers?select=*&order=created_at.desc&limit=100',token)

    def publish(self,token,tid,upload_seconds):
        self.call('POST','/rest/v1/rpc/cv_publish',token,{'p_id':tid,'p_upload_seconds':upload_seconds})

    def download_url(self,token,record):
        result = self.call('POST',f'/storage/v1/object/sign/{self.bucket}/{record["object_path"]}',token,{'expiresIn':60})
        return self.url+'/storage/v1'+result['signedURL']

    def receipt(self,token,tid,report):
        self.call('POST','/rest/v1/rpc/cv_receipt',token,{'p_id':tid,'p_receipt':report})

    def delete(self,token,tid):
        record = self.get_transfer(token,tid)
        self.call('DELETE',f'/storage/v1/object/{self.bucket}',token,{'prefixes':[record['object_path']]})
        self.call('DELETE','/rest/v1/cv_transfers?id=eq.'+quote(tid),token)

    def results(self,token):
        rows = self.call('GET','/rest/v1/cv_results?select=kind,value',token)
        return {r['kind']:r['value'] for r in rows}

    def save_result(self,token,kind,value):
        uid = self.user(token)['id']
        self.call('POST','/rest/v1/cv_results?on_conflict=user_id,kind',token,{'user_id':uid,'kind':kind,'value':value},
                  {'Prefer':'resolution=merge-duplicates'})
