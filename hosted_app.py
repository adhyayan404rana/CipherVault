"""Optional account-based web edition. The original Streamlit application is unchanged."""
import base64
import datetime as dt
import hashlib
import json
import math
import os
import re
import secrets
import time
import uuid
from pathlib import Path
from urllib.parse import urlparse

from dotenv import load_dotenv
from flask import Flask, abort, g, jsonify, request, send_file, session
from werkzeug.exceptions import HTTPException
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

import crypto_service as crypto
from ai_service import ask_assistant
from analysis_service import confusion_diffusion, aes_length_analysis, password_length_analysis, hashing_resistance_analysis
from benchmark_service import run_benchmarks
from hosted_store import LocalAccounts, SupabaseAccounts, StoreError

ROOT = Path(__file__).parent
RESULT_KINDS = {'benchmarks','avalanche','lengths','password_lengths','hash_resistance','vault_metrics','hash_metrics','signature_metrics'}


def utc_now():
    return dt.datetime.now(dt.timezone.utc)


def unbase64(value,maximum=8192):
    if not isinstance(value,str) or len(value)>maximum:
        raise ValueError('Invalid encoded value.')
    return base64.b64decode(value,validate=True)


def safe_results(value):
    forbidden = {'data','password','private_key','plaintext','key','aes_key','api_key','left_message_hex','right_message_hex'}
    if isinstance(value,dict):
        return {k:safe_results(v) for k,v in value.items() if k not in forbidden}
    if isinstance(value,list):
        return [safe_results(v) for v in value]
    if value is None or type(value) in (str,int,bool):
        return value
    if type(value) is float and math.isfinite(value):
        return value
    raise ValueError('Unsupported result value.')


def load_der_public(value):
    key = serialization.load_der_public_key(value)
    if not isinstance(key,rsa.RSAPublicKey) or key.key_size!=3072:
        raise ValueError('Expected a 3072-bit RSA public key.')
    return key


def create_app(config=None):
    load_dotenv()
    app = Flask(__name__,static_folder='hosted',static_url_path='/assets')
    settings = config or {}
    mode = settings.get('MODE',os.getenv('CIPHERVAULT_HOSTED_MODE','supabase' if os.getenv('VERCEL') else 'local'))
    if os.getenv('VERCEL') and mode != 'supabase':
        raise RuntimeError('Vercel requires Supabase persistence; local SQLite mode is not supported there.')
    store = settings.get('STORE')
    if store is None:
        store = (SupabaseAccounts(os.getenv('SUPABASE_URL',''),os.getenv('SUPABASE_PUBLISHABLE_KEY','')) if mode=='supabase'
                 else LocalAccounts(settings.get('DATABASE',os.getenv('CIPHERVAULT_HOSTED_DB',str(ROOT/'local_data'/'accounts.sqlite3')))))
    secret = settings.get('SECRET_KEY') or os.getenv('CIPHERVAULT_SESSION_SECRET')
    if not secret:
        if mode == 'supabase':
            raise RuntimeError('Set CIPHERVAULT_SESSION_SECRET to a random secret of at least 32 characters.')
        secret_path = store.path.parent/'hosted-session.secret'
        try:
            with secret_path.open('x',encoding='ascii') as output:
                output.write(secrets.token_urlsafe(48))
        except FileExistsError:
            pass
        secret = secret_path.read_text(encoding='ascii')
    if len(secret)<32:
        raise RuntimeError('CIPHERVAULT_SESSION_SECRET must contain at least 32 characters.')
    app.config.update(SECRET_KEY=secret,MAX_CONTENT_LENGTH=crypto.MAX_PACKAGE,
                      SESSION_COOKIE_NAME='cv_account',SESSION_COOKIE_HTTPONLY=True,
                      SESSION_COOKIE_SAMESITE='Strict',SESSION_COOKIE_SECURE=bool(os.getenv('VERCEL')),
                      PERMANENT_SESSION_LIFETIME=dt.timedelta(hours=8))
    app.config.update(settings)
    app.extensions['accounts'] = store

    @app.before_request
    def authenticate():
        g.start = time.perf_counter()
        if not request.path.startswith('/api/'):
            return
        if request.method not in ('GET','HEAD','OPTIONS'):
            csrf = request.headers.get('X-CSRF-Token','')
            if not csrf or not secrets.compare_digest(csrf,session.get('csrf','')):
                abort(403,description='Refresh this page before submitting (CSRF check failed).')
            origin = request.headers.get('Origin')
            if origin and urlparse(origin).netloc != request.host:
                abort(403,description='Cross-site requests are not permitted.')
        if request.path in ('/api/session','/api/register','/api/login'):
            return
        g.token = session.get('access','')
        g.user = store.user(g.token) if g.token else None
        if not g.user:
            abort(401,description='Sign in to continue; your session may have expired.')

    @app.after_request
    def headers(response):
        cloud_origin = urlparse(os.getenv('SUPABASE_URL',''))
        connect = ' '+cloud_origin.scheme+'://'+cloud_origin.netloc if cloud_origin.scheme=='https' and cloud_origin.netloc else ''
        response.headers.update({'Cache-Control':'no-store','X-Content-Type-Options':'nosniff',
             'Referrer-Policy':'no-referrer','Content-Security-Policy':"default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'"+connect+"; img-src 'self' blob: data:; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'",
             'Permissions-Policy':'camera=(), microphone=(), geolocation=()'})
        if request.path.startswith('/api/'):
            response.headers['Server-Timing'] = f'app;dur={(time.perf_counter()-g.start)*1000:.3f}'
        return response

    @app.errorhandler(Exception)
    def error(exc):
        if isinstance(exc,HTTPException):
            status,message = exc.code,exc.description
        elif isinstance(exc,(ValueError,StoreError)):
            status,message = 400,str(exc)
        else:
            status,message = 500,'Operation could not complete. No plaintext was released.'
        return jsonify(error=message,elapsed_until_failure_seconds=time.perf_counter()-getattr(g,'start',time.perf_counter())),status

    def body():
        if request.content_length and request.content_length>256*1024:
            abort(413,description='Metadata request too large.')
        value = request.get_json()
        if not isinstance(value,dict):
            raise ValueError('Expected a JSON object.')
        return value

    def elapsed(**values):
        return jsonify(**values,operation_seconds=time.perf_counter()-g.start)

    def credentials():
        data = body()
        email,password = data.get('email',''),data.get('password','')
        if not isinstance(email,str) or not re.fullmatch(r'[^\s@]{1,64}@[^\s@]{1,185}\.[^\s@]{1,63}',email) or len(email)>254:
            raise ValueError('Enter a valid email address.')
        if not isinstance(password,str) or not 12<=len(password)<=128:
            raise ValueError('Account passwords require 12–128 characters.')
        if store.mode=='local':
            store.throttle('auth:'+hashlib.sha256((request.remote_addr or '').encode()).hexdigest(),30)
        return email.lower(),password

    def transfer(tid,sender=False,recipient=False):
        try:
            tid = str(uuid.UUID(tid))
        except ValueError:
            abort(404)
        record = store.get_transfer(g.token,tid)
        if not record or (sender and record['sender_id']!=g.user['id']) or (recipient and record['recipient_id']!=g.user['id']):
            abort(404,description='Transfer not found.')
        if dt.datetime.fromisoformat(record['expires_at'].replace('Z','+00:00'))<=utc_now():
            abort(410,description='Transfer has expired.')
        return record

    @app.get('/')
    def index():
        return send_file(ROOT/'hosted'/'index.html')

    @app.get('/health')
    def health():
        return jsonify(status='ok',mode=store.mode)

    @app.get('/api/session')
    def current_session():
        session.setdefault('csrf',secrets.token_urlsafe(32))
        token = session.get('access','')
        user = store.user(token) if token else None
        return elapsed(user=user,csrf=session['csrf'],mode=store.mode,ai_configured=bool(os.getenv('GEMINI_API_KEY')),
                       profile=store.profile(token,user['id']) if user else None)

    @app.post('/api/register')
    def register():
        return elapsed(**store.register(*credentials()))

    @app.post('/api/login')
    def login():
        token = store.login(*credentials())
        session.clear()
        session.update(access=token,csrf=secrets.token_urlsafe(32))
        session.permanent = True
        return elapsed(message='Signed in.',csrf=session['csrf'])

    @app.post('/api/logout')
    def logout():
        store.logout(g.token)
        session.clear()
        return elapsed(message='Signed out.')

    @app.get('/api/identity')
    def identity():
        return elapsed(profile=store.profile(g.token,g.user['id'],private=True))

    @app.post('/api/identity')
    def enroll():
        value = body()
        username = value.get('username','')
        if not isinstance(username,str) or not re.fullmatch('[a-zA-Z0-9_-]{3,32}',username):
            raise ValueError('Username: 3–32 letters, digits, underscores or hyphens.')
        public_bytes = unbase64(value.get('public_key'))
        key = load_der_public(public_bytes)
        if key.key_size!=3072:
            raise ValueError('Expected a 3072-bit RSA signing identity.')
        fingerprint = hashlib.sha256(public_bytes).hexdigest()
        if fingerprint!=value.get('fingerprint'):
            raise ValueError('Public-key fingerprint mismatch.')
        wrapped = value.get('wrapped_key')
        if not isinstance(wrapped,dict) or set(wrapped)!= {'salt','nonce','ciphertext','iterations'} or wrapped['iterations']!=600000 or len(unbase64(wrapped['salt']))!=16 or len(unbase64(wrapped['nonce']))!=12 or not 1000<=len(unbase64(wrapped['ciphertext']))<=4096:
            raise ValueError('Invalid encrypted private-key envelope.')
        store.enroll(g.token,{'username':username,'public_key':value['public_key'],'fingerprint':fingerprint,'wrapped_key':wrapped})
        return elapsed(message='Signing identity created. Keep your signing passphrase safe.')

    @app.get('/api/directory')
    def directory():
        return elapsed(users=store.directory(g.token))

    @app.get('/api/transfers')
    def transfers():
        return elapsed(transfers=store.transfers(g.token))

    @app.post('/api/transfers')
    def draft():
        data = body()
        profile = store.profile(g.token,g.user['id'])
        if not profile:
            raise ValueError('Create a signing identity first.')
        message = unbase64(data.get('message'),4096)
        manifest = json.loads(message)
        fields = {'id','sender_id','recipient_id','filename','size_bytes','package_bytes','original_sha256','package_sha256','published_at'}
        if not isinstance(manifest,dict) or set(manifest)!=fields or manifest['sender_id']!=g.user['id']:
            raise ValueError('Invalid signed transfer manifest.')
        tid = str(uuid.UUID(manifest['id']))
        recipient_id = str(uuid.UUID(manifest['recipient_id']))
        if tid!=manifest['id'] or recipient_id!=manifest['recipient_id'] or recipient_id==g.user['id'] or not store.profile(g.token,recipient_id):
            raise ValueError('Choose another registered recipient with a signing identity.')
        if manifest['filename']!=crypto.safe_filename(manifest['filename']) or type(manifest['size_bytes']) is not int or not 0<=manifest['size_bytes']<=crypto.MAX_FILE or type(manifest['package_bytes']) is not int or not 25<=manifest['package_bytes']<=crypto.MAX_PACKAGE:
            raise ValueError('Invalid filename or file size.')
        if any(not isinstance(manifest[k],str) or not re.fullmatch('[0-9a-f]{64}',manifest[k]) for k in ('original_sha256','package_sha256')):
            raise ValueError('Invalid file digest.')
        stamp = dt.datetime.fromisoformat(manifest['published_at'].replace('Z','+00:00'))
        if stamp.tzinfo is None or abs((utc_now()-stamp).total_seconds())>3600:
            raise ValueError('Check the sender clock; publication time is outside the one-hour window.')
        signature = unbase64(data.get('signature'),1024)
        verification = crypto.verify_file(message,signature,load_der_public(unbase64(profile['public_key'])))
        if not verification['valid']:
            raise ValueError('Transfer signature is invalid.')
        timings = data.get('timings',{})
        if not isinstance(timings,dict) or set(timings)!= {'encryption_seconds','aes_seconds','hash_seconds','sign_seconds','key_setup_seconds'} or any(type(n) not in (int,float) or not math.isfinite(n) or not 0<=n<=3600 for n in timings.values()):
            raise ValueError('Invalid transfer measurements.')
        created_at = utc_now()
        record = {'id':tid,'sender_id':g.user['id'],'recipient_id':recipient_id,'manifest':manifest,
                  'message':data['message'],'signature':data['signature'],'public_key':profile['public_key'],
                  'fingerprint':profile['fingerprint'],'object_path':g.user['id']+'/'+tid+'.cvault',
                  'created_at':created_at.isoformat(),'expires_at':(created_at+dt.timedelta(hours=24)).isoformat(),
                  'timings':timings,'upload_seconds':None}
        upload = store.create_transfer(g.token,record)
        return elapsed(id=tid,**upload,server_signature_seconds=verification['verify_seconds'],server_hash_seconds=verification['hash_seconds'])

    @app.put('/api/transfers/<tid>/upload')
    def upload(tid):
        if store.mode!='local':
            abort(404)
        record = transfer(tid,sender=True)
        package = request.get_data()
        meta,*_ = crypto.parse_package(package)
        manifest = record['manifest']
        if len(package)!=manifest['package_bytes'] or hashlib.sha256(package).hexdigest()!=manifest['package_sha256'] or meta['sha256']!=manifest['original_sha256'] or meta['filename']!=manifest['filename'] or meta['size']!=manifest['size_bytes']:
            raise ValueError('Uploaded package does not match the signed manifest.')
        store.upload(g.token,tid,package)
        return elapsed(message='Encrypted package uploaded.')

    @app.post('/api/transfers/<tid>/publish')
    def publish(tid):
        transfer(tid,sender=True)
        seconds = body().get('upload_seconds')
        if type(seconds) not in (int,float) or not math.isfinite(seconds) or not 0<=seconds<=3600:
            raise ValueError('Invalid measured upload duration.')
        store.publish(g.token,tid,seconds)
        return elapsed(message='File sent. Awaiting recipient verification.')

    @app.get('/api/transfers/<tid>/download')
    def download(tid):
        record = transfer(tid,recipient=True)
        if record['status'] not in ('sent','verified'):
            abort(409,description='Sender has not finished uploading this file.')
        if store.mode=='supabase':
            return elapsed(download_url=store.download_url(g.token,record))
        return app.response_class(store.download(g.token,tid),mimetype='application/octet-stream')

    @app.post('/api/transfers/<tid>/receipt')
    def receipt(tid):
        record = transfer(tid,recipient=True)
        report = body()
        fields = {'sha256','signature_valid','network_seconds','decrypt_seconds','aes_seconds','hash_seconds','signature_seconds','receive_seconds','recovered_at'}
        if set(report)!=fields or report['sha256']!=record['manifest']['original_sha256'] or report['signature_valid'] is not True:
            raise ValueError('Receipt must report matching hashes and a verified signature.')
        if any(type(report[k]) not in (int,float) or not math.isfinite(report[k]) or not 0<=report[k]<=3600 for k in fields-{'sha256','signature_valid','recovered_at'}):
            raise ValueError('Invalid receipt timing.')
        if not isinstance(report['recovered_at'],str) or len(report['recovered_at'])>40 or dt.datetime.fromisoformat(report['recovered_at'].replace('Z','+00:00')).tzinfo is None:
            raise ValueError('Invalid recovery timestamp.')
        report['recorded_at'] = utc_now().isoformat()
        store.receipt(g.token,tid,report)
        return elapsed(message='Receiver confirmation recorded.')

    @app.delete('/api/transfers/<tid>')
    def delete(tid):
        # Allow sender cleanup even after expiry.
        record = store.get_transfer(g.token,tid)
        if not record or record['sender_id']!=g.user['id']:
            abort(404)
        store.delete(g.token,tid)
        return elapsed(message='Transfer and encrypted storage deleted.')

    @app.get('/api/results')
    def results():
        return elapsed(results=store.results(g.token))

    @app.post('/api/results/<kind>')
    def save_result(kind):
        if kind not in RESULT_KINDS:
            abort(404)
        value = safe_results(body())
        if len(json.dumps(value))>200_000:
            raise ValueError('Result too large to save.')
        store.save_result(g.token,kind,value)
        return elapsed(message='Measurements saved to your account.')

    @app.post('/api/analysis/<kind>')
    def analysis(kind):
        data = body()
        if store.mode=='local':
            store.throttle('compute:'+g.user['id'],30)
        else:
            store.call('POST','/rest/v1/rpc/cv_compute_slot',g.token,{})
        if kind=='benchmarks':
            value = run_benchmarks()
        elif kind=='avalanche':
            result = confusion_diffusion(bytes.fromhex(data.get('block','00112233445566778899aabbccddeeff')),32)
            value = {**result.value,'total_seconds':result.seconds}
        elif kind=='lengths':
            result = aes_length_analysis()
            value = {**result.value,'total_seconds':result.seconds}
        elif kind=='password_lengths':
            result = password_length_analysis()
            value = {**result.value,'total_seconds':result.seconds}
        elif kind=='hash_resistance':
            result = hashing_resistance_analysis(attempts=5000,repeats=3)
            value = {**result.value,'total_seconds':result.seconds}
        else:
            abort(404)
        value = safe_results(value)
        store.save_result(g.token,kind,value)
        return elapsed(result=value)

    @app.post('/api/ai')
    def ai():
        value = body()
        if store.mode=='local':
            store.throttle('ai:'+g.user['id'],15)
        else:
            store.call('POST','/rest/v1/rpc/cv_compute_slot',g.token,{})
        # Only stored numeric benchmark rows accompany an explicitly submitted question.
        rows = store.results(g.token).get('benchmarks',{}).get('rows',[])
        result = ask_assistant(value.get('question',''),rows)
        return elapsed(answer=result.value,response_latency_seconds=result.seconds)

    return app


if __name__=='__main__':
    create_app().run(host='127.0.0.1',port=int(os.getenv('CIPHERVAULT_WEB_PORT','8502')),debug=False)
