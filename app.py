"""Run with: python -m streamlit run app.py"""
import os
import time
import sqlite3
import base64
import json
from html import escape
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import pandas as pd
import streamlit as st
from dotenv import load_dotenv

import crypto_service as crypto
from ai_service import ask_assistant
from benchmark_service import run_benchmarks, throughput
from transfer_service import TransferService, lan_ipv4
from dashboard_style import CSS
from analysis_ui import render_analysis
from vault_charts import record_measurement, show_operation_graph, show_vault_comparison
from storage_service import ResultStore
from render_access import require_demo_access

load_dotenv()
st.set_page_config(page_title='CipherVault', page_icon='🔐', layout='wide')
render_demo = require_demo_access()
store = None
try:
    if not render_demo:
        store = ResultStore()
        store.restore(st.session_state)
except (OSError, ValueError, sqlite3.Error):
    st.warning('Saved results could not be loaded. Check local_data permissions or use Clear saved results if available.')


@st.cache_resource
def receiver_runtime(profile):
    # Live process resource only. Never serialize TLS keys or transfer capabilities.
    return {'service':None}


runtime = receiver_runtime(str(store.path) if store is not None else 'local-workspace')
receiver = st.session_state.get('transfer_service') or runtime['service']
if receiver is not None and not hasattr(receiver,'signing_fingerprint'):
    receiver.stop()
    receiver = None
    for field in ('transfer_service','transfer_token','transfer_plain_preview'):
        st.session_state.pop(field,None)
    st.info('The transfer receiver was updated. Start it again and verify its new certificate and signing-key fingerprint.')
if receiver is not None and receiver.thread.is_alive():
    st.session_state.transfer_service = receiver
    runtime['service'] = receiver
else:
    st.session_state.pop('transfer_service',None)
    runtime['service'] = None
st.markdown(CSS, unsafe_allow_html=True)
st.sidebar.markdown('<div class="brand"><span class="brand-mark">◇</span>CipherVault</div><div class="brand-sub">SECURITY WORKSPACE</div>', unsafe_allow_html=True)
LABELS = {'Overview': 'Dashboard', 'File Encryption and Decryption': 'File vault',
          'Device-to-Device Transfer': 'Device transfer', 'Hashing and Digital Signatures': 'Integrity & signatures',
          'Performance Dashboard': 'Benchmarks', 'Cryptographic Analysis': 'Analysis lab', 'AI Assistant': 'AI assistant'}
section = st.sidebar.radio('Workspace', ['Overview', 'File Encryption and Decryption',
    'Device-to-Device Transfer', 'Hashing and Digital Signatures', 'Performance Dashboard', 'Cryptographic Analysis', 'AI Assistant'],
    format_func=LABELS.get, key='workspace_section', label_visibility='collapsed')
st.sidebar.divider()
st.sidebar.caption('AES-256-GCM · RSA-PSS')
st.sidebar.caption(('Render demonstration' if render_demo else 'Local workspace') + ' · 20 MiB / file')
if render_demo and st.sidebar.button('Lock laboratory'):
    st.session_state.clear()
    st.rerun()
with st.sidebar.expander('Saved results'):
    st.caption('This hosted laboratory keeps results only in your browser session. Download outputs before refreshing. Uploaded files are processed on the Render server.' if render_demo else 'Charts and encrypted packages are saved locally. Passwords, private keys and recovered plaintext are not saved.')
    if store is not None:
        st.button('Clear saved results',on_click=store.clear,args=(st.session_state,))
header, status_badge = st.columns([4, 1])
with header:
    st.markdown('<div class="section-kicker">CipherVault / Workspace</div>', unsafe_allow_html=True)
    st.title(LABELS[section])
with status_badge:
    st.markdown('<span class="status-pill">● ' + ('Render demo' if render_demo else 'Local workspace') + '</span>', unsafe_allow_html=True)


def duration(label, seconds):
    st.caption(f'{label} · {seconds*1000:.4f} ms' if seconds < 1 else f'{label} · {seconds:.4f} s')


def navigate(section):
    st.session_state.workspace_section = section


def compact_time(seconds):
    return f'{seconds*1000:.3f} ms' if seconds < 1 else f'{seconds:.3f} s'


def failure(exc, start):
    st.error(str(exc) or 'Operation failed.')
    duration('Elapsed time until failure', time.perf_counter() - start)


def read(upload):
    if upload is None:
        raise ValueError('Select the required file first.')
    if upload.size > crypto.MAX_FILE:
        raise ValueError('File exceeds the 20 MiB limit.')
    return upload.getvalue()


def read_key(upload):
    if upload is None or upload.size != 32:
        raise ValueError('Upload a .key file containing exactly 32 raw bytes (256 bits).')
    return crypto.validate_aes_key(upload.getvalue())


def workflow_result(result, mode):
    value = result.value
    st.success('Encrypted package ready.' if mode == 'Encryption' else 'Previous recovery authenticated; hash matched.' if value.get('_restored') else 'Recovered file authenticated. Hash matches.')
    st.write(value['metadata']['filename'])
    timing = st.columns(3)
    timing[0].metric('AES '+mode.lower(), compact_time(value['aes_seconds']))
    timing[1].metric('SHA-256', compact_time(value['hash_seconds']))
    timing[2].metric('Total workflow', compact_time(result.seconds))
    method = 'Key file' if value['metadata']['kdf'] == 'RAW-KEY' else 'Password'
    st.caption(f'{value["metadata"]["size"]:,} bytes · AES {throughput(value["metadata"]["size"], value["aes_seconds"]):.3f} MB/s · {method}')
    if 'key_setup_seconds' in value:
        duration('Key-file validation' if method == 'Key file' else 'Password key derivation',value['key_setup_seconds'])
    with st.expander('SHA-256 digest'):
        st.code(value['metadata']['sha256'], language=None)
    if mode == 'Encryption':
        st.caption(f'Package size · {len(value["package"]):,} bytes')
        st.download_button('Download encrypted package', value['package'],
                           value['metadata']['filename']+'.cvault', 'application/octet-stream')
    else:
        if 'data' in value:
            st.download_button('Download recovered file', value['data'], value['metadata']['filename'], 'application/octet-stream')
        else:
            st.info('Saved timings restored. '+('Re-upload the original key file' if method == 'Key file' else 'Re-enter the package password')+' and click Authenticate and decrypt to unlock the recovered download.')
    show_operation_graph(result, mode)


if section == 'Overview':
    st.caption('Your files, transfers and measured performance in one place.')
    metrics = st.columns(4)
    metrics[0].metric('Encrypted outputs', sum(k in st.session_state for k in ('enc_result','transfer_encrypted')))
    metrics[1].metric('Recovered outputs', int('dec_result' in st.session_state))
    metrics[2].metric('Benchmark sizes', len(st.session_state.get('benchmarks', {}).get('rows', [])))
    metrics[3].metric('LAN receiver', 'Online' if 'transfer_service' in st.session_state else 'Offline')
    st.caption('Saved outputs and measurements · Receiver status is live')
    st.subheader('Quick actions')
    cards = st.columns(3)
    for card, icon, title, description, target in zip(cards, ['◇','↗','◎'],
        ['File vault','Device transfer','Integrity & signatures'],
        ['Encrypt a file or recover an encrypted package.', 'Send an encrypted file to another device.', 'Compare hashes, sign files and verify signatures.'],
        ['File Encryption and Decryption','Device-to-Device Transfer','Hashing and Digital Signatures']):
        with card, st.container(border=True):
            st.markdown(f'<div class="tool-icon">{icon}</div>', unsafe_allow_html=True)
            st.subheader(title)
            st.caption(description)
            st.button('Open '+title.lower(), key='quick_'+target, on_click=navigate, args=(target,), width='stretch')
    performance, activity = st.columns([1.6, 1])
    with performance, st.container(border=True):
        st.subheader('Performance snapshot')
        benchmark = st.session_state.get('benchmarks')
        if benchmark:
            snapshot = pd.DataFrame(benchmark['rows'])
            st.line_chart(snapshot, x='size_KiB', y=['aes_encrypt_ms','aes_decrypt_ms'], x_label='File size (KiB)', y_label='AES duration (ms)', color=['#38bdf8','#6ee7b7'])
            duration('Last benchmark run', benchmark['total_seconds'])
            st.button('View all benchmarks', on_click=navigate, args=('Performance Dashboard',))
        else:
            st.markdown('<div class="empty-chart"><strong>No measurements yet</strong><span>Run a benchmark to see encryption performance.</span></div>', unsafe_allow_html=True)
            if st.button('Run benchmark', type='primary'):
                start = time.perf_counter()
                try:
                    with st.spinner('Measuring…'):
                        st.session_state.benchmarks = run_benchmarks()
                    if store is not None: store.sync(st.session_state)
                    st.rerun()
                except Exception as exc: failure(exc, start)
    with activity, st.container(border=True):
        st.subheader('Saved activity')
        entries = []
        for key, title in [('enc_result','File encrypted'),('dec_result','File recovered'),('transfer_encrypted','Transfer prepared')]:
            if key in st.session_state:
                result = st.session_state[key]
                entries.append((title, f'{result.value["metadata"]["filename"]} · {compact_time(result.seconds)}'))
        if 'signature' in st.session_state:
            entries.append(('RSA signature created', compact_time(st.session_state.signature['sign_seconds'])))
        if benchmark:
            entries.append(('Benchmark completed', f'{len(benchmark["rows"])} sizes · {compact_time(benchmark["total_seconds"])}'))
        if entries:
            for title, detail in entries:
                st.markdown(f'<div class="activity-row"><strong>{escape(title)}</strong><span>{escape(detail)}</span></div>', unsafe_allow_html=True)
        else:
            st.caption('No completed operations yet.')
        st.divider()
        st.caption('AI assistant · '+('Configured' if os.getenv('GEMINI_API_KEY') else 'API key required'))
        st.button('Open assistant', on_click=navigate, args=('AI Assistant',), width='stretch')
    with st.expander('Security & measurement notes'):
        st.caption('Password encryption uses PBKDF2-SHA256 with fresh salts. File vault also accepts 256-bit key files. Keep credentials separate from packages and trust certificates and public keys through a verified channel.')
        st.caption('Python timings use perf_counter(); receiver timings use performance.now(). MB/s = bytes / 1,000,000 / seconds. Benchmark sizes use KiB/MiB. Full setup and limitations are in README.md.')

elif section == 'File Encryption and Decryption':
    st.caption('Password or key file · AES-256-GCM · Up to 20 MiB')
    encrypt_tab, decrypt_tab = st.tabs(['Encrypt', 'Decrypt'])
    with encrypt_tab:
        inputs, output = st.columns([1, 1.25])
        with inputs, st.container(border=True):
            st.subheader('Encrypt a file')
            upload = st.file_uploader('Original file', key='enc_file')
            method = st.selectbox('Encryption method',['Password','Key file'],key='enc_method')
            if method == 'Key file':
                key_upload = st.file_uploader('AES-256 key file',type=['key'],key='enc_key_file',help='Exactly 32 raw bytes. Use demo_files/demo_key.key for testing only.')
                password = None
                st.caption('Keep the key separate. Anyone with it can decrypt this file.')
            else:
                key_upload = None
                password = st.text_input('Password', type='password', key='enc_password', help='At least 12 characters. Keep this password separate from the package.')
            if st.button('Encrypt with AES-256-GCM', type='primary', width='stretch'):
                st.session_state.pop('enc_result', None)
                start = time.perf_counter()
                try:
                    data = read(upload)
                    st.session_state.enc_result = crypto.encrypt_file(data,password,upload.name,
                        key=read_key(key_upload) if method == 'Key file' else None)
                    st.session_state.vault_measurements = record_measurement(
                        st.session_state.get('vault_measurements', []), st.session_state.enc_result, 'Encryption')
                except Exception as exc:
                    failure(exc, start)
        with output, st.container(border=True):
            st.subheader('Encrypted output')
            if 'enc_result' in st.session_state:
                workflow_result(st.session_state.enc_result, 'Encryption')
            else:
                st.caption('Your package and measured timings will appear here.')
    with decrypt_tab:
        inputs, output = st.columns([1, 1.25])
        with inputs, st.container(border=True):
            st.subheader('Recover a file')
            upload = st.file_uploader('CipherVault package', type=['cvault'], key='dec_file')
            if upload is None and 'dec_package' in st.session_state:
                st.caption('Your last successfully decrypted package is saved. Provide its password or original key file to recover it again.')
            preview = upload.getvalue() if upload is not None and upload.size <= crypto.MAX_PACKAGE else st.session_state.get('dec_package') if upload is None else None
            key_mode = False
            if preview is not None:
                try:
                    key_mode = crypto.parse_package(preview)[0]['kdf'] == 'RAW-KEY'
                except ValueError:
                    pass
            if key_mode:
                st.caption('This package requires the AES key file used for encryption.')
                key_upload = st.file_uploader('Original AES-256 key file',type=['key'],key='dec_key_file')
                password = None
            else:
                key_upload = None
                password = st.text_input('Package password', type='password', key='dec_password')
            if st.button('Authenticate and decrypt', type='primary', width='stretch'):
                st.session_state.pop('dec_result', None)
                start = time.perf_counter()
                try:
                    if upload is not None and upload.size > crypto.MAX_PACKAGE:
                        raise ValueError('Select a package within the size limit.')
                    package = upload.getvalue() if upload is not None else st.session_state.get('dec_package')
                    if package is None:
                        raise ValueError('Select a package first.')
                    st.session_state.dec_result = crypto.decrypt_file(package,password,
                        key=read_key(key_upload) if key_mode else None)
                    st.session_state.dec_package = package
                    st.session_state.vault_measurements = record_measurement(
                        st.session_state.get('vault_measurements', []), st.session_state.dec_result, 'Decryption')
                except Exception as exc:
                    failure(exc, start)
        with output, st.container(border=True):
            st.subheader('Recovered output')
            if 'dec_result' in st.session_state:
                workflow_result(st.session_state.dec_result, 'Decryption')
            else:
                st.caption('Authenticate a package to recover its original file.')
    show_vault_comparison(duration, failure, run_benchmarks)

elif section == 'Hashing and Digital Signatures':
    hashing, signatures, experiment = st.tabs(['SHA-256 integrity', 'RSA-PSS signatures', 'Avalanche experiment'])
    with hashing:
        st.caption('Compare original and recovered files. Matching hashes check integrity, not sender identity.')
        first, second = st.columns(2)
        a = first.file_uploader('Original file', key='hash_a')
        b = second.file_uploader('Comparison file (optional)', key='hash_b')
        actions = st.columns(3)
        if actions[0].button('Compute SHA-256', width='stretch', type='primary'):
            start = time.perf_counter()
            st.session_state.pop('hash_result',None)
            try:
                data = read(a); result = crypto.hash_file(data)
                st.session_state.hash_result = result
                st.session_state.hash_size = len(data)
            except Exception as exc: failure(exc, start)
        if 'hash_result' in st.session_state:
            result = st.session_state.hash_result
            st.code(result.value,language=None); duration('SHA-256',result.seconds)
            st.caption(f'Hashing throughput: {throughput(st.session_state.hash_size,result.seconds):.3f} MB/s')
        if actions[1].button('Compare files', width='stretch'):
            start = time.perf_counter()
            st.session_state.pop('hash_comparison',None)
            try:
                st.session_state.hash_comparison = crypto.compare_files(read(a),read(b))
            except Exception as exc: failure(exc, start)
        if 'hash_comparison' in st.session_state:
            result = st.session_state.hash_comparison
            duration('Complete file comparison',result.seconds)
            for name in ('first','second'):
                st.code(result.value[name].value,language=None)
                duration(name.title()+' hash',result.value[name].seconds)
            st.write(f'Hashes equal: {result.value["hash_equal"]} · Bytes equal: {result.value["bytes_equal"]}')
        if actions[2].button('One-byte demo', width='stretch'):
            start = time.perf_counter()
            st.session_state.pop('hash_byte_demo',None)
            try:
                data = read(a)
                if not data: raise ValueError('Choose a nonempty file for a one-byte change.')
                altered = bytes([data[0] ^ 1]) + data[1:]
                result = crypto.compare_files(data, altered)
                st.session_state.hash_byte_demo = {'comparison':result,'seconds':time.perf_counter()-start}
            except Exception as exc: failure(exc, start)
        if 'hash_byte_demo' in st.session_state:
            demo = st.session_state.hash_byte_demo
            result = demo['comparison']
            duration('One-byte demonstration',demo['seconds'])
            for name in ('first','second'):
                st.code(result.value[name].value,language=None)
                duration(name.title()+' hash',result.value[name].seconds)
            st.write('Digest changed:',not result.value['hash_equal'])
            st.caption('This observation does not prove preimage, second-preimage or collision resistance.')
    with signatures:
        st.caption('RSA-PSS · 3072 bits · Verify using a public key you trust.')
        if st.button('Generate 3072-bit RSA key pair'):
            start = time.perf_counter()
            try:
                result = crypto.generate_keys(); st.session_state.rsa_key = result.value
                st.session_state.rsa_setup_seconds = result.seconds
                st.session_state.pop('signature', None)
            except Exception as exc: failure(exc, start)
        if 'rsa_key' in st.session_state:
            key = st.session_state.rsa_key
            duration('RSA key generation (setup)', st.session_state.rsa_setup_seconds)
            st.download_button('Export public key', crypto.public_pem(key), 'public.pem')
            with st.expander('Private-key backup'):
                export_password = st.text_input('Private-key export password', type='password')
                if st.button('Protect private key for export'):
                    start = time.perf_counter()
                    try:
                        result = crypto.private_pem(key, export_password)
                        duration('Private-key encryption and serialization', result.seconds)
                        st.download_button('Download encrypted private key', result.value, 'private-encrypted.pem')
                    except Exception as exc: failure(exc, start)
            signing_file = st.file_uploader('File to sign', key='sign_file')
            if st.button('Sign file'):
                st.session_state.pop('signature', None)
                start = time.perf_counter()
                try:
                    st.session_state.signature = crypto.sign_file(read(signing_file), key)
                    st.session_state.signature_public = crypto.public_pem(key)
                except Exception as exc: failure(exc, start)
        else: st.info('Generate a key pair to sign. Verification also accepts an uploaded public key.')
        if 'signature' in st.session_state:
            signed = st.session_state.signature
            duration('SHA-256 before signing',signed['hash_seconds'])
            duration('RSA-PSS signing of digest',signed['sign_seconds'])
            st.download_button('Download signature',signed['signature'],'file.sig')
            if 'signature_public' in st.session_state:
                st.download_button('Download signature public key',st.session_state.signature_public,'signature-public.pem')
        st.divider()
        st.subheader('Verify a signature')
        verification_files = st.columns(3)
        vf = verification_files[0].file_uploader('File to verify', key='verify_file')
        sf = verification_files[1].file_uploader('Signature', type=['sig'], key='verify_sig')
        pf = verification_files[2].file_uploader('Trusted public key PEM', type=['pem'], key='verify_key')
        if st.button('Verify signature'):
            start = time.perf_counter()
            st.session_state.pop('verification_result',None)
            try:
                if sf is None or pf is None or sf.size > 512 or pf.size > 8192:
                    raise ValueError('Provide a signature (≤512 bytes) and public key (≤8 KiB).')
                loaded = crypto.measured(crypto.load_public, pf.getvalue())
                result = crypto.verify_file(read(vf), sf.getvalue(), loaded.value)
                st.session_state.verification_result = {**result,'key_parse_seconds':loaded.seconds}
            except Exception as exc: failure(exc, start)
        if 'verification_result' in st.session_state:
            result = st.session_state.verification_result
            duration('Public-key parsing',result['key_parse_seconds'])
            duration('SHA-256 before verification',result['hash_seconds'])
            duration('RSA-PSS verification of digest',result['verify_seconds'])
            (st.success if result['valid'] else st.error)('Recorded verification: signature valid for that key and content.' if result['valid'] else 'Recorded verification failed: content, signature or key did not match.')
    with experiment:
        st.caption('Flip one plaintext bit and measure how many AES output bits change.')
        with st.expander('Experiment method'):
            st.caption('Two 128-bit blocks use the same random AES-256 key. Isolated ECB block analysis is educational only, never used for files or transfer. No GCM nonce is reused.')
        block_hex = st.text_input('128-bit plaintext in hexadecimal', '00112233445566778899aabbccddeeff')
        bit = st.number_input('Bit index (byte index × 8 + least-significant bit index)', 0, 127, 0)
        if st.button('Measure avalanche effect'):
            start = time.perf_counter()
            st.session_state.pop('avalanche_result',None)
            try:
                st.session_state.avalanche_result = crypto.avalanche(bytes.fromhex(block_hex), int(bit))
            except Exception as exc: failure(exc, start)
        if 'avalanche_result' in st.session_state:
            result = st.session_state.avalanche_result
            st.json(result.value);duration('Avalanche experiment',result.seconds)
        st.caption('One experiment does not prove security or guarantee exactly 50% changed bits.')

elif section == 'Device-to-Device Transfer':
    if render_demo:
        st.info('For transfers between accounts, use the CipherVault account website. The original LAN receiver runs on your local computer.')
        st.link_button('Open account transfers', 'https://ciphervault-alpha.vercel.app')
        st.caption('Render hosts this Python laboratory. Its server is outside your Wi-Fi network and cannot provide your original LAN receiver URL.')
        st.stop()
    st.caption('Encrypted delivery over your private network. Share the password separately.')
    setup, guide = st.columns([1.3, 1])
    with setup, st.container(border=True):
        st.subheader('Receiver connection')
        address_col, port_col = st.columns([2, 1])
        address = address_col.text_input('LAN IPv4', lan_ipv4(), help='Find your Wi-Fi IPv4 address with ipconfig.')
        port = port_col.number_input('HTTPS port', 1024, 65535, 8765)
        st.caption('Status · '+('Online' if 'transfer_service' in st.session_state else 'Offline'))
    with guide, st.container(border=True):
        st.subheader('Connect another device')
        st.caption('01  Start the receiver on this computer.')
        st.caption('02  Verify and trust its certificate.')
        st.caption('03  Open the receiver URL and enter your token.')
        st.caption('04  Enter the verified signing-key fingerprint and password, then receive.')
    if 'transfer_service' not in st.session_state:
        if st.button('Start LAN HTTPS receiver', type='primary'):
            start = time.perf_counter()
            try:
                service = TransferService('0.0.0.0', int(port), address)
                st.session_state.transfer_service = service
                runtime['service'] = service
                st.rerun()
            except Exception as exc: failure(exc, start)
    else:
        service = st.session_state.transfer_service
        duration('TLS certificate and RSA setup', service.setup.seconds)
        duration('Transfer RSA signing-key generation',service.signing_setup.seconds)
        st.code(f'https://{service.lan_ip}:{service.port}/', language=None)
        st.caption('Verify the certificate fingerprint before trusting it on the receiver.')
        st.caption('Signing-key fingerprint · Copy to the receiver through a trusted channel')
        st.code(service.signing_fingerprint,language=None)
        with st.expander('Certificate & device setup'):
            st.code(service.fingerprint, language=None)
            st.download_button('Download receiver certificate for trust setup', service.certificate, 'ciphervault-receiver.pem')
            st.caption('Trust this certificate on the second device. Certificate-warning bypasses may block Web Crypto. Windows, Android, iOS and private-network firewall steps are in README.md.')
        file = st.file_uploader('File to transfer', key='transfer_file')
        pw = st.text_input('Strong transfer password (share separately)', type='password', key='transfer_pw')
        if st.button('Encrypt and publish single-use transfer', type='primary'):
            start = time.perf_counter()
            st.session_state.pop('transfer_token', None)
            st.session_state.pop('transfer_plain_preview',None)
            try:
                data = read(file)
                result = crypto.encrypt_file(data, pw, file.name)
                published = crypto.measured(service.publish, result.value['package'], result.seconds, start=start)
                st.session_state.transfer_token = published.value
                st.session_state.transfer_encrypted = result
                preview = data[:512]
                try:
                    text_preview = preview.decode('utf-8')
                    if any(ord(c)<32 and c not in '\n\r\t' for c in text_preview):
                        raise ValueError('Binary preview')
                except (UnicodeError,ValueError):
                    text_preview = 'Binary bytes (hex): '+preview.hex()
                st.session_state.transfer_plain_preview = text_preview or '(empty file)'
                duration('Publish encrypted package', published.seconds)
            except Exception as exc: failure(exc, start)
        if 'transfer_token' in st.session_state:
            st.caption('Transfer token · One download · Expires after 5 minutes')
            st.code(st.session_state.transfer_token, language=None)
            result = st.session_state.transfer_encrypted
            duration('Transfer encryption workflow', result.seconds)
            duration('Transfer AES encryption', result.value['aes_seconds'])
            duration('Original SHA-256', result.value['hash_seconds'])
            st.write(f'File: {result.value["metadata"]["size"]:,} bytes · Package: {len(result.value["package"]):,} bytes')
            st.code(result.value['metadata']['sha256'], language=None)
            with st.expander('Original plaintext preview · first 512 bytes · session only'):
                st.code(st.session_state.get('transfer_plain_preview','Preview cleared after refresh; plaintext is not saved.'),language=None)
            with st.expander('Encrypted message preview · first 256 ciphertext bytes · hexadecimal'):
                *_,ciphertext = crypto.parse_package(result.value['package'])
                st.code(ciphertext[:min(result.value['metadata']['size'],256)].hex() or '(empty plaintext)',language=None)
        if service.last_proof:
            proof = service.last_proof
            manifest = json.loads(base64.b64decode(proof['message']))
            st.caption('Published at (sender UTC): '+manifest['published_at'])
            duration('Transfer package SHA-256',proof['package_hash_seconds'])
            duration('Signature manifest SHA-256',proof['hash_seconds'])
            duration('RSA-PSS transfer signing',proof['sign_seconds'])
            with st.expander('Digital signature · RSA-PSS / SHA-256'):
                st.code(proof['signature'],language=None)
                st.download_button('Download transfer signature',base64.b64decode(proof['signature']),'transfer.sig')
                st.download_button('Download signed transfer manifest',base64.b64decode(proof['message']),'transfer-manifest.json')
                st.download_button('Download transfer signing public key',crypto.public_pem(service._signing_key),'transfer-public.pem')
            st.caption('Signature covers the encrypted package hash, original file hash, filename and publication timestamp. Decrypted message preview appears only on the receiver.')
        st.button('Refresh receiver receipt')
        status = service.status()
        if status:
            if status['hash_matches'] and status.get('signature_valid') is True:
                st.success('File successfully transferred and recovered — receiver reports matching SHA-256 and verified digital signature.')
            elif not status['hash_matches']:
                st.error('Receiver reported a hash mismatch.')
            else:
                st.warning('Receiver reports a matching hash; signature verification was not reported.')
            st.write('Original SHA-256: '+status['original_sha256'])
            st.write('Recovered SHA-256: '+status['sha256'])
            st.caption('Published (sender UTC): '+status['published_at'])
            st.caption('Recovered (receiver UTC): '+status.get('received_at','Not reported'))
            st.caption('Receipt recorded (sender UTC): '+status['receipt_at'])
            if 'signature_seconds' in status:
                duration('Receiver RSA-PSS verification (includes import and hashing)',status['signature_seconds'])
            for label, field in [('Network request + complete body (receiver reported)','network_seconds'),
                ('Receiver decryption workflow','decrypt_seconds'), ('Recovered SHA-256','hash_seconds'),
                ('Receive and recovery','receive_seconds'), ('Active total: encryption + signing/hashing + receive/recovery','active_total_seconds'),
                ('Wall total: encryption start to receipt, includes human waiting','wall_total_seconds')]:
                duration(label, status[field])
            if status['server_write_seconds'] is not None: duration('Server response write (not end-to-end delivery)', status['server_write_seconds'])
            st.write(f'Network throughput: {throughput(status["package_bytes"], status["network_seconds"]):.3f} MB/s')
            st.caption('Receiver-reported metrics, including signature, authentication and hash checks. Device-clock timestamps are not trusted timestamp-authority evidence.')
        else: st.caption('No receiver receipt yet. Receive on the second device, then refresh.')
        if st.button('Stop receiver and revoke transfers'):
            service.stop(); del st.session_state.transfer_service
            runtime['service'] = None
            st.session_state.pop('transfer_token', None)
            st.session_state.pop('transfer_encrypted', None)
            st.session_state.pop('transfer_plain_preview',None)
            st.rerun()

elif section == 'Performance Dashboard':
    st.caption('Actual measurements · 6 file sizes · Median of 3 trials')
    with st.expander('Measurement method & units'):
        st.caption('AES excludes password derivation. RSA signing/verification excludes file hashing; prehash times are separate CSV columns. RSA key generation is setup. MB/s = original bytes / 1,000,000 / seconds. Timings vary with hardware and load.')
    if st.button('Run benchmark: 1 KiB to 10 MiB', type='primary'):
        start = time.perf_counter()
        try:
            with st.spinner('Measuring and validating actual operations…'):
                st.session_state.benchmarks = run_benchmarks()
        except Exception as exc: failure(exc, start)
    if 'benchmarks' not in st.session_state:
        st.markdown('<div class="empty-chart"><strong>No benchmark results yet</strong><span>Run a benchmark to generate charts and a CSV export.</span></div>', unsafe_allow_html=True)
    else:
        result = st.session_state.benchmarks
        duration('Total benchmark run', result['total_seconds'])
        duration('RSA key generation (setup)', result['key_generation_seconds'])
        df = pd.DataFrame(result['rows'])
        with st.expander('All measurements'):
            st.dataframe(df, hide_index=True, width='stretch')
        st.download_button('Download measurements CSV', df.to_csv(index=False), 'ciphervault-benchmarks.csv', 'text/csv')
        charts = [('AES encryption time', ['aes_encrypt_ms'], 'Duration (ms)'),
                  ('AES decryption time', ['aes_decrypt_ms'], 'Duration (ms)'),
                  ('SHA-256 hashing time', ['sha256_ms'], 'Duration (ms)'),
                  ('AES throughput', ['aes_encrypt_MB_s','aes_decrypt_MB_s'], 'Throughput (MB/s)'),
                  ('RSA-PSS digest signing and verification', ['rsa_sign_ms','rsa_verify_ms'], 'Duration (ms)')]
        columns = st.columns(2)
        with plt.style.context('dark_background'):
            for i, (title, fields, ylabel) in enumerate(charts):
                fig, ax = plt.subplots(figsize=(7,4))
                for field in fields: ax.plot(df['size_KiB'], df[field], marker='o', label=field.replace('_',' '))
                ax.set(xscale='log', xlabel='Input size (KiB, logarithmic axis)', ylabel=ylabel, title=title)
                ax.grid(alpha=.2); ax.legend(); fig.tight_layout()
                columns[i%2].pyplot(fig); plt.close(fig)

elif section == 'Cryptographic Analysis':
    render_analysis(duration, failure)

elif section == 'AI Assistant':
    st.caption('Explain algorithms, errors and your benchmark results.')
    st.caption('Questions go to Gemini. Keep passwords, keys and sensitive files out of the chat.')
    if not os.getenv('GEMINI_API_KEY'):
        st.info('Assistant offline · Add GEMINI_API_KEY to .env and restart to connect.')
    question = st.text_area('Question', max_chars=4000)
    consent = st.checkbox('Send this question and available numeric benchmark results to Gemini')
    if st.button('Ask Gemini', disabled=not consent or not os.getenv('GEMINI_API_KEY')):
        st.session_state.pop('ai_response', None)
        start = time.perf_counter()
        try:
            with st.spinner('Waiting for Gemini…'):
                st.session_state.ai_response = ask_assistant(question, st.session_state.get('benchmarks', {}).get('rows', []))
        except Exception as exc: failure(exc, start)
    if 'ai_response' in st.session_state:
        duration('AI response latency', st.session_state.ai_response.seconds)
        st.markdown(st.session_state.ai_response.value)

if store is not None:
    try:
        store.sync(st.session_state)
    except (OSError,ValueError,sqlite3.Error):
        st.warning('Results are available now, but could not be saved locally. Check local_data permissions before refreshing.')
