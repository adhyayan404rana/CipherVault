"""Execute real Streamlit scripts and interactions without a graphical browser."""
import pytest
from pathlib import Path
from streamlit.testing.v1 import AppTest
from benchmark_service import run_benchmarks

APP = str(Path(__file__).resolve().parents[1] / 'app.py')


@pytest.mark.parametrize('section', ['Overview', 'File Encryption and Decryption',
    'Device-to-Device Transfer', 'Hashing and Digital Signatures', 'Performance Dashboard', 'Cryptographic Analysis', 'AI Assistant'])
def test_all_sections_render(section, monkeypatch):
    monkeypatch.delenv('GEMINI_API_KEY', raising=False)
    app = AppTest.from_file(APP, default_timeout=30).run()
    app.sidebar.radio[0].set_value(section).run()
    assert not app.exception


def test_actual_benchmark_charts_render():
    app = AppTest.from_file(APP, default_timeout=30).run()
    app.session_state['benchmarks'] = run_benchmarks()
    app.sidebar.radio[0].set_value('Performance Dashboard').run()
    assert not app.exception
    assert len(app.dataframe) == 1
    assert len(app.dataframe[0].value) == 6
    assert len(app.get('imgs')) + len(app.get('image')) > 0
    app.sidebar.radio[0].set_value('Overview').run()
    assert not app.exception
    next(b for b in app.button if b.label == 'Open file vault').click().run()
    assert not app.exception
    assert app.sidebar.radio[0].value == 'File Encryption and Decryption'


def test_rsa_generation_and_avalanche_buttons():
    app = AppTest.from_file(APP, default_timeout=30).run()
    app.sidebar.radio[0].set_value('Hashing and Digital Signatures').run()
    next(b for b in app.button if b.label == 'Generate 3072-bit RSA key pair').click().run()
    assert not app.exception and app.session_state['rsa_key'].key_size == 3072
    next(b for b in app.button if b.label == 'Measure avalanche effect').click().run()
    assert not app.exception and len(app.json) == 1


def test_all_analysis_graphs_render_actual_results():
    from analysis_service import confusion_diffusion, aes_length_analysis, hashing_resistance_analysis
    app = AppTest.from_file(APP, default_timeout=30).run()
    app.session_state['analysis_avalanche'] = confusion_diffusion(bytes(16), 8)
    app.session_state['analysis_lengths'] = aes_length_analysis([1024,10*1024], 1)
    app.session_state['analysis_hashes'] = hashing_resistance_analysis(b'original', 300, 1)
    app.sidebar.radio[0].set_value('Cryptographic Analysis').run()
    assert not app.exception
    assert len(app.dataframe) == 3
    assert len(app.get('imgs')) + len(app.get('image')) == 14


def test_analysis_run_buttons_with_default_experiments():
    app = AppTest.from_file(APP, default_timeout=60).run()
    app.sidebar.radio[0].set_value('Cryptographic Analysis').run()
    for label in ('Run confusion & diffusion', 'Run plaintext & key length benchmark', 'Run hash resistance analysis'):
        next(b for b in app.button if b.label == label).click().run()
        assert not app.exception
    assert len(app.session_state['analysis_avalanche'].value['rows']) == 64
    assert len(app.session_state['analysis_lengths'].value['rows']) == 18
    assert app.session_state['analysis_hashes'].value['budget'] == 20000


def test_file_vault_graphs_use_actual_file_results():
    from crypto_service import encrypt_file, decrypt_file
    from vault_charts import record_measurement
    app = AppTest.from_file(APP, default_timeout=30).run()
    history = []
    for size in (1024,10*1024):
        encrypted = encrypt_file(b'x'*size,'a strong vault test password','test.txt')
        decrypted = decrypt_file(encrypted.value['package'],'a strong vault test password')
        history = record_measurement(history,encrypted,'Encryption')
        history = record_measurement(history,decrypted,'Decryption')
    app.session_state['enc_result'] = encrypted
    app.session_state['dec_result'] = decrypted
    app.session_state['vault_measurements'] = history
    app.sidebar.radio[0].set_value('File Encryption and Decryption').run()
    assert not app.exception
    assert len(app.get('imgs')) + len(app.get('image')) == 4
    assert len(app.dataframe[0].value) == 4
    app.run()
    assert len(app.session_state['vault_measurements']) == 4


def test_file_vault_key_length_graph_and_refresh():
    app = AppTest.from_file(APP,default_timeout=30).run()
    app.sidebar.radio[0].set_value('File Encryption and Decryption').run()
    next(b for b in app.button if b.label == 'Run password character-length analysis').click().run()
    assert not app.exception
    rows = app.dataframe[0].value
    assert list(rows.password_characters) == [12,16,24,32,64]
    assert list(rows.key_bits) == [256]*5
    assert list(rows.size_bytes) == [1024*1024]*5
    assert (rows[['encrypt_ms','decrypt_ms']] >= 0).all().all()
    assert len(app.get('image')) == 1
    restored = AppTest.from_file(APP,default_timeout=30).run()
    assert not restored.exception
    assert list(restored.dataframe[0].value.password_characters) == [12,16,24,32,64]
    assert len(restored.get('image')) == 1


def test_file_vault_size_benchmark_button():
    app = AppTest.from_file(APP,default_timeout=30).run()
    app.sidebar.radio[0].set_value('File Encryption and Decryption').run()
    next(b for b in app.button if b.label == 'Run File vault size benchmark').click().run()
    assert not app.exception
    assert len(app.dataframe[0].value) == 6
    assert len(app.get('imgs')) + len(app.get('image')) == 2


def test_fresh_browser_session_restores_outputs_and_requires_password():
    from crypto_service import encrypt_file,decrypt_file
    from vault_charts import record_measurement
    password = 'refresh keeps encrypted outputs'
    plaintext = b'File survives browser refresh securely.'
    encrypted = encrypt_file(plaintext,password,'refresh.txt')
    decrypted = decrypt_file(encrypted.value['package'],password)
    first = AppTest.from_file(APP,default_timeout=30).run()
    first.session_state['enc_result'] = encrypted
    first.session_state['dec_result'] = decrypted
    first.session_state['dec_package'] = encrypted.value['package']
    first.session_state['vault_measurements'] = record_measurement([],encrypted,'Encryption')
    first.session_state['benchmarks'] = run_benchmarks([1024,10240],1)
    first.sidebar.radio[0].set_value('File Encryption and Decryption').run()
    assert not first.exception

    refreshed = AppTest.from_file(APP,default_timeout=30).run()
    assert not refreshed.exception
    assert refreshed.sidebar.radio[0].value == 'File Encryption and Decryption'
    assert refreshed.session_state['enc_result'].value['package'] == encrypted.value['package']
    assert len(refreshed.session_state['benchmarks']['rows']) == 2
    assert len(refreshed.session_state['vault_measurements']) == 1
    assert 'data' not in refreshed.session_state['dec_result'].value
    assert any('Re-enter the package password' in info.value for info in refreshed.info)
    next(field for field in refreshed.text_input if field.key == 'dec_password').set_value(password).run()
    next(button for button in refreshed.button if button.label == 'Authenticate and decrypt').click().run()
    assert not refreshed.exception
    assert refreshed.session_state['dec_result'].value['data'] == plaintext
    assert len(refreshed.session_state['vault_measurements']) == 2


def test_saved_results_clear_button():
    first = AppTest.from_file(APP,default_timeout=30).run()
    first.session_state['benchmarks'] = run_benchmarks([1024],1)
    first.run()
    assert not first.exception
    next(button for button in first.button if button.label == 'Clear saved results').click().run()
    assert not first.exception and 'benchmarks' not in first.session_state
    fresh = AppTest.from_file(APP,default_timeout=30).run()
    assert not fresh.exception and 'benchmarks' not in fresh.session_state


def test_browser_refresh_reattaches_existing_receiver():
    import socket
    with socket.socket() as sock:
        sock.bind(('127.0.0.1',0))
        port = sock.getsockname()[1]
    app = AppTest.from_file(APP,default_timeout=30).run()
    app.sidebar.radio[0].set_value('Device-to-Device Transfer').run()
    next(field for field in app.text_input if field.label == 'LAN IPv4').set_value('127.0.0.1').run()
    next(field for field in app.number_input if field.label == 'HTTPS port').set_value(port).run()
    next(button for button in app.button if button.label == 'Start LAN HTTPS receiver').click().run()
    assert not app.exception
    service = app.session_state['transfer_service']
    try:
        fresh = AppTest.from_file(APP,default_timeout=30).run()
        assert not fresh.exception
        assert fresh.session_state['transfer_service'] is service
        assert service.thread.is_alive() and service.port == port
        next(button for button in fresh.button if button.label == 'Stop receiver and revoke transfers').click().run()
        assert not fresh.exception and not service.thread.is_alive()
    finally:
        if service.thread.is_alive():
            service.stop()


def test_key_file_mode_and_restored_package_prompt():
    import os
    from crypto_service import encrypt_file
    app = AppTest.from_file(APP,default_timeout=30).run()
    app.sidebar.radio[0].set_value('File Encryption and Decryption').run()
    next(field for field in app.selectbox if field.key == 'enc_method').set_value('Key file').run()
    assert not app.exception
    assert any(field.label == 'AES-256 key file' for field in app.get('file_uploader'))
    key = os.urandom(32)
    encrypted = encrypt_file(b'demo',key=key)
    app.session_state['enc_result'] = encrypted
    app.session_state['dec_package'] = encrypted.value['package']
    app.run()
    assert not app.exception
    fresh = AppTest.from_file(APP,default_timeout=30).run()
    assert not fresh.exception
    assert any(field.label == 'Original AES-256 key file' for field in fresh.get('file_uploader'))
    assert not any(field.key == 'dec_password' for field in fresh.text_input)
