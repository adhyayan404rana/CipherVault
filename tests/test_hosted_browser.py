import json
import os
from pathlib import Path
import shutil
import subprocess
import threading

import pytest
from werkzeug.serving import make_server
from hosted_app import create_app

ROOT=Path(__file__).resolve().parents[1]
CHROME=Path(os.getenv('CIPHERVAULT_TEST_CHROME',r'C:\Program Files\Google\Chrome\Application\chrome.exe'))


@pytest.mark.skipif(not CHROME.exists() or not shutil.which('node') or not (ROOT/'.test-tools/node_modules/playwright').exists(),
                    reason='Optional Chrome UI test requires Chrome and npm install --prefix .test-tools --no-save playwright')
def test_two_isolated_browser_accounts_and_all_core_workflows(tmp_path):
    app=create_app({'TESTING':True,'DATABASE':tmp_path/'accounts.sqlite3','SECRET_KEY':'browser-test-only-secret-at-least-32-characters'})
    server=make_server('127.0.0.1',0,app,threaded=True)
    thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
    demo=tmp_path/'demo.txt';demo.write_bytes(b'Hosted CipherVault demo.\nConfidentiality, integrity and authenticity.\n')
    key=tmp_path/'demo.key';key.write_bytes(os.urandom(32))
    changed=tmp_path/'changed.txt';changed.write_bytes(b'Changed content fails verification.')
    artifacts={name:str(tmp_path/file) for name,file in {'recovered':'received.txt','encrypted':'demo.cvault','vaultRecovered':'vault-recovered.txt','signature':'demo.sig','publicKey':'public.pem'}.items()}
    result_dir=ROOT/'test-results';result_dir.mkdir(exist_ok=True)
    try:
        run=subprocess.run(['node',str(ROOT/'tests/hosted_browser.cjs')],input=json.dumps({'base':f'http://127.0.0.1:{server.server_port}',
                 'chrome':str(CHROME),'demo':str(demo),'key':str(key),'changed':str(changed),
                 'screenshot':str(result_dir/'hosted-dashboard.png'),**artifacts}),text=True,capture_output=True,timeout=180)
        assert run.returncode==0,run.stderr
        result=json.loads(run.stdout)
        assert result['success'] and result['browserErrors']==[] and result['encrypted']
        assert result['bytes']==len(demo.read_bytes())
        assert Path(artifacts['recovered']).read_bytes()==demo.read_bytes()
    finally:
        server.shutdown();thread.join(timeout=5)
