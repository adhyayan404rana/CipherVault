import json
import subprocess
from pathlib import Path

from hosted_app import create_app


def test_api_only_proxy_origin_and_secure_cookie(tmp_path):
    origin='https://frontend.example'
    app=create_app({'TESTING':True,'MODE':'local','DATABASE':tmp_path/'db.sqlite3',
                    'SECRET_KEY':'proxy-test-only-secret-at-least-32-characters',
                    'PUBLIC_ORIGIN':origin,'API_ONLY':True})
    client=app.test_client()
    backend='https://backend.example'
    response=client.get('/api/session',base_url=backend)
    cookie=response.headers['Set-Cookie']
    assert 'Secure' in cookie and 'HttpOnly' in cookie and 'SameSite=Strict' in cookie
    token=response.json['csrf']
    payload={'email':'proxy@example.test','password':'proxy-test-account-password'}
    headers={'Origin':origin,'X-CSRF-Token':token}
    assert client.post('/api/register',base_url=backend,json=payload,headers=headers).status_code==200
    assert client.post('/api/login',base_url=backend,json=payload,headers=headers).status_code==200
    assert client.get('/api/session',base_url=backend).json['user']
    assert client.post('/api/login',base_url=backend,json=payload,headers={**headers,'Origin':'https://evil.example'}).status_code==403
    assert client.post('/api/login',base_url=backend,json=payload,headers={'Origin':origin}).status_code==403
    assert client.get('/',base_url=backend).json['service']=='CipherVault API'
    assert client.get('/assets/app.js',base_url=backend).status_code==404
    assert client.get('/health',base_url=backend).json['role']=='api'


def test_static_build_contains_only_dashboard_files(tmp_path):
    import shutil
    root=Path(__file__).resolve().parents[1]
    shutil.copy(root/'build_frontend.cjs',tmp_path)
    shutil.copytree(root/'hosted',tmp_path/'hosted')
    (tmp_path/'private.key').write_text('must not be bundled')
    subprocess.run(['node',str(tmp_path/'build_frontend.cjs')],check=True,capture_output=True)
    files={str(p.relative_to(tmp_path/'frontend_dist')).replace('\\','/') for p in (tmp_path/'frontend_dist').rglob('*') if p.is_file()}
    assert files=={'index.html','assets/app.js','assets/crypto.js','assets/style.css'}
    config=json.loads((root/'vercel.json').read_text())
    assert config['framework'] is None and 'functions' not in config
    assert any(r['source']=='/api/:path*' and '.onrender.com/api/' in r['destination'] for r in config['rewrites'])
