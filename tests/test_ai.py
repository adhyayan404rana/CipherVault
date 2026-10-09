import pytest
import ai_service as a
from crypto_service import OperationError


def test_no_key(monkeypatch):
    monkeypatch.delenv('GEMINI_API_KEY', raising=False)
    with pytest.raises(OperationError, match='Configure GEMINI_API_KEY') as exc:
        a.ask_assistant('What is AES?')
    assert exc.value.seconds >= 0


def test_real_api_contract_with_stub(monkeypatch):
    monkeypatch.setenv('GEMINI_API_KEY', 'test-key')
    monkeypatch.setenv('GEMINI_MODEL', 'test-model')
    class Response:
        ok = True
        def json(self): return {'candidates':[{'content':{'parts':[{'text':'test API response'}]}}]}
    def post(url, **kwargs):
        assert url == a.BASE+'/models/test-model:generateContent'
        assert kwargs['headers']['x-goog-api-key'] == 'test-key'
        assert 'PRIVATE_TEST_VALUE' not in str(kwargs['json'])
        return Response()
    monkeypatch.setattr(a.requests, 'post', post)
    response = a.ask_assistant('Explain AES', [{'size_bytes':1024, 'private_key':'PRIVATE_TEST_VALUE'}])
    assert response.value == 'test API response' and response.seconds >= 0
