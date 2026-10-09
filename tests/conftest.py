import pytest


@pytest.fixture(autouse=True)
def isolated_local_results(monkeypatch,tmp_path):
    # Never let automated UI tests modify the user's saved workspace.
    monkeypatch.setenv('CIPHERVAULT_DB_PATH',str(tmp_path/'results.sqlite3'))
