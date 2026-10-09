from pathlib import Path

import pytest
from streamlit.testing.v1 import AppTest

APP = str(Path(__file__).resolve().parents[1] / 'app.py')


@pytest.fixture
def render_environment(monkeypatch, tmp_path):
    monkeypatch.setenv('CIPHERVAULT_RENDER_DEMO', 'true')
    monkeypatch.setenv('CIPHERVAULT_DEMO_PASSWORD', 'test-only-password-long-enough')
    database = tmp_path / 'should-not-exist.sqlite3'
    monkeypatch.setenv('CIPHERVAULT_DB_PATH', str(database))
    return database


def test_render_gate_and_session_isolation(render_environment):
    app = AppTest.from_file(APP).run()
    assert not app.exception and not app.sidebar.radio
    app.text_input[0].set_value('wrong')
    app.button[0].click().run()
    assert app.error and not app.sidebar.radio
    app.text_input[0].set_value('test-only-password-long-enough')
    app.button[0].click().run()
    assert not app.exception and app.sidebar.radio
    assert not render_environment.exists()
    app.sidebar.radio[0].set_value('Device-to-Device Transfer').run()
    assert not app.exception and app.info
    assert not any('Start LAN' in b.label for b in app.button)
    other = AppTest.from_file(APP).run()
    assert not other.sidebar.radio
    next(b for b in app.button if b.label == 'Lock laboratory').click().run()
    assert not app.exception and not app.sidebar.radio


def test_render_gate_fails_closed_without_password(render_environment, monkeypatch):
    monkeypatch.delenv('CIPHERVAULT_DEMO_PASSWORD')
    app = AppTest.from_file(APP).run()
    assert app.error and not app.sidebar.radio
    assert not render_environment.exists()
