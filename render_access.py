"""Access gate for the separately hosted, session-only Streamlit demonstration."""
import os
import secrets
import time

import streamlit as st


def require_demo_access():
    hosted = os.getenv('CIPHERVAULT_RENDER_DEMO') == 'true' or bool(os.getenv('RENDER'))
    if not hosted:
        return False
    expected = os.getenv('CIPHERVAULT_DEMO_PASSWORD', '')
    if len(expected) < 20:
        st.error('The hosted demonstration password has not been configured.')
        st.stop()
    if st.session_state.get('_render_authorized', False):
        return True

    def authenticate():
        started = time.perf_counter()
        supplied = st.session_state.pop('_render_password', '')
        st.session_state['_render_authorized'] = secrets.compare_digest(
            supplied.encode('utf-8'), expected.encode('utf-8'))
        st.session_state['_render_access_seconds'] = time.perf_counter() - started
        st.session_state['_render_attempted'] = True

    st.title('CipherVault · Python laboratory')
    st.caption('Private Streamlit demonstration. Enter the demo access password.')
    with st.form('_render_access_form'):
        st.text_input('Demo access password', type='password', key='_render_password')
        st.form_submit_button('Open laboratory', on_click=authenticate)
    if st.session_state.get('_render_attempted'):
        st.error('Incorrect demo access password.')
        st.caption(f"Access check · {st.session_state['_render_access_seconds'] * 1000:.4f} ms")
    st.stop()
