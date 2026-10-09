"""Render's Gunicorn WSGI entrypoint; local launch uses hosted_app.py."""
from hosted_app import create_app
app = create_app()
