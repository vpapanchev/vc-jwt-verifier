#! /bin/sh

gunicorn --limit-request-line 0 --preload --workers=2 --timeout 60 -k eventlet -b :${API_PORT} vc_jwt_verifier.__main__:flask_app
