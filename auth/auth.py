from itsdangerous import URLSafeTimedSerializer
from datetime import datetime, timedelta
from pathlib import Path
from uuid import uuid4
import configparser
import logging

from flask import (
    Flask,
    request,
    jsonify,
    session,
    make_response,
    redirect, 
    Response
)
from flask_session import Session
import duo_client

app = Flask(__name__)

cfg = configparser.ConfigParser()
cfg.read(Path(__file__).with_name('config.ini'))

DUO_IKEY = cfg["duo"]["DUO_IKEY"]
DUO_SKEY = cfg["duo"]["DUO_SKEY"]
DUO_HOST = cfg["duo"]["DUO_HOST"]
DUO_DEVICE = cfg["duo"]["DUO_DEVICE"]
DUO_FACTOR = cfg["duo"]["DUO_FACTOR"]
DUO_USERNAME = cfg["duo"]["DUO_USERNAME"]

app.secret_key = cfg["flask"]["SECRET_KEY"]
app.config["SESSION_TYPE"] = cfg["flask"]["SESSION_TYPE"]
app.config["SESSION_USE_SIGNER"] = cfg["flask"]["SESSION_USE_SIGNER"]
app.config["SESSION_COOKIE_PATH"] = cfg["flask"]["SESSION_COOKIE_PATH"] 
app.config["SESSION_COOKIE_DOMAIN"] = cfg["flask"]["SESSION_COOKIE_DOMAIN"] 
app.config["SESSION_COOKIE_SECURE"] = cfg["flask"]["SESSION_COOKIE_SECURE"] 
app.config["SESSION_COOKIE_HTTPONLY"] = cfg["flask"]["SESSION_COOKIE_HTTPONLY"] 

COOKIE_NAME = cfg["cookie"]["COOKIE_NAME"]
# COOKIE_REFRESH = cfg["cookie"]["COOKIE_REFRESH"]  # todo
COOKIE_REFRESH = False
COOKIE_EXPIRY_MINUTES = int(cfg["cookie"]["COOKIE_EXPIRY_MINUTES"])


serializer = URLSafeTimedSerializer(app.secret_key)
auth_client = duo_client.Auth(ikey=DUO_IKEY, skey=DUO_SKEY, host=DUO_HOST)

def generate_uuid():
    return str(uuid4())

def set_cookie(response: Response, sess_id: str = None):
    if not sess_id:
        session_id = serializer.dumps(generate_uuid())
    else:
        session_id = serializer.dumps(sess_id)

    exp = datetime.utcnow() + timedelta(seconds=COOKIE_EXPIRY_MINUTES * 60)
    app.logger.debug(exp)

    # todo: expiry via session
    response.set_cookie(
        COOKIE_NAME,
        session_id,
        max_age=COOKIE_EXPIRY_MINUTES * 60,
        expires=exp.strftime("%a, %d %b %Y %H:%M:%S GMT"),
        samesite='Strict',
        secure=False,
        httponly=True
    )

@app.route("/login", methods=["POST", "GET"])
def login():
    try:
        duo_ping = auth_client.ping()
        if 'time' in duo_ping:
            app.logger.info("Duo service is online")
        else:
            raise Exception(f"Error: {duo_ping}")

    except Exception as e:
        app.logger.warning(f"DUO is not reachable: {str(e)}")
        return jsonify({"error": ""}), 500

    try:
        duo_check = auth_client.check()
        if 'time' in duo_check:
            app.logger.info("IKEY and SKEY are correct")
        else:
            raise Exception(f"Error: {duo_check}")

    except Exception as e:
        app.logger.warning(f"IKEY/SKEY are incorrect: {str(e)}")
        return jsonify({"error": ""}), 500

    try:
        app.logger.info("DUO Pre-auth")
        pre_auth = auth_client.preauth(username=DUO_USERNAME)
        if pre_auth['result'] != "auth":
            app.logger.warning(f"DUO Pre-auth failed: {str(pre_auth)}")
            return jsonify({"error": ""}), 400

        app.logger.info("DUO Auth")
        auth = auth_client.auth(
            device=DUO_DEVICE,
            factor=DUO_FACTOR,
            username=DUO_USERNAME
        )

        if auth['result'] == 'allow':
            response = make_response(jsonify({'success': ''}))
            # for testing change location to '/test'
            response.headers['Location'] = '/'
            response.status_code = 302
            set_cookie(response)

            return response

        return jsonify({"error": ""}), 401

    except Exception as e:
        app.logger.error(e)
        return jsonify({"error": ""}), 500

@app.route("/validate", methods=["GET"])
def validate_session():
    signed_session_id = request.cookies.get(COOKIE_NAME)

    if not signed_session_id:
        return jsonify({"error": ""}), 401

    try:
        session_id = serializer.loads(
            signed_session_id,
            max_age=COOKIE_EXPIRY_MINUTES * 60
        )
        response = make_response(jsonify({'success': ''}))
        response.status_code = 200

        if COOKIE_REFRESH:
            app.logger.debug("Cookie being refreshed")
            set_cookie(response, session_id) 

        return response

    except Exception as e:
        app.logger.warning(f"Cookie invalid or expired: [{signed_session_id}]")
        return jsonify({"error": ""}), 401

if __name__ == '__main__':
    app.run(
        debug=False,
        host=cfg["flask"]["HOST"],
        port=cfg["flask"]["PORT"]
    )
