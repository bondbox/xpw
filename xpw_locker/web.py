# coding:utf-8

from functools import wraps
import os
from typing import Any
from typing import Optional

from flask import Flask
from flask import Response
from flask import redirect  # noqa:H306
from flask import render_template_string
from flask import request
from flask import url_for
import requests
from xhtml import FlaskProxy
from xhtml import LocaleTemplate
from xkits import cmds

from xpw import AuthInit
from xpw import BasicAuth
from xpw import SessionPool

AUTH: BasicAuth
PROXY: FlaskProxy
TEMPLATE: LocaleTemplate

BASE: str = os.path.dirname(__file__)
SESSIONS: SessionPool = SessionPool()

app = Flask(__name__)
app.secret_key = SESSIONS.secret.key


def auth() -> Optional[Any]:
    session_id: Optional[str] = request.cookies.get("session_id")
    if session_id is None:
        response = redirect(url_for("proxy", path=request.path.lstrip("/")))
        response.set_cookie("session_id", SESSIONS.search().name)
        return response
    if SESSIONS.verify(session_id):
        # cmds.logger.info(f"{session_id} is logged.")
        return None  # logged
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        if not password:  # invalid password
            cmds.logger.info("%s login to %s with empty password.", session_id, username)  # noqa:E501
        elif AUTH.verify(username, password):
            SESSIONS.sign_in(session_id)
            cmds.logger.info("%s sign in with %s.", session_id, username)
            return redirect(url_for("proxy", path=request.path.lstrip("/")))
        cmds.logger.warning("%s login to %s error.", session_id, username)
    context = TEMPLATE.search(request.headers.get("Accept-Language", "en"), "login").fill()  # noqa:E501
    return render_template_string(TEMPLATE.seek("login.html").loads(), **context)  # noqa:E501


def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if (response := auth()) is not None:
            return response
        return f(*args, **kwargs)
    return decorated_function


@app.route("/favicon.ico", methods=["GET"])
def favicon() -> Response:
    if (response := PROXY.request(request)).status_code == 200:
        return response
    session_id: Optional[str] = request.cookies.get("session_id")
    logged: bool = isinstance(session_id, str) and SESSIONS.verify(session_id)
    binary: bytes = TEMPLATE.seek("unlock.ico" if logged else "locked.ico").loadb()  # noqa:E501
    return app.response_class(binary, mimetype="image/vnd.microsoft.icon")


@app.route("/", defaults={"path": ""}, methods=["GET", "POST"])
@app.route("/<path:path>", methods=["GET", "POST"])
@login_required
def proxy(path: str) -> Response:  # pylint: disable=unused-argument
    try:
        cmds.logger.debug("request.headers:\n%s", request.headers)
        return PROXY.request(request)
    except requests.ConnectionError:
        return Response("Bad Gateway", status=502)


if __name__ == "__main__":
    AUTH = AuthInit.from_file()
    PROXY = FlaskProxy("http://127.0.0.1:8000")
    TEMPLATE = LocaleTemplate(os.path.join(BASE, "resources"))
    app.run(host="0.0.0.0", port=3000)
