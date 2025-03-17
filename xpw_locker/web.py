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
app.secret_key = SESSIONS.secret_key


def get() -> str:
    context = TEMPLATE.search(request.headers.get("Accept-Language", "en"), "login").fill()  # noqa:E501
    return render_template_string(TEMPLATE.seek("login.html").loads(), **context)  # noqa:E501


def auth() -> Optional[Any]:
    session_id: Optional[str] = request.cookies.get("session_id")
    if session_id is None:
        response = redirect(url_for("proxy", path=request.path.lstrip("/")))
        response.set_cookie("session_id", SESSIONS.search().name)
        return response
    elif SESSIONS.verify(session_id):
        # cmds.logger.info(f"{session_id} is logged.")
        return None  # logged
    elif request.method == "GET":
        return get()
    elif request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        if not password or not AUTH.verify(username, password):
            cmds.logger.warn(f"{session_id} login error with {username}.")
            return get()
        SESSIONS.sign_in(session_id)
        cmds.logger.info(f"{session_id} sign in with {username}.")
        return redirect(url_for("proxy", path=request.path.lstrip("/")))


def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if (response := auth()) is not None:
            return response
        return f(*args, **kwargs)
    return decorated_function


@app.route("/favicon.ico", methods=["GET"])
def favicon() -> Response:
    if (response := requests.get(PROXY.urljoin("favicon.ico"), headers=request.headers)).status_code == 200:  # noqa:E501
        return Response(response.content, response.status_code, response.headers.items())  # noqa:E501
    logged: bool = SESSIONS.verify(request.cookies.get("session_id"))
    object: str = "unlock.ico" if logged else "locked.ico"
    binary: bytes = TEMPLATE.seek(object).loadb()
    return app.response_class(binary, mimetype="image/vnd.microsoft.icon")


@app.route("/", defaults={"path": ""}, methods=["GET", "POST"])
@app.route("/<path:path>", methods=["GET", "POST"])
@login_required
def proxy(path: str) -> Response:
    try:
        return PROXY.request(request)
    except requests.ConnectionError:
        return Response("Bad Gateway", status=502)


if __name__ == "__main__":
    AUTH = AuthInit.from_file()
    PROXY = FlaskProxy("http://127.0.0.1:8000")
    TEMPLATE = LocaleTemplate(os.path.join(BASE, "resources"))
    app.run(host="0.0.0.0", port=3000)
