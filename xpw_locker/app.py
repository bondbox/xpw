# coding:utf-8

from functools import wraps
import os
from typing import Any
from typing import Optional
from urllib.parse import urljoin

from flask import Flask
from flask import Response
from flask import redirect  # noqa:H306
from flask import render_template_string
from flask import request
from flask import url_for
import requests
from xhtml import AcceptLanguage
from xhtml import Template
from xlc import Message
from xlc import Segment

from xpw import AuthInit
from xpw import BasicAuth
from xpw import SessionPool

TARGET: str = "http://127.0.0.1:8000"
SESSIONS: SessionPool = SessionPool()
AUTH: BasicAuth = AuthInit.from_file()
BASE: str = os.path.dirname(__file__)
TEMPLATE: Template = Template(os.path.join(BASE, "resources"))
MESSAGE: Message = Message.load(os.path.join(TEMPLATE.base, "locale"))


app = Flask(__name__)
app.secret_key = SESSIONS.secret_key


def get() -> str:
    accept_language: str = request.headers.get("Accept-Language", "en")
    segment: Segment = AcceptLanguage(accept_language).choice(MESSAGE)
    return render_template_string(TEMPLATE.seek("login.html").loads(),
                                  **segment.seek("login").fill())


def auth() -> Optional[Any]:
    session_id: Optional[str] = request.cookies.get("session_id")
    if session_id is None:
        response = redirect(url_for("proxy", path=request.path.lstrip("/")))
        response.set_cookie("session_id", SESSIONS.search().name)
        return response
    elif SESSIONS.verify(session_id):
        return None  # logged
    elif request.method == "GET":
        return get()
    elif request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        if not password or not AUTH.verify(username, password):
            return get()
        SESSIONS.sign_in(session_id)
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
    logged: bool = SESSIONS.verify(request.cookies.get("session_id"))
    if logged and (response := requests.get(urljoin(TARGET, "favicon.ico"), headers=request.headers)).status_code == 200:  # noqa:E501
        return Response(response.content, response.status_code, response.headers.items())  # noqa:E501
    return app.response_class(TEMPLATE.favicon.loadb(), mimetype="image/vnd.microsoft.icon")  # noqa:E501


@app.route("/", defaults={"path": ""}, methods=["GET", "POST"])
@app.route("/<path:path>", methods=["GET", "POST"])
@login_required
def proxy(path: str) -> Response:
    target_url = urljoin(TARGET, path)

    try:
        if request.method == "GET":
            response = requests.get(target_url, headers=request.headers)
        elif request.method == "POST":
            response = requests.post(target_url, headers=request.headers, data=request.data)  # noqa:E501
        else:
            return Response("Method Not Allowed", status=405)
    except requests.ConnectionError:
        return Response("Bad Gateway", status=502)

    excluded_headers = ["content-encoding", "content-length", "transfer-encoding", "connection"]  # noqa:E501
    headers = [(name, value) for (name, value) in response.raw.headers.items() if name.lower() not in excluded_headers]  # noqa:E501
    return Response(response.content, response.status_code, headers)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=3000)
