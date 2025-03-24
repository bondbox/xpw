# coding:utf-8

from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler
from http.server import ThreadingHTTPServer
import os
from typing import Optional
from urllib.parse import urljoin

from requests import Session
from xhtml import LocaleTemplate

from xpw import SessionKeys

BASE: str = os.path.dirname(os.path.dirname(__file__))
SESSIONS: SessionKeys = SessionKeys(lifetime=86400)
TEMPLATE: LocaleTemplate = LocaleTemplate(os.path.join(BASE, "xpw_locker", "resources"))  # noqa:E501


class RequestProxy(BaseHTTPRequestHandler):
    @property
    def accept_language(self) -> str:
        return self.headers.get("Accept-Language", "en;q=0.8")

    @property
    def cookies(self) -> SimpleCookie:
        return SimpleCookie(self.headers.get("Cookie"))

    @property
    def session_id(self) -> Optional[str]:
        return s.value if (s := self.cookies.get("session_id")) else None

    def redirect(self) -> None:
        self.send_response(302)
        self.send_header("Location", self.path)
        self.end_headers()

    def send_login(self):
        self.send_response(200)
        self.send_header("Content-type", "text/html")
        self.end_headers()
        context = TEMPLATE.search(self.accept_language, "login").fill()
        content = TEMPLATE.seek("login.html").render(**context).encode()
        self.wfile.write(content)

    def urljoin(self, path: str) -> str:
        return urljoin(base="https://example.com/", url=path)

    def authenticate(self) -> bool:
        session_id: Optional[str] = self.session_id
        if session_id is None:
            session_id = SESSIONS.search().name
            print(f"new session {session_id}")
            self.send_response(302)
            self.send_header("Location", self.path)
            self.send_header("Set-Cookie", f"session_id={session_id}")
            self.end_headers()
            return False
        if SESSIONS.verify(session_id):
            return True
        return True
        print(f"Verify session {session_id} failure")
        self.send_login()
        return False

    def do_GET(self):
        print(f"GET Path: {self.path}")
        # for key, value in self.headers.items():
        #     print(f"{key}: {value}")
        # cookies = SimpleCookie(self.headers.get("Cookie"))
        # for cookie_name, cookie in cookies.items():
        #     print(f"Cookie: {cookie_name} = {cookie.value}")
        if self.authenticate():
            # self.send_response(200)
            # self.send_header("Content-type", "text/html")
            # self.end_headers()
            # self.wfile.write(b"test get")
            target_url = self.urljoin(self.path.lstrip("/"))
            print(target_url)
            with Session() as session:
                response = session.get(target_url)
                self.send_response(response.status_code)
                print(response.status_code)
                for header, value in response.headers.items():
                    self.send_header(header, value)
                    print(f"{header}: {value}")
                self.end_headers()
                self.wfile.write(response.content)

    def do_POST(self):
        print(f"POST Path: {self.path}")
        for key, value in self.headers.items():
            print(f"{key}: {value}")
        self.send_response(200)
        self.send_header("Content-type", "text/html")
        self.end_headers()
        self.wfile.write(b"test post")


def run(host: str, port: int):
    listen_address = (host, port)
    httpd = ThreadingHTTPServer(listen_address, RequestProxy)
    print(f"Listening on {host}:{port}")
    httpd.serve_forever()


if __name__ == "__main__":
    run("0.0.0.0", 8080)
