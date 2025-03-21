# coding:utf-8

import os
import unittest
from unittest.mock import MagicMock
from unittest.mock import patch

from xpw.authorize import Argon2Auth
from xpw_locker import web

web.AUTH = Argon2Auth({"users": {"test": "unit"}})
web.PROXY = web.FlaskProxy("https://example.com/")
web.TEMPLATE = web.LocaleTemplate(os.path.join(web.BASE, "resources"))
web.SESSIONS = web.SessionPool(lifetime=86400)
web.app.secret_key = web.SESSIONS.secret.key


class TestFavicon(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        pass

    @classmethod
    def tearDownClass(cls):
        pass

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_favicon_origin(self):
        with patch.object(web.PROXY, "request") as mock_request:
            fake_request = MagicMock()
            fake_request.status_code = 200
            mock_request.side_effect = [fake_request]
            with web.app.test_request_context("/favicon.ico"):
                self.assertIs(web.favicon(), fake_request)

    def test_favicon_locked(self):
        with patch.object(web, "requests") as mock_requests:
            mock_requests.get.return_value.status_code = 500
            with web.app.test_request_context("/favicon.ico"):
                response = web.favicon()
                self.assertEqual(response.status_code, 200)
                self.assertIsInstance(response.data, bytes)


class TestProxy(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        pass

    @classmethod
    def tearDownClass(cls):
        pass

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_session_id_is_none(self):
        with web.app.test_client() as client:
            response = client.get("/")
            self.assertEqual(response.status_code, 302)

    def test_session_id_password_empty(self):
        with patch.object(web.SESSIONS, "verify") as mock_verify:
            mock_verify.side_effect = [False]
            with web.app.test_client() as client:
                client.set_cookie("session_id", "test")
                response = client.post("/", data={"username": "test", "password": ""},  # noqa:E501
                                    content_type="application/x-www-form-urlencoded")  # noqa:E501
                self.assertEqual(response.status_code, 200)

    def test_session_id_password_right(self):
        with patch.object(web.SESSIONS, "verify") as mock_verify:
            mock_verify.side_effect = [False]
            with web.app.test_client() as client:
                client.set_cookie("session_id", "test")
                with patch.object(web.AUTH, "verify") as mock_auth:
                    mock_auth.side_effect = [True]
                    response = client.post("/", data={"username": "test", "password": "unit"},  # noqa:E501
                                        content_type="application/x-www-form-urlencoded")  # noqa:E501
                    self.assertEqual(response.status_code, 302)

    @patch.object(web, "PROXY")
    def test_proxy_ConnectionError_502(self, mock_proxy):
        with patch.object(web.SESSIONS, "verify") as mock_verify:
            mock_verify.side_effect = [True]
            mock_proxy.request.side_effect = [web.requests.ConnectionError()]
            with web.app.test_client() as client:
                client.set_cookie("session_id", "test")
                response = client.get("/test")
                self.assertEqual(response.status_code, 502)
                self.assertEqual(response.data, b"Bad Gateway")


if __name__ == "__main__":
    unittest.main()
