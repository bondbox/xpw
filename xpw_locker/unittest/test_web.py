# coding:utf-8

import os
import unittest
from unittest.mock import patch

from xpw.authorize import Argon2Auth
from xpw_locker import web

web.AUTH = Argon2Auth({"users": {"test": "unit"}})
web.PROXY = web.FlaskProxy("https://example.com/")
web.TEMPLATE = web.LocaleTemplate(os.path.join(web.BASE, "resources"))


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

    @patch.object(web, "requests")
    def test_favicon_origin(self, mock_requests):
        mock_requests.get.return_value.status_code = 200
        mock_requests.get.return_value.content = b"favicon_content"
        with web.app.test_request_context("/favicon.ico"):
            response = web.favicon()
            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.data, b"favicon_content")

    @patch.object(web, "requests")
    def test_favicon_locked(self, mock_requests):
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

    @patch.object(web.SESSIONS, "verify")
    def test_session_id_password_empty(self, mock_verify):
        mock_verify.side_effect = [False]
        with web.app.test_client() as client:
            client.set_cookie("session_id", "test")
            response = client.post("/", data={"username": "test", "password": ""},  # noqa:E501
                                   content_type="application/x-www-form-urlencoded")  # noqa:E501
            self.assertEqual(response.status_code, 200)

    @patch.object(web.SESSIONS, "verify")
    def test_session_id_password_right(self, mock_verify):
        mock_verify.side_effect = [False]
        with web.app.test_client() as client:
            client.set_cookie("session_id", "test")
            with patch.object(web.AUTH, "verify") as mock_auth:
                mock_auth.side_effect = [True]
                response = client.post("/", data={"username": "test", "password": "unit"},  # noqa:E501
                                    content_type="application/x-www-form-urlencoded")  # noqa:E501
                self.assertEqual(response.status_code, 302)

    @patch.object(web, "PROXY")
    @patch.object(web.SESSIONS, "verify")
    def test_proxy_ConnectionError_502(self, mock_verify, mock_proxy):
        mock_verify.side_effect = [True]
        mock_proxy.request.side_effect = [web.requests.ConnectionError()]
        with web.app.test_client() as client:
            client.set_cookie("session_id", "test")
            response = client.get("/test")
            self.assertEqual(response.status_code, 502)
            self.assertEqual(response.data, b"Bad Gateway")


if __name__ == "__main__":
    unittest.main()
