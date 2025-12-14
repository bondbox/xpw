# coding:utf-8

from hashlib import md5
from unittest import TestCase
from unittest import main

from xpw import session


class TestSessionID(TestCase):

    @classmethod
    def setUpClass(cls):
        cls.user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36 Edg/135.0.0.0"  # noqa:E501
        cls.session_id = session.SessionID(cls.user_agent)

    @classmethod
    def tearDownClass(cls):
        pass

    def setUp(self):
        self.session_id = session.SessionID(self.user_agent)
        pass

    def tearDown(self):
        pass

    def test_number(self):
        self.assertEqual(len(self.session_id.number), 32)
        for n in self.session_id.number:
            self.assertIn(n, "0123456789abcdef")

    def test_digest(self):
        digest = md5(self.user_agent.encode("utf-8")).hexdigest()
        self.assertEqual(self.session_id.digest, digest)

    def test_verify(self):
        self.assertTrue(self.session_id.verify(self.user_agent))
        self.assertFalse(self.session_id.verify("test"))


class TestSessionUser(TestCase):

    @classmethod
    def setUpClass(cls):
        cls.identity: str = "demo"
        cls.session_id: str = "1234567890"
        cls.secret_key: str = "abcdefghij"
        cls.session = session.SessionUser(cls.session_id, cls.secret_key, cls.identity)  # noqa: E501

    @classmethod
    def tearDownClass(cls):
        pass

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_str(self):
        self.assertEqual(str(self.session), f"SessionUser(session_id={self.session_id}, identity={self.identity})")  # noqa: E501


class TestSessionKeys(TestCase):

    @classmethod
    def setUpClass(cls):
        pass

    @classmethod
    def tearDownClass(cls):
        pass

    def setUp(self):
        self.skeys = session.SessionKeys()

    def tearDown(self):
        pass

    def test_sign_out(self):
        self.assertEqual(self.skeys.sign_in("test"), self.skeys.secret.key)
        self.assertIsNone(self.skeys.sign_out("test"))

    def test_verify(self):
        self.assertEqual(self.skeys.sign_in("test"), self.skeys.secret.key)
        self.assertFalse(self.skeys.verify("unit", self.skeys.secret.key))
        self.assertFalse(self.skeys.verify("test", "unittest1234567890"))
        self.assertTrue(self.skeys.verify("test", self.skeys.secret.key))


if __name__ == "__main__":
    main()
