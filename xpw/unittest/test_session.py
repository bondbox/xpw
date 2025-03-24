# coding:utf-8

import unittest

from xpw import session


class TestSessionKeys(unittest.TestCase):

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
        self.assertTrue(self.skeys.verify("test", self.skeys.secret.key))


if __name__ == "__main__":
    unittest.main()
