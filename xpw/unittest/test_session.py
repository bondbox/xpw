# coding:utf-8

import unittest

from xpw import session


class TestSessionPool(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        pass

    @classmethod
    def tearDownClass(cls):
        pass

    def setUp(self):
        self.spool = session.SessionPool()

    def tearDown(self):
        pass

    def test_sign_out(self):
        self.assertEqual(self.spool.sign_in("test"), self.spool.secret.key)
        self.assertIsNone(self.spool.sign_out("test"))

    def test_verify(self):
        self.assertEqual(self.spool.sign_in("test"), self.spool.secret.key)
        self.assertFalse(self.spool.verify("unit", self.spool.secret.key))
        self.assertTrue(self.spool.verify("test", self.spool.secret.key))


if __name__ == "__main__":
    unittest.main()
