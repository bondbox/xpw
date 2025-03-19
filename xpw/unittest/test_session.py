# coding:utf-8

import unittest

from xpw import session


class TestSessionPool(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.spool = session.SessionPool()

    @classmethod
    def tearDownClass(cls):
        pass

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_sign(self):
        self.assertTrue(self.spool.sign_in("test"))
        self.assertTrue(self.spool.sign_out("test"))

    def test_verify(self):
        self.assertFalse(self.spool.verify("unit"))


if __name__ == "__main__":
    unittest.main()
