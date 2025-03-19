# coding:utf-8

from errno import ECANCELED
import unittest

import mock

from xpw_locker import cmd


class TestCmd(unittest.TestCase):

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

    @mock.patch.object(cmd.web.app, "run")
    def test_main(self, _):
        self.assertEqual(cmd.main([]), ECANCELED)


if __name__ == "__main__":
    unittest.main()
