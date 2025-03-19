# coding:utf-8

import unittest

from xpw.randkey import main


class TestLocaleTemplate(unittest.TestCase):

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

    def test_main(self):
        self.assertEqual(main("--enable-digit".split()), 0)
        self.assertEqual(main("--enable-letter".split()), 0)
        self.assertEqual(main("--enable-lowercase".split()), 0)
        self.assertEqual(main("--enable-uppercase".split()), 0)
        self.assertEqual(main("--enable-punctuation".split()), 0)


if __name__ == "__main__":
    unittest.main()
