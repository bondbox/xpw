# coding:utf-8

from unittest import TestCase
from unittest import main

from xpw import randkey


class TestLocaleTemplate(TestCase):

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
        self.assertEqual(randkey.main("--enable-digit".split()), 0)
        self.assertEqual(randkey.main("--enable-letter".split()), 0)
        self.assertEqual(randkey.main("--enable-lowercase".split()), 0)
        self.assertEqual(randkey.main("--enable-uppercase".split()), 0)
        self.assertEqual(randkey.main("--enable-punctuation".split()), 0)


if __name__ == "__main__":
    main()
