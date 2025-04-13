# coding:utf-8

import unittest
from unittest import mock

from xpw import password


class TestSecret(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.secret = password.Secret("test")

    @classmethod
    def tearDownClass(cls):
        pass

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_hash(self):
        self.assertIsInstance(hash(self.secret), int)

    def test_str(self):
        self.assertEqual(str(self.secret), "test")

    def test_eq(self):
        self.assertEqual(self.secret, "test")


class TestPass(unittest.TestCase):

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

    def test_eq(self):
        self.assertNotEqual(password.Pass("test"), "demo")

    def test_check_TooShortError(self):
        self.assertFalse(password.Pass.check("123"))

    def test_check_throw_TooShortError(self):
        self.assertRaises(password.Pass.TooShortError,
                          password.Pass.check,
                          "123", True)

    def test_check_IllegalCharacterError(self):
        self.assertFalse(password.Pass.check("123\t456"))

    def test_check_throw_IllegalCharacterError(self):
        self.assertRaises(password.Pass.IllegalCharacterError,
                          password.Pass.check,
                          "123\t456", True)

    def test_match(self):
        self.assertTrue(password.Pass("test").match(password.Pass("test")))

    def test_mismatch(self):
        self.assertRaises(password.Pass.MismatchError,
                          password.Pass("test").match,
                          "demo", throw=True)

    def test_get_character_set(self):
        self.assertEqual(len(password.Pass.get_character_set()), 94)

    @mock.patch("getpass.getpass")
    def test_dialog(self, mock_getpass):
        mock_getpass.side_effect = ["test", "test"]
        self.assertEqual(password.Pass.dialog(), "test")

    @mock.patch("getpass.getpass")
    def test_MaxRetriesError(self, mock_getpass):
        mock_getpass.side_effect = ["test", "unit"]
        self.assertRaises(password.Pass.MaxRetriesError,
                          password.Pass.dialog, 1)


class TestSalt(unittest.TestCase):

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

    def test_format(self):
        self.assertIsInstance(password.Salt.generate("test"), password.Salt)


class TestArgon2Hasher(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.hash = password.Argon2Hasher.hash("test")

    @classmethod
    def tearDownClass(cls):
        pass

    def setUp(self):
        pass

    def tearDown(self):
        pass

    @mock.patch("argon2.PasswordHasher.verify")
    def test_init_value_error(self, mock_verify):
        mock_verify.side_effect = [None]
        self.assertRaises(ValueError, password.Argon2Hasher, "test")

    def test_secret(self):
        self.assertIsInstance(self.hash.secret, password.Secret)

    def test_verify(self):
        self.assertFalse(self.hash.verify("unit"))
        self.assertTrue(self.hash.verify("test"))


if __name__ == "__main__":
    unittest.main()
