# coding:utf-8

from os.path import join
from tempfile import TemporaryDirectory
from typing import List
import unittest

from xpw import account
from xpw import authorize


def read_api_tokens(profile: account.Profile) -> List[account.Profile.Token]:
    return list(profile.api_tokens)


class TestAccount(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.admin: str = "admin"
        cls.username: str = "demo"
        cls.password: str = "adc123456"
        cls.datas = {
            "users": {
                cls.username: cls.password,
                cls.admin: cls.password,
            },
            "admin": {"user": cls.admin},
        }

    @classmethod
    def tearDownClass(cls):
        pass

    def setUp(self):
        self.temp = TemporaryDirectory()
        self.path = join(self.temp.name, "test.cfg")
        authorize.BasicConfig(self.path, self.datas).dumpf(self.path)
        self.account = account.Account.from_file(self.path)

    def tearDown(self):
        self.temp.cleanup()

    def test_default_options(self):
        self.assertEqual(self.account.catalog, account.dirname(self.path))
        self.assertEqual(len(self.account.tickets.secret.key), 64)
        self.assertEqual(self.account.tickets.lifetime, 0.0)
        self.assertFalse(self.account.allow_register)
        self.assertFalse(self.account.allow_terminate)
        self.assertEqual(self.account.administrators, [self.admin])
        self.assertFalse(self.account.first_user_is_admin)
        self.assertFalse(self.account.allow_admin_create_user)
        self.assertFalse(self.account.allow_admin_delete_user)

    def test_fetch_administrator(self):
        self.assertIsNone(self.account.fetch(""))
        self.assertIsNone(self.account.fetch(self.admin))
        self.assertIsInstance(user := self.account.login(self.admin, self.password), account.SessionUser)  # noqa:E501
        assert isinstance(user, account.SessionUser)
        self.assertIsInstance(profile := self.account.fetch(user.session_id), account.Profile)  # noqa:E501
        assert isinstance(profile, account.Profile)
        self.assertEqual(profile.workspace, account.join(self.account.catalog, self.admin))  # noqa:E501
        self.assertEqual(profile.catalog, self.account.catalog)
        self.assertEqual(profile.identity, self.admin)
        self.assertEqual(profile.username, self.admin)
        self.assertTrue(profile.administrator)
        self.assertIsInstance(token1 := profile.create_token("test"), account.UserToken)  # noqa:E501
        self.assertIsInstance(token2 := profile.create_token("test"), account.UserToken)  # noqa:E501
        for token in profile.tokens:
            self.assertIsInstance(token, account.Profile.Token)
            self.assertEqual(token.note, "test")
        self.assertIsInstance(api_token := profile.create_api_token("api"), account.ApiToken)  # noqa:E501
        for token in profile.api_tokens:
            self.assertIsInstance(token, account.Profile.Token)
            self.assertEqual(token.note, "api")
        for session in profile.sessions:
            self.assertIsInstance(session, account.Profile.Session)
            self.assertIsInstance(session.session_id, str)
        self.assertIsInstance(self.account.update_token(user.session_id, user.secret_key, token2.name), account.UserToken)  # noqa:E501
        self.assertTrue(self.account.delete_token(user.session_id, user.secret_key, token1.name))  # noqa:E501
        self.assertTrue(self.account.delete_token(user.session_id, user.secret_key, token2.name))  # noqa:E501
        self.assertTrue(self.account.logout(user.session_id, user.secret_key))
        self.assertIsNone(self.account.fetch(user.session_id, user.secret_key))
        self.assertIsNone(self.account.fetch(user.session_id))
        self.assertIsInstance(user := self.account.login("", api_token.hash), account.SessionUser)  # noqa:E501

    def test_fetch_general_user(self):
        self.assertIsNone(self.account.fetch(""))
        self.assertIsNone(self.account.fetch(self.username))
        self.assertIsInstance(user := self.account.login(self.username, self.password), account.SessionUser)  # noqa:E501
        assert isinstance(user, account.SessionUser)
        self.assertIsInstance(profile := self.account.fetch(user.session_id), account.Profile)  # noqa:E501
        assert isinstance(profile, account.Profile)
        self.assertEqual(profile.workspace, account.join(self.account.catalog, self.username))  # noqa:E501
        self.assertEqual(profile.catalog, self.account.catalog)
        self.assertEqual(profile.identity, self.username)
        self.assertEqual(profile.username, self.username)
        self.assertFalse(profile.administrator)
        self.assertIsInstance(token1 := profile.create_token("test"), account.UserToken)  # noqa:E501
        self.assertIsInstance(token2 := profile.create_token("test"), account.UserToken)  # noqa:E501
        for token in profile.tokens:
            self.assertIsInstance(token, account.Profile.Token)
            self.assertEqual(token.note, "test")
        self.assertRaises(PermissionError, profile.create_api_token, "api")
        self.assertRaises(PermissionError, read_api_tokens, profile)
        for session in profile.sessions:
            self.assertIsInstance(session, account.Profile.Session)
            self.assertIsInstance(session.session_id, str)
        self.assertIsInstance(self.account.update_token(user.session_id, user.secret_key, token2.name), account.UserToken)  # noqa:E501
        self.assertTrue(self.account.delete_token(user.session_id, user.secret_key, token1.name))  # noqa:E501
        self.assertTrue(self.account.delete_token(user.session_id, user.secret_key, token2.name))  # noqa:E501
        self.assertTrue(self.account.logout(user.session_id, user.secret_key))
        self.assertIsNone(self.account.fetch(user.session_id, user.secret_key))
        self.assertIsNone(self.account.fetch(user.session_id))

    def test_login_and_logout(self):
        self.assertIsNone(self.account.login(self.username, "test"))
        self.assertIsInstance(user1 := self.account.login(self.username, self.password), account.SessionUser)  # noqa:E501
        assert isinstance(user1, account.SessionUser)
        self.assertEqual(user1.identity, self.username)
        self.assertFalse(self.account.check(user1.session_id, "adc123456789"))
        self.assertTrue(self.account.check(user1.session_id, user1.secret_key))
        self.assertTrue(self.account.check(user1.session_id))
        self.assertIsInstance(user2 := self.account.login(self.username, self.password), account.SessionUser)  # noqa:E501
        assert isinstance(user2, account.SessionUser)
        self.assertEqual(user2.identity, self.username)
        self.assertNotEqual(user1.session_id, user2.session_id)
        self.assertTrue(self.account.check(user2.session_id, user2.secret_key))
        self.assertTrue(self.account.check(user2.session_id))
        self.assertFalse(self.account.logout(user2.session_id, "abc1234567890"))  # noqa:E501
        self.assertTrue(self.account.logout(user2.session_id, user2.secret_key))  # noqa:E501
        self.assertFalse(self.account.check(user2.session_id, user2.secret_key))  # noqa:E501
        self.assertFalse(self.account.check(user2.session_id))
        self.assertFalse(self.account.check(user2.session_id, user2.secret_key))  # noqa:E501
        self.assertFalse(self.account.check(user2.session_id))

    def test_generate(self):
        self.assertIsInstance(user := self.account.login(self.username, self.password), account.SessionUser)  # noqa:E501
        assert isinstance(user, account.SessionUser)
        self.assertIsInstance(token1 := self.account.create_token(user.session_id, user.secret_key), account.UserToken)  # noqa:E501
        self.assertIsInstance(token2 := self.account.create_token(user.session_id, user.secret_key), account.UserToken)  # noqa:E501
        self.assertIsNone(self.account.create_token(user.session_id, "abc123456789"))  # noqa:E501
        self.assertIsNone(self.account.create_token(self.username, self.password))  # noqa:E501
        self.assertNotEqual(token1, token2)
        self.assertTrue(self.account.logout(user.session_id))
        self.assertIsNone(self.account.create_token(user.session_id, user.secret_key))  # noqa:E501

    def test_register(self):
        self.assertFalse(self.account.allow_register)
        self.assertRaises(PermissionError, self.account.register, "username", "password")  # noqa:E501
        self.assertRaises(PermissionError, self.account.register, self.username, self.password)  # noqa:E501
        self.account.members.config.datas[account.Account.ACCOUNT_SECTION] = {"register": True}  # noqa:E501
        self.assertTrue(self.account.allow_register)
        self.assertEqual(self.account.administrators, [self.admin])
        self.assertRaises(ValueError, self.account.register, self.username, self.password)  # noqa:E501
        self.assertIsInstance(profile := self.account.register("username", "password"), account.Profile)  # noqa:E501
        self.assertRaises(ValueError, self.account.register, "user name", "password")  # noqa:E501
        self.assertRaises(ValueError, self.account.register, "", "password")
        self.assertEqual(self.account.administrators, [self.admin])
        assert isinstance(profile, account.Profile)
        self.assertEqual(profile.workspace, account.join(self.account.catalog, "username"))  # noqa:E501
        self.assertEqual(profile.catalog, self.account.catalog)
        self.assertEqual(profile.identity, "username")
        self.assertEqual(profile.username, "username")
        self.assertFalse(profile.administrator)

    def test_terminate(self):
        self.assertRaises(PermissionError, self.account.terminate, self.username, self.password)  # noqa:E501
        self.account.members.config.datas[account.Account.ACCOUNT_SECTION] = {"register": True, "terminate": True}  # noqa:E501
        self.account.members.config.datas[account.Account.ADMIN_SECTION] = {"user": [], "first_auto": True}  # noqa:E501
        self.assertEqual(self.account.administrators, [])
        self.assertTrue(self.account.first_user_is_admin)
        self.assertTrue(self.account.allow_terminate)
        self.assertTrue(self.account.allow_register)
        self.assertIsInstance(profile := self.account.register("username", "password"), account.Profile)  # noqa:E501
        self.assertEqual(self.account.administrators, ["username"])
        assert isinstance(profile, account.Profile)
        self.assertTrue(profile.administrator)
        self.assertRaises(PermissionError, self.account.terminate, "username", "password")  # noqa:E501
        self.assertFalse(self.account.terminate(self.username, "password"))
        self.assertIsInstance(user := self.account.login(self.username, self.password, "1"), account.SessionUser)  # noqa:E501
        assert isinstance(user, account.SessionUser)
        self.assertIsInstance(token1 := self.account.create_token(user.session_id, user.secret_key), account.UserToken)  # noqa:E501
        self.assertIsInstance(token2 := self.account.create_token(user.session_id, user.secret_key), account.UserToken)  # noqa:E501
        self.assertIsNone(self.account.create_token(self.username, "password"))
        assert isinstance(token1, account.UserToken) and isinstance(token2, account.UserToken)  # noqa:E501
        self.assertIsInstance(self.account.login("", token1.hash, "2"), account.SessionUser)  # noqa:E501
        self.assertIsInstance(self.account.login("", token2.hash, "3"), account.SessionUser)  # noqa:E501
        self.assertTrue(self.account.check("1"))
        self.assertTrue(self.account.check("2"))
        self.assertTrue(self.account.check("3"))
        self.assertTrue(self.account.terminate(self.username, self.password))
        self.assertFalse(self.account.check("1"))
        self.assertFalse(self.account.check("2"))
        self.assertFalse(self.account.check("3"))
        self.assertFalse(self.account.terminate(self.username, self.password))
