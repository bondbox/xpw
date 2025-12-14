# coding:utf-8

from unittest import TestCase
from unittest import main
from unittest import mock

from xpw import authorize


class TestToken(TestCase):
    @classmethod
    def setUpClass(cls):
        cls.usr_token: authorize.UserToken = authorize.UserToken.create("demo", "test")  # noqa:E501
        cls.api_token: authorize.ApiToken = authorize.ApiToken.create()  # noqa:E501

    @classmethod
    def tearDownClass(cls):
        pass

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_api_token_check_property(self):
        info: str = f"ApiToken({self.api_token.name}, {self.api_token.user}, {self.api_token.note})"  # noqa:E501
        self.assertEqual(self.api_token.user, authorize.ApiToken.DEFAULT_USER)
        self.assertEqual(self.api_token.note, authorize.ApiToken.DEFAULT_NOTE)
        self.assertEqual(str(self.api_token), info)

    def test_user_token_check_property(self):
        info: str = f"UserToken({self.usr_token.name}, {self.usr_token.user}, {self.usr_token.note})"  # noqa:E501
        self.assertEqual(self.usr_token.user, "demo")
        self.assertEqual(self.usr_token.note, "test")
        self.assertEqual(str(self.usr_token), info)

    def test_user_token_renew(self):
        self.assertIsNot(new_token := self.usr_token.renew(), self.usr_token)
        self.assertNotEqual(self.usr_token.hash, new_token.hash)
        self.assertEqual(self.usr_token.name, new_token.name)
        self.assertEqual(self.usr_token.note, new_token.note)
        self.assertEqual(self.usr_token.user, new_token.user)


class TestAuthInit(TestCase):

    @classmethod
    def setUpClass(cls):
        cls.datas = {"users": {"demo": "demo"}}
        cls.ldap_datas = {
            "auth_method": "ldap",
            "ldap": {
                "server": "example.com",
                "bind_username": "cn=admin,dc=demo,dc=com",
                "bind_password": "123456",
                "search_base": "ou=users,dc=demo,dc=com",
                "search_filter": "(uid=*)",
                "search_attributes": ["uid"],
            }
        }
        cls.path = "test"

    @classmethod
    def tearDownClass(cls):
        pass

    def setUp(self):
        pass

    def tearDown(self):
        pass

    @mock.patch.object(authorize, "exists", mock.MagicMock(side_effect=[True]))
    @mock.patch.object(authorize.BasicConfig, "dumpf", mock.MagicMock())
    def test_api_token(self):
        with mock.patch.object(authorize.BasicConfig, "loadf") as mock_loadf:
            mock_loadf.side_effect = [authorize.BasicConfig(self.path, self.datas)]  # noqa:E501
            auth = authorize.AuthInit.from_file()
            self.assertRaises(RuntimeWarning, auth.create_api_token, token="abc123", store=True)  # noqa:E501
            self.assertIsInstance(auth.create_api_token(token="abc123", store=False), authorize.ApiToken)  # noqa:E501
            self.assertIsInstance(auth.create_api_token(token="", store=True), authorize.ApiToken)  # noqa:E501

    @mock.patch.object(authorize, "exists", mock.MagicMock(side_effect=[True]))
    @mock.patch.object(authorize.BasicConfig, "dumpf", mock.MagicMock())
    def test_verify(self):
        with mock.patch.object(authorize.BasicConfig, "loadf") as mock_loadf:
            mock_loadf.side_effect = [authorize.BasicConfig(self.path, self.datas)]  # noqa:E501
            auth = authorize.AuthInit.from_file()
            self.assertIsInstance(token1 := auth.generate_user_token("demo", "test"), authorize.UserToken)  # noqa:E501
            self.assertIsInstance(token2 := auth.update_user_token(token1.name), authorize.UserToken)  # noqa:E501
            self.assertIsInstance(token3 := auth.update_user_token(token1.name), authorize.UserToken)  # noqa:E501
            self.assertIsNone(auth.update_user_token("test_token"))
            assert isinstance(token2, authorize.UserToken)
            assert isinstance(token3, authorize.UserToken)
            self.assertIsNone(auth.verify("", "test"))
            self.assertIsNone(auth.verify("test", "unit"))
            self.assertIsNone(auth.verify("demo", "test"))
            self.assertEqual(auth.verify("demo", "demo"), "demo")
            self.assertEqual(auth.verify("", token3.hash), "demo")
            self.assertIsNone(auth.verify("", token2.hash))
            self.assertIsNone(auth.delete_user_token("test"))
            self.assertIsNone(auth.delete_user_token("demo"))
            self.assertIsNone(auth.delete_user_token(token1.name))
            self.assertIsNone(auth.delete_user_token(token2.name))
            self.assertIsNone(auth.delete_user_token(token3.name))
            self.assertIsNone(auth.verify("", token1.hash))
            self.assertIsNone(auth.verify("", token2.hash))
            self.assertIsNone(auth.verify("", token3.hash))

    @mock.patch.object(authorize, "exists", mock.MagicMock(side_effect=[True]))
    @mock.patch.object(authorize.BasicConfig, "dumpf", mock.MagicMock())
    @mock.patch.object(authorize.LdapConfig, "client")
    def test_ldap_verify(self, mock_client):
        with mock.patch.object(authorize.BasicConfig, "loadf") as mock_loadf:
            mock_loadf.side_effect = [authorize.BasicConfig(self.path, self.ldap_datas)]  # noqa:E501
            auth = authorize.AuthInit.from_file()
            token1 = auth.generate_user_token("demo", "test")
            self.assertIsInstance(token2 := auth.update_user_token(token1.name), authorize.UserToken)  # noqa:E501
            self.assertIsInstance(token3 := auth.update_user_token(token1.name), authorize.UserToken)  # noqa:E501
            self.assertIsNone(auth.update_user_token("test_token"))
            assert isinstance(token2, authorize.UserToken)
            assert isinstance(token3, authorize.UserToken)
            mock_client.signed.side_effect = [None, Exception(), mock.MagicMock(uid="demo")]  # noqa:E501
            self.assertIsNone(auth.verify("", "test"))
            self.assertIsNone(auth.verify("test", "unit"))
            self.assertIsNone(auth.verify("demo", "test"))
            self.assertEqual(auth.verify("demo", "demo"), "demo")
            self.assertEqual(auth.verify("", token3.hash), "demo")
            self.assertIsNone(auth.verify("", token2.hash))
            self.assertIsNone(auth.delete_user_token("test"))
            self.assertIsNone(auth.delete_user_token("demo"))
            self.assertIsNone(auth.delete_user_token(token1.name))
            self.assertIsNone(auth.delete_user_token(token2.name))
            self.assertIsNone(auth.delete_user_token(token3.name))
            self.assertIsNone(auth.verify("", token1.hash))
            self.assertIsNone(auth.verify("", token2.hash))
            self.assertIsNone(auth.verify("", token3.hash))

    @mock.patch.object(authorize, "exists", mock.MagicMock(side_effect=[True]))
    @mock.patch.object(authorize.BasicConfig, "dumpf", mock.MagicMock())
    def test_user(self):
        with mock.patch.object(authorize.BasicConfig, "loadf") as mock_loadf:
            mock_loadf.side_effect = [authorize.BasicConfig(self.path, self.datas)]  # noqa:E501
            auth = authorize.AuthInit.from_file()
            self.assertEqual(auth.create_user("user", "unit"), "user")
            self.assertRaises(ValueError, auth.create_user, "user", "unit")
            self.assertRaises(ValueError, auth.change_password, "abcd", "unit", "test")  # noqa:E501
            self.assertRaises(ValueError, auth.change_password, "user", "demo", "test")  # noqa:E501
            self.assertEqual(auth.change_password("user", "unit", "test"), "user")  # noqa:E501
            self.assertRaises(ValueError, auth.change_password, "user", "unit", "test")  # noqa:E501
            self.assertRaises(ValueError, auth.delete_user, "user", "unit")
            self.assertTrue(auth.delete_user("user", "test"))
            self.assertRaises(ValueError, auth.delete_user, "user", "test")


if __name__ == "__main__":
    main()
