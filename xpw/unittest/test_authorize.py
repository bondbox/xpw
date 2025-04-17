# coding:utf-8

import unittest
from unittest import mock
from unittest.mock import MagicMock

from xpw import authorize


class TestAuthInit(unittest.TestCase):

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

    def test_verify(self):
        with mock.patch.object(authorize.BasicConfig, "loadf") as mock_loadf:
            mock_loadf.side_effect = [authorize.BasicConfig(self.path, self.datas)]  # noqa:E501
            auth = authorize.AuthInit.from_file()
            token = auth.generate_token()
            self.assertIsNone(auth.verify("", "test"))
            self.assertIsNone(auth.verify("test", "unit"))
            self.assertIsNone(auth.verify("demo", "test"))
            self.assertEqual(auth.verify("demo", "demo"), "demo")
            self.assertEqual(auth.verify("", token), authorize.__project__)
            self.assertIsNone(auth.delete_token("test"))
            self.assertIsNone(auth.delete_token("demo"))
            self.assertIsNone(auth.delete_token(token))
            self.assertIsNone(auth.delete_token(token))

    @mock.patch.object(authorize.LdapConfig, "client")
    def test_ldap_verify(self, mock_client):
        with mock.patch.object(authorize.BasicConfig, "loadf") as mock_loadf:
            mock_loadf.side_effect = [authorize.BasicConfig(self.path, self.ldap_datas)]  # noqa:E501
            auth = authorize.AuthInit.from_file()
            token = auth.generate_token()
            mock_client.signed.side_effect = [None, Exception(), MagicMock(entry_dn="demo")]  # noqa:E501
            self.assertIsNone(auth.verify("", "test"))
            self.assertIsNone(auth.verify("test", "unit"))
            self.assertIsNone(auth.verify("demo", "test"))
            self.assertEqual(auth.verify("demo", "demo"), "demo")
            self.assertEqual(auth.verify("", token), authorize.__project__)
            self.assertIsNone(auth.delete_token("test"))
            self.assertIsNone(auth.delete_token("demo"))
            self.assertIsNone(auth.delete_token(token))
            self.assertIsNone(auth.delete_token(token))


if __name__ == "__main__":
    unittest.main()
