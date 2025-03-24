# coding:utf-8

import unittest
from unittest import mock
from unittest.mock import MagicMock

from xpw import authorize


class TestAuthInit(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.config = {"users": {"demo": "demo"}}
        cls.ldap_config = {
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

    @classmethod
    def tearDownClass(cls):
        pass

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_verify(self):
        with mock.patch.object(authorize.BasicConfig, "loadf") as mock_loadf:
            mock_loadf.side_effect = [self.config]
            auth = authorize.AuthInit.from_file()
            self.assertIsNone(auth.verify("test", "unit"))
            self.assertIsNone(auth.verify("demo", "test"))
            self.assertEqual(auth.verify("demo", "demo"), "demo")

    @mock.patch.object(authorize.LdapConfig, "client")
    def test_ldap_verify(self, mock_client):
        with mock.patch.object(authorize.BasicConfig, "loadf") as mock_loadf:
            mock_loadf.side_effect = [self.ldap_config]
            auth = authorize.AuthInit.from_file()
            mock_client.signed.side_effect = [None, Exception(), MagicMock(entry_dn="demo")]  # noqa:E501
            self.assertIsNone(auth.verify("test", "unit"))
            self.assertIsNone(auth.verify("demo", "test"))
            self.assertEqual(auth.verify("demo", "demo"), "demo")


if __name__ == "__main__":
    unittest.main()
