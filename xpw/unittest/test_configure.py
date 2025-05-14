# coding:utf-8

import unittest
from unittest import mock

from xpw import configure


class TestBasicConfig(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.datas = {"users": {"demo": "demo"}, "admin": "demo"}
        cls.path = "test"

    @classmethod
    def tearDownClass(cls):
        pass

    @mock.patch.object(configure.BasicConfig, "dumpf", mock.MagicMock())
    def setUp(self):
        self.config = configure.BasicConfig(self.path, self.datas)
        self.assertEqual(self.config.administrators, ["demo"])

    def tearDown(self):
        pass

    @mock.patch("toml.load")
    def test_loadf(self, mock_load):
        mock_load.side_effect = [self.datas]
        self.assertIsInstance(configure.BasicConfig.loadf(), configure.BasicConfig)  # noqa:E501

    def test_dumps(self):
        self.assertIsInstance(self.config.dumps(), str)

    @mock.patch.object(configure, "open")
    def test_dumpf(self, mock_open):
        with mock.mock_open(mock_open):
            self.assertIsNone(self.config.dumpf())


class TestLdapConfig(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.ldap_datas = {
            "auth_method": "ldap",
            "admin": ("demo", "user"),
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

    @mock.patch.object(configure.BasicConfig, "dumpf", mock.MagicMock())
    def setUp(self):
        self.config = configure.BasicConfig(self.path, self.ldap_datas)
        self.assertEqual(self.config.administrators, ["demo", "user"])

    def tearDown(self):
        pass

    @mock.patch.object(configure.BasicConfig, "dumpf", mock.MagicMock())
    @mock.patch.object(configure.LdapInit, "bind")
    def test_ldap(self, mock_bind):
        config = configure.LdapConfig(self.config)
        self.assertIs(config.client, mock_bind())


if __name__ == "__main__":
    unittest.main()
