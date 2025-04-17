# coding:utf-8

import unittest
from unittest import mock

from xpw import configure


class TestBasicConfig(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.config = {"users": {"demo": "demo"}}

    @classmethod
    def tearDownClass(cls):
        pass

    def setUp(self):
        pass

    def tearDown(self):
        pass

    @mock.patch("toml.load")
    def test_loadf(self, mock_load):
        mock_load.side_effect = [self.config]
        self.assertIs(configure.BasicConfig.loadf(), self.config)

    def test_dumps(self):
        config = configure.BasicConfig(self.config)
        self.assertIsInstance(config.dumps(), str)

    @mock.patch.object(configure, "open")
    def test_dumpf(self, mock_open):
        with mock.mock_open(mock_open):
            config = configure.BasicConfig(self.config)
            self.assertIsNone(config.dumpf())


class TestLdapConfig(unittest.TestCase):

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

    @mock.patch.object(configure.LdapInit, "bind")
    def test_ldap(self, mock_bind):
        config = configure.LdapConfig(self.ldap_config)
        self.assertIs(config.client, mock_bind())


if __name__ == "__main__":
    unittest.main()
