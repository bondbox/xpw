# coding:utf-8

from unittest import TestCase
from unittest import main
from unittest import mock

from xpw import configure


class TestBasicConfig(TestCase):

    @classmethod
    def setUpClass(cls):
        cls.datas = {"users": {"demo": "abc123"}}
        cls.path = "test"

    @classmethod
    def tearDownClass(cls):
        pass

    @mock.patch.object(configure.BasicConfig, "dumpf", mock.MagicMock())
    def setUp(self):
        self.config = configure.BasicConfig(self.path, self.datas)

    def tearDown(self):
        pass

    @mock.patch.object(configure, "SafeRead", mock.MagicMock())
    @mock.patch("toml.loads")
    def test_loadf(self, mock_loads):
        mock_loads.side_effect = [self.datas]
        self.assertIsInstance(configure.BasicConfig.loadf(), configure.BasicConfig)  # noqa:E501

    def test_dumps(self):
        self.assertIsInstance(self.config.dumps(), str)

    @mock.patch.object(configure, "SafeWrite", mock.MagicMock())
    def test_dumpf(self):
        self.assertIsNone(self.config.dumpf())

    def test_new(self):
        self.assertIsInstance(configure.BasicConfig.new(), configure.BasicConfig)  # noqa:E501


class TestLdapConfig(TestCase):

    @classmethod
    def setUpClass(cls):
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

    @mock.patch.object(configure.BasicConfig, "dumpf", mock.MagicMock())
    def setUp(self):
        self.config = configure.BasicConfig(self.path, self.ldap_datas)

    def tearDown(self):
        pass

    @mock.patch.object(configure.BasicConfig, "dumpf", mock.MagicMock())
    @mock.patch.object(configure.LdapInit, "bind")
    def test_ldap(self, mock_bind):
        config = configure.LdapConfig(self.config)
        self.assertIs(config.client, mock_bind())


if __name__ == "__main__":
    main()
