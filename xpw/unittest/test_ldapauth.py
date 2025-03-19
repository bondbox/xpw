# coding:utf-8

import unittest
from unittest import mock

from mock import MagicMock

from xpw import ldapauth


class TestLdapClient(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.server = ldapauth.Server(host="ldap://example.com")
        cls.ldap = ldapauth.LdapClient(cls.server, "demo", "demo")

    @classmethod
    def tearDownClass(cls):
        pass

    def setUp(self):
        pass

    def tearDown(self):
        pass

    @mock.patch.object(ldapauth, "Connection")
    def test_search(self, mock_connection):
        fake_entry = MagicMock()
        fake_entry.uid.values = ["demo"]
        fake_connection = MagicMock()
        fake_connection.entries = [fake_entry]
        mock_connection.side_effect = [fake_connection]
        self.assertIs(self.ldap.search("ou=users,dc=demo,dc=com", "(uid=*)", ["uid"], "demo"), fake_entry)  # noqa:E501

    @mock.patch.object(ldapauth, "Connection")
    def test_verify(self, mock_connection):
        fake_connection = MagicMock()
        fake_connection.bind.side_effect = [Exception()]
        mock_connection.side_effect = [fake_connection]
        self.assertFalse(self.ldap.verify("demo", "demo"))

    @mock.patch.object(ldapauth, "Connection")
    def test_signed(self, mock_connection):
        fake_entry = MagicMock()
        fake_entry.uid.values = ["test"]
        fake_connection = MagicMock()
        fake_connection.entries = [fake_entry]
        mock_connection.side_effect = [fake_connection]
        self.assertIsNone(self.ldap.signed("ou=users,dc=demo,dc=com", "(uid=*)", ["uid"], "demo", "demo"))  # noqa:E501


class TestLdapInit(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.ldap = ldapauth.LdapInit.from_url("ldap://example.com")

    @classmethod
    def tearDownClass(cls):
        pass

    def setUp(self):
        pass

    def tearDown(self):
        pass

    @mock.patch.object(ldapauth, "LdapClient")
    def test_ldap(self, mock_client):
        fake_client = MagicMock()
        mock_client.side_effect = [fake_client]
        self.assertIs(self.ldap.bind("test", "unit"), fake_client)


if __name__ == "__main__":
    unittest.main()
