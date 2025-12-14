# coding:utf-8

from unittest import TestCase
from unittest import main
from unittest.mock import MagicMock
from unittest.mock import patch

import ldap3

from xpw import ldapauth


class FakeAttribute():
    @property
    def values(self):
        return ["demo"]


class FakeEntry(ldap3.Entry):
    def __init__(self):
        pass

    @property
    def uid(self):
        return FakeAttribute()


class TestLdapClient(TestCase):

    @classmethod
    def setUpClass(cls):
        cls.server = ldap3.Server(host="ldap://example.com")
        cls.ldap = ldapauth.LdapClient(cls.server, "demo", "demo")

    @classmethod
    def tearDownClass(cls):
        pass

    def setUp(self):
        pass

    def tearDown(self):
        pass

    @patch("ldap3.Connection")
    def test_search(self, mock_connection):
        fake_entry = FakeEntry()
        fake_connection = MagicMock()
        fake_connection.entries = [fake_entry]
        mock_connection.side_effect = [fake_connection]
        self.assertIs(self.ldap.search("ou=users,dc=demo,dc=com", "(uid=*)", ["uid"], "demo"), fake_entry)  # noqa:E501

    @patch("ldap3.Connection")
    def test_verify(self, mock_connection):
        fake_connection = MagicMock()
        fake_connection.bind.side_effect = [Exception()]
        mock_connection.side_effect = [fake_connection]
        self.assertFalse(self.ldap.verify("demo", "demo"))

    @patch("ldap3.Connection")
    def test_signed(self, mock_connection):
        fake_entry = MagicMock()
        fake_entry.uid.values = ["test"]
        fake_connection = MagicMock()
        fake_connection.entries = [fake_entry]
        mock_connection.side_effect = [fake_connection]
        self.assertIsNone(self.ldap.signed("ou=users,dc=demo,dc=com", "(uid=*)", ["uid"], "demo", "demo"))  # noqa:E501


class TestLdapInit(TestCase):

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

    @patch.object(ldapauth, "LdapClient")
    def test_ldap(self, mock_client):
        fake_client = MagicMock()
        mock_client.side_effect = [fake_client]
        self.assertIs(self.ldap.bind("test", "unit"), fake_client)


if __name__ == "__main__":
    main()
