# coding:utf-8

from errno import EINVAL
from unittest import TestCase
from unittest import main
from unittest import mock

from xpw import pwhasher


class TestLocaleTemplate(TestCase):

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

    def test_verify(self):
        with mock.patch.object(pwhasher, "open", mock.mock_open(read_data="$argon2id$v=19$m=65536,t=16,p=8$/Pdirf1TKZaTeCWeqrDiiwk6kwGo60vIhhCJB8/XtnA$X0wLLu01TDA4lauZl589OMDW1q5hCsruOU8LpJc5Q/yZvpRJjEt+iE5vB8gVkVaUjBrVDd1ZO5ykH0NbMZJFMQ")):  # noqa:E501
            self.assertEqual(pwhasher.main("verify unit".split()), EINVAL)
            self.assertEqual(pwhasher.main("verify test".split()), 0)

    def test_encode(self):
        with mock.patch.object(pwhasher, "open", mock.mock_open()):
            self.assertEqual(pwhasher.main("encode --store demo --password test".split()), 0)  # noqa:E501
            self.assertEqual(pwhasher.main("encode --password test".split()), 0)  # noqa:E501


if __name__ == "__main__":
    main()
