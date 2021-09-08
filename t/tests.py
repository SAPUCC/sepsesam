import unittest
import sepsesam.api

""" Configure before executing unittest suite """
cred = {
    "url": "http://localhost:11401",
    "username": "Administrator",
    "password": "sesam",
}

api = sepsesam.api.Api(**cred)


class TestSepSesam(unittest.TestCase):
    """ sepsesam.api unittests """

    def testGetServerInfo(self):
        self.assertEqual(api.get_server_info()["restPort"], 11401)

    def testClientList(self):
        self.assertEqual(api.client_list()[0]["id"], 0)

    def testClientGet(self):
        self.assertEqual(api.client_get(0)["id"], 0)

    def testClientFind(self):
        self.assertGreater(len(api.client_find(name="*")), 0)


if __name__ == "__main__":
    unittest.main()
