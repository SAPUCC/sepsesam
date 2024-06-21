import unittest
import sepsesam.api

""" Configure before executing unittest suite """
cred = {
    "url": "http://localhost:11401",
    "username": "Administrator",
    "password": "sesam",
}

api = sepsesam.api.Api(**cred, verify=False)


class TestSepSesam(unittest.TestCase):
    """ sepsesam.api unittests """

    """ server info """

    def testGetServerInfo(self):
        self.assertEqual(api.get_server_info()["restPort"], 11401)

    """ clients """

    def testClient1List(self):
        self.assertEqual(api.client_list()[0]["id"], 0)

    def testClient2Get(self):
        self.assertEqual(api.client_get(0)["id"], 0)

    def testClient3Find(self):
        self.assertGreater(len(api.client_find(name="*")), 0)

    def testClient4Create(self):
        self.assertEqual(api.client_create("unittest")["id"], 1)

    def testClient5Update(self):
        # TODO
        return

    def testClient6Delete(self):
        self.assertEqual(api.client_delete("1"), 1)

    """ locations """

    def testLocations1List(self):
        self.assertEqual(api.location_list()[0]["id"], 0)

    def testLocations2Get(self):
        self.assertEqual(api.location_get(0)["id"], 0)

    def testLocations3Create(self):
        self.assertEqual(api.location_create("UNITTEST")["id"], 1)

    def testLocations4Delete(self):
        self.assertEqual(api.location_delete(1), 1)


if __name__ == "__main__":
    unittest.main()
