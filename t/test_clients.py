import unittest
from t.config import api
import logging

# testing clients


class TestClients(unittest.TestCase):
    logger = logging.getLogger("sepsesam")
    old_level = logger.level
    client_name = "unittest_client"
    client_ids = []

    def setUp(self):
        self.client_ids = []
        self.client_ids.append(api.client_create(self.client_name)["id"])

    def tearDown(self):
        self.logger.setLevel(logging.CRITICAL)
        try:
            for id in self.client_ids:
                api.client_delete(id)
        except Exception:
            pass
        self.logger.setLevel(self.old_level)

    def test_client_create(self):
        result = api.client_create("second_unittest_client")
        self.client_ids.append(result["id"])
        self.assertEqual(result["name"], "second_unittest_client")

    def test_client_find(self):
        self.assertGreater(len(api.client_find(name="*")), 1)
        self.assertEqual(api.client_find(
            **{"name": "unittest_client"})[0]["name"], "unittest_client")

    def test_client_delete(self):
        api.client_delete(self.client_ids[0])
        clients = api.client_find(name=self.client_name)
        self.assertFalse(any(c["name"] == self.client_name for c in clients))

    def test_client_update(self):
        self.assertRaises(Exception, api.client_update, None, None)
        self.assertEqual(api.client_update(self.client_ids[0], usercomment="unittest_command")[
                         "usercomment"], "unittest_command")

    def test_client_get(self):
        self.assertEqual(api.client_get(self.client_name)
                         ["id"], self.client_ids[0])

    def test_client_list(self):
        self.assertTrue(
            any(
                cli["name"] == self.client_name
                for cli in api.client_list()
            )
        )
        api.client_delete(self.client_ids[0])
        self.logger.setLevel(logging.CRITICAL)
        self.assertFalse(
            any(
                cli["name"] == self.client_name
                for cli in api.client_list()
            )
        )
