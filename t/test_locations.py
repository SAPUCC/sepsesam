import unittest
import logging
from t.config import api
from sepsesam.api import SEPSesamAPIError

#testing locations
class TestLocations(unittest.TestCase):
    logger = logging.getLogger("sepsesam")
    old_level = logger.level
    location_ids = []

    def setUp(self):
        self.location_ids = []
        self.location_ids.append(api.location_create("unittest_location", contact="testing")["id"])
            
    def tearDown(self):
        try:
            for id in reversed(self.location_ids):
                api.location_delete(id)
        except:
            pass
        self.logger.setLevel(self.old_level)

    def test_location_create(self):
        result = api.location_create("second_unittest_location")
        self.location_ids.append(result["id"])
        self.assertIsInstance(result, dict)
        self.assertEqual(result["name"], "second_unittest_location")

    def test_location_delete(self):
        self.assertEqual(api.location_delete(self.location_ids[0]), self.location_ids[0])
        self.location_ids.pop()

    def test_location_resolve_to_id(self):
        self.assertEqual(api.location_resolve_to_id("unittest_location"), self.location_ids[0])

    def test_location_unique_id(self):
        self.logger.setLevel(logging.CRITICAL)
        with self.assertRaises(SEPSesamAPIError):
            self.assertEqual(
                api.location_create("second_unittest_location", **{"id": self.location_ids[0]})["error"],
                "duplicate.entry",
            )
            
    def test_location_get(self):
        self.assertEqual(api.location_get("unittest_location")["id"], self.location_ids[0])

    def test_location_list(self):
        self.logger.setLevel(logging.CRITICAL)
        result = api.location_create("second_unittest_location")
        id_now = result["id"]
        self.location_ids.append(id_now)
        names = [cmd["name"] for cmd in api.location_list()]
        self.assertIn("unittest_location", names)
        self.assertIn("second_unittest_location", names)
        api.location_delete(id_now)
        self.assertFalse(
            any(
                loc["name"] == "second_unittest_location"
                for loc in api.location_list()
            )
        )
        self.location_ids.remove(id_now)

    def test_location_find(self):
        id_now = api.location_create("third_unittest_location", parentId=self.location_ids[0])["id"]
        self.location_ids.append(id_now)

        locations = api.location_find(self.location_ids[0])
        self.assertTrue(
            any(
                loc["id"] == id_now 
                and loc["name"] == "third_unittest_location" 
                for loc in locations)
        )

    def test_location_update(self):
        self.assertEqual(api.location_get("unittest_location")["contact"],"testing")
        api.location_update(self.location_ids[0], "unittest_location", contact="testing_done")
        self.assertEqual(api.location_get("unittest_location")["contact"],"testing_done")