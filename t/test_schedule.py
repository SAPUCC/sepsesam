import unittest
import logging
from t.config import api

# testing schedules


class TestSchedules(unittest.TestCase):
    logger = logging.getLogger("sepsesam")
    old_level = logger.level
    schedule_names = []

    def setUp(self):
        self.schedule_names = []
        self.create_schedule("unittest_schedule")

    def tearDown(self):
        self.logger.setLevel(logging.CRITICAL)
        for name in self.schedule_names:
            try:
                api.schedule_delete(name)
            except Exception:
                pass
        self.logger.setLevel(self.old_level)

    def test_schedule_create(self):
        self.assertEqual(self.schedule_names[0], "unittest_schedule")

    def test_schedule_delete(self):
        self.assertEqual(api.schedule_delete(
            self.schedule_names[0]), "unittest_schedule")
        self.schedule_names.pop(0)

    def test_schedule_get(self):
        self.create_schedule("second_unittest_schedule")
        self.assertEqual(api.schedule_get("unittest_schedule")[
                         "mo"], api.schedule_get("second_unittest_schedule")["mo"])
        self.assertEqual(api.schedule_get("second_unittest_schedule")[
                         "name"], "second_unittest_schedule")

    def test_schedule_update(self):
        self.assertEqual(api.schedule_update(
            "unittest_schedule", **{"mo": "true"})["mo"], True)
        self.assertEqual(api.schedule_update(
            "unittest_schedule", **{"mo": "false"})["mo"], False)

    def test_schedule_find(self):
        self.assertEqual(
            api.schedule_find(**{"name": "unittest_schedule"})[0]['usercomment'], "unittest_comment")

    def test_schedule_list(self):
        original_length = len(api.schedule_list())
        self.create_schedule("second_unittest_schedule")
        self.assertTrue(len(api.schedule_list()) == original_length+1)
        self.create_schedule("third_unittest_schedule")
        self.assertTrue(len(api.schedule_list()) > original_length+1)
        self.assertTrue(
            any(
                sch["name"] == "second_unittest_schedule"
                and sch["absFlag"]
                and not sch["mo"]
                and sch["usercomment"] == "unittest_comment"
                for sch in api.schedule_list()
            )
        )

    ### HELPER METHODS ###
    def create_schedule(self, name):
        self.schedule_names.append(
            api.schedule_create(
                **{"name": name, "absFlag": True, "tu": True, "pBase": "DAILY", "mo": "false", "usercomment": "unittest_comment"})["name"]
        )
