import unittest
import logging
from t.config import api

# testing clients


class TestCommandEvents(unittest.TestCase):
    logger = logging.getLogger("sepsesam")
    old_level = logger.level
    command_names = []
    command_event_ids = []
    schedule_names = []
    test_events = []

    def setUp(self):
        self.command_names = []
        self.command_event_ids = []
        self.schedule_names = []
        self.create_command("unittest_command", "unittest_user")
        result = api.schedule_create(
            **{"name": "unittest_schedule", "absFlag": True, "tu": True, "pBase": "DAILY"})
        self.schedule_names.append(result["name"])
        self.create_command_event(
            0, "unittest_command_event", "unittest_schedule", "unittest_command")

    def tearDown(self):
        self.logger.setLevel(logging.CRITICAL)
        for id in self.command_event_ids:
            try:
                api.command_event_delete(int(id))
            except Exception:
                pass
        for name in self.schedule_names:
            try:
                api.schedule_delete(name)
            except Exception:
                pass
        for name in self.command_names:
            try:
                api.command_delete(name)
            except Exception:
                pass
        self.logger.setLevel(self.old_level)

    def test_command_event_create(self):
        self.assertEqual(self.test_events[0],  "unittest_command_event")

    def test_command_event_delete(self):
        self.assertEqual(api.command_event_delete(
            int(self.command_event_ids[0])), 0)
        self.command_event_ids.pop(0)

    def test_command_event_get(self):
        self.assertEqual(api.command_event_get(int(self.command_event_ids[0]))[
                         "name"],  "unittest_command_event")

    def test_command_event_find(self):
        self.create_command_event(
            1, "second_unittest_command_event", "unittest_schedule", "unittest_command")
        self.assertTrue(
            len(api.command_event_find(
                **{"commandName": "unittest_command"})) > 1
        )
        api.command_event_delete(int(self.command_event_ids[0]))
        self.command_event_ids.pop(0)
        self.assertTrue(
            len(api.command_event_find(
                **{"commandName": "unittest_command"})) == 1
        )

    def test_command_event_update(self):
        self.create_command("second_unittest_command",  "unittest_user")
        self.assertEqual(api.command_event_update(0,  "unittest_command_event", 0, **
                         {"object": "second_unittest_command"})["object"], "second_unittest_command")

    def test_command_event_list(self):
        original_length = len(api.command_event_list())
        self.create_command_event(
            1, "second_unittest_command_event", "unittest_schedule", "unittest_command")
        self.assertTrue(len(api.command_event_list()) == original_length+1)
        self.create_command_event(
            2, "third_unittest_command_event", "unittest_schedule", "unittest_command")
        self.assertTrue(len(api.command_event_list()) == original_length+2)
        self.assertTrue(
            any(
                cmd["name"] == "second_unittest_command_event"
                and cmd["scheduleName"] == "unittest_schedule"
                and cmd["commandName"] == "unittest_command"
                and cmd["clientId"] == 0
                for cmd in api.command_event_list()
            )
        )

    ### HELPER METHODS ###
    def create_command(self, name: str, owner: str):
        result = api.command_create(
            **{
                "name": name,
                "owner": owner,
                "type": "EXECUTE",
                "command": "echo 'command'",
            }
        )
        self.command_names.append(result["name"])

    def create_command_event(self, id: int, name: str, scheduleName: str, commandName: str):
        result = api.command_event_create(
            **{
                "id": id,
                "name": name,
                "scheduleName": scheduleName,
                "commandName": commandName,
                "clientId": 0,
            }
        )
        self.command_event_ids.append(result["id"])
        self.test_events.append(result["name"])
