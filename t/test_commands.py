import unittest
import logging
from t.config import api

# testing commands


class TestCommands(unittest.TestCase):
    logger = logging.getLogger("sepsesam")
    old_level = logger.level
    command_names = []

    def setUp(self):
        self.command_names = []
        self.create_command("unittest_command", "unittest_user")

    def tearDown(self):
        self.logger.setLevel(logging.CRITICAL)
        try:
            for name in self.command_names:
                self.deleteCommand(name)
        except Exception:
            pass
        self.logger.setLevel(self.old_level)

    def test_command_creation(self):
        result = self.create_command(
            "second_unittest_command", "unittest_user")
        self.assertEqual(result["name"], "second_unittest_command")

    def test_command_deletion(self):
        self.assertEqual(api.command_delete(
            "unittest_command"), "unittest_command")
        self.command_names.pop(0)

    def test_command_list(self):
        original_length = len(api.command_list())
        self.create_command("second_unittest_command", "unittest_user")
        self.assertTrue(len(api.command_list()) == original_length+1)
        self.create_command("third_unittest_command", "second_unittest_user")
        self.assertTrue(len(api.command_list()) == original_length+2)
        self.assertTrue(
            any(
                cmd["name"] == "second_unittest_command"
                and cmd["owner"] == "unittest_user"
                and cmd["type"] == "EXECUTE"
                and cmd["command"] == "echo 'command'"
                for cmd in api.command_list()
            )
        )

    def test_command_get(self):
        self.assertEqual(api.command_get("unittest_command")
                         ["owner"], "unittest_user")

    def test_command_find(self):
        self.create_command(
            "second_unittest_command",  "unittest_user")
        self.assertTrue(len(api.command_find(
            **{"owner": "unittest_user"})) > 1)

    def test_command_update(self):
        self.assertEqual(
            api.command_update("unittest_command", "echo 'command'", **{"owner": "third_unittest_user"})[
                "owner"
            ],
            "third_unittest_user",
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
        return result

    def deleteCommand(self, name: str):
        self.logger.setLevel(logging.CRITICAL)
        try:
            api.command_delete(name)
        except Exception:
            pass
