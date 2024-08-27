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
    """sepsesam.api unittests"""

    """Managing Backup Tasks"""

    # backup_task_create
    def test_backupTaskCreate(self):
        # backup_task_create
        api.backup_task_create(
            "Unittest_BackupTask",
            **{"client": api.client_list()[0]["name"], "source": "C:/tmp"},
        )

        # Backup-task-get
        self.assertEqual(
            api.backup_task_get("Unittest_BackupTask")["name"], "Unittest_BackupTask"
        )
        self.assertEqual(api.backup_task_get("Unittest_BackupTask")["client"]["id"], 0)

        # backup_task_delete
        api.backup_task_delete("Unittest_BackupTask")
        with self.assertRaises(sepsesam.api.SEPSesamAPIError):
            api.backup_task_get("Unittest_BackupTask")
            self.assertEqual(
                api.backup_task_get("Unittest_BackupTask")["error"],
                "object.not.found.id",
            )

    """Managing Clients"""

    def test_Clients(self):
        # client create
        self.assertEqual(api.client_create("unittest_Client")["id"], 1)

        # client_find
        self.assertGreater(len(api.client_find(name="*")), 1)
        self.assertEqual(
            api.client_find(**{"name": "unittest_Client"})[0]["name"], "unittest_Client"
        )

        # client update
        self.assertRaises(Exception, api.client_update, None, None)
        self.assertEqual(
            api.client_update(1, **{"usercomment": "test"})["usercomment"],
            "test",
        )

        # client delete
        self.assertEqual(api.client_delete("1"), 1)
        self.assertLess(len(api.client_find(name="*")), 2)

    """Manage external groups"""

    def test_externalGroups(self):
        # # external_group_create
        self.assertEqual(
            api.external_group_create(externalId="Unittest_ExternalGroup", enabled=True)[
                "externalId"
            ],
            "Unittest_ExternalGroup",
        )

        # external_group_list
        self.assertEqual(
            api.external_group_list()[0]["externalId"], "Unittest_ExternalGroup"
        )

        # external_group_get
        self.assertEqual(
            api.external_group_get(id="1")["externalId"], "Unittest_ExternalGroup"
        )

        # external_group_find
        self.assertEqual(
            api.external_group_find(
                **{"externalId": "Unittest_ExternalGroup", "id": 1}
            )[0]["externalId"],
            "Unittest_ExternalGroup",
        )

        # external_group_update
        self.assertEqual(
            api.external_group_update(
                externalId="Unittest_ExternalGroup", enabled=False
            )["enabled"],
            False,
        )
        self.assertEqual(
            api.external_group_update(
                externalId="Unittest_ExternalGroup_renamed", id="1"
            )["externalId"],
            "Unittest_ExternalGroup_renamed",
        )

        # external_group_update_relations and external_group_get_relations
        groups = ["OPERATOR", "BACKUP"]
        relating_groups = api.external_group_update_relations(
            externalId="Unittest_ExternalGroup_renamed", groups=groups
        )
        self.assertEqual(
            [group["name"] for group in relating_groups], ["OPERATOR", "BACKUP"]
        )
        relating_groups = api.external_group_get_relations(
            externalId="Unittest_ExternalGroup_renamed"
        )
        self.assertEqual(
            [group["name"] for group in relating_groups], ["OPERATOR", "BACKUP"]
        )
        relating_groups = api.external_group_get_relations(
            id="1"
        )
        self.assertEqual(
            [group["name"] for group in relating_groups], ["OPERATOR", "BACKUP"]
        )

        # external_group_delete
        api.external_group_delete(1)

    """Manage Groups"""

    def test_GroupCreateAndDelete(self):
        # group_create
        self.assertEqual(
            api.group_create(
                5,
                **{"name": "UnittestGroup", "enabled": True, "rolesList": ["ReadOnly"]},
            )["id"],
            5,
        )

        # group_delete
        self.assertEqual(api.group_delete(5), 5)

    """Manage locations"""

    # location_create and location_delete
    def test_LocationsCreateAndDelete(self):
        # location create
        self.assertEqual(api.location_create("UNITTEST_LOCATION")["id"], 1)

        # location_resolve_to_id
        self.assertEqual(api.location_resolve_to_id("UNITTEST_LOCATION"), 1)

        # id has to be unique
        with self.assertRaises(sepsesam.api.SEPSesamAPIError):
            self.assertEqual(
                api.location_create("UNITTEST_LOCATION2", **{"id": 1})["error"],
                "duplicate.entry",
            )

        # location delete
        api.location_delete(1)
        self.assertEqual(api.location_get(1), None)

    """Manage commands"""

    def test_command_handling(self):
        # no commands should exist
        self.assertEqual(api.command_list(), [])

        api.command_create(
            **{
                "name": "newerCommand",
                "owner": "Marcus",
                "type": "EXECUTE",
                "command": "echo 'command'",
            }
        )

        self.assertEqual(api.command_get("newerCommand")["owner"], "Marcus")

        # create second command for testing the command_find method
        api.command_create(
            **{
                "name": "newererCommand",
                "owner": "Marcus",
                "type": "EXECUTE",
                "command": "echo 'command'",
            }
        )

        # finds more than one command matching "owner":"Marcus"
        self.assertTrue(len(api.command_find(**{"owner": "Marcus"})) > 1)

        # only one command with the owner Marcus should be left after command_update
        self.assertEqual(
            api.command_update("newererCommand", "echo 'command'", **{"owner": "Mike"})[
                "owner"
            ],
            "Mike",
        )
        self.assertEqual(
            api.command_find(**{"owner": "Marcus"}), [api.command_get("newerCommand")]
        )

        # cleaning up
        self.assertEqual(api.command_delete("newererCommand"), "newererCommand")
        self.assertEqual(api.command_delete("newerCommand"), "newerCommand")
        self.assertEqual(api.command_list(), [])

        """Manage command events"""
        """ Same test as commands due to dependency of command events """

        # no command events should exist at the beginning
        self.assertEqual(api.command_event_list(), [])

        # create commands and schedule as prerequisite
        api.command_create(
            **{
                "name": "eventCommand1",
                "owner": "Marcus",
                "type": "EXECUTE",
                "command": "echo 'command'",
            }
        )
        api.command_create(
            **{
                "name": "eventCommand2",
                "owner": "Marcus",
                "type": "EXECUTE",
                "command": "echo 'command'",
            }
        )
        api.schedule_create(
            **{"name": "mySchedule", "absFlag": True, "tu": True, "pBase": "DAILY"}
        )

        api.command_event_create(
            **{
                "id": 0,
                "name": "testEvent1",
                "scheduleName": "mySchedule",
                "commandName": "eventCommand1",
                "clientId": 0,
            }
        )

        # testing event_get()
        self.assertEqual(api.command_event_get(0)["name"], "testEvent1")

        # creating second event for find() testing
        # command_event_find is only working if the command_event has a assigned schedule
        api.command_event_create(
            **{
                "id": 1,
                "name": "testEvent2",
                "scheduleName": "mySchedule",
                "commandName": "eventCommand1",
                "clientId": 0,
            }
        )
        self.assertTrue(
            len(api.command_event_find(**{"commandName": "eventCommand1"})) > 1
        )

        # there should only be found one command event after the update
        api.command_event_update(1, "testEvent2", 0, **{"object": "eventCommand2"})
        self.assertEqual(api.command_event_get(1)["object"], "eventCommand2")

        # command_event_find not working yet
        self.assertTrue(
            len(api.command_event_find(**{"commandName": "eventCommand1"})) == 1
        )

        # cleaning up
        api.command_event_delete(0)
        api.command_event_delete(1)
        api.command_delete("eventCommand1")
        api.command_delete("eventCommand2")
        api.schedule_delete("mySchedule")

        self.assertEqual(api.command_event_list(), [])

    """ Manage backup schedule """

    def test_schedule(self):
        # create Backup schedule
        api.schedule_create("APISchedule1", **{"mo": "false"})
        api.schedule_create("APISchedule2", **{"mo": "false"})

        # find and list
        self.assertTrue(len(api.schedule_find(**{"mo": "false"})) > 1)
        self.assertTrue(api.schedule_list() != [])

        # get and update backup schedules
        self.assertEqual(
            api.schedule_get("APISchedule1")["mo"],
            api.schedule_get("APISchedule2")["mo"],
        )
        api.schedule_update("APISchedule2", **{"mo": "true"})
        self.assertNotEqual(
            api.schedule_get("APISchedule1")["mo"],
            api.schedule_get("APISchedule2")["mo"],
        )

        # APISchedule1 is found in list()
        names = [schedule["name"] for schedule in api.schedule_list()]
        self.assertIn("APISchedule1", names)

        # clean up
        api.schedule_delete("APISchedule1")
        api.schedule_delete("APISchedule2")

        # APISchedule1 should not be found anymore
        names = [schedule["name"] for schedule in api.schedule_list()]
        self.assertNotIn("APISchedule1", names)

    """Drive group handling"""

    def test_drive_group(self):
        # test if there are already drive_groups
        if api.drive_group_list() != []:
            # check if get and list produce the same result
            self.assertEqual(
                api.drive_group_list()[0]["name"], api.drive_group_get(1)["name"]
            )

            # check if drive_group_get() is able to access drive groups by name and id
            self.assertEqual(
                api.drive_group_get(1), api.drive_group_get(None, "Test-Drives")
            )


if __name__ == "__main__":
    unittest.main()
