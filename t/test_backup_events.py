import unittest
import logging
from t.config import api

# testing backup events


class TestBackupEvents(unittest.TestCase):
    logger = logging.getLogger("sepsesam")
    old_level = logger.level
    backup_tasks = []
    schedules = []
    media_pools = []
    drive_groups = []
    backup_event_ids = []
    backup_events = []
    current = []

    def setUp(self):
        self.backup_tasks = []
        self.schedules = []
        self.media_pools = []
        self.backup_events = []
        self.backup_event_ids = []
        self.drive_groups = []
        self.create_backup_event_initial(
            "unittest_backup_event", "unittest_backup_task_be", "unittest_schedule_be", "unittest_dg_be", "unittest_mp_be")

    def tearDown(self):
        self.logger.setLevel(logging.CRITICAL)
        for id in self.backup_event_ids:
            try:
                api.backup_event_delete(int(id))
            except Exception:
                pass
        for name in self.media_pools:
            try:
                api.media_pool_delete(name)
            except Exception:
                pass
        for dg in self.drive_groups:
            try:
                api.drive_group_delete(dg)
            except Exception:
                pass
        for name in self.schedules:
            try:
                api.schedule_delete(name)
            except Exception:
                pass
        for name in self.backup_tasks:
            try:
                api.backup_task_delete(name)
            except Exception:
                pass
        self.logger.setLevel(self.old_level)

    def test_backup_event_create(self):
        self.assertEqual(self.backup_events[0], "unittest_backup_event")

    def test_backup_event_delete(self):
        self.assertEqual(api.backup_event_delete(
            self.backup_event_ids[0]), int(self.backup_event_ids[0]))
        self.backup_event_ids.pop(0)

    def test_backup_event_list(self):
        original_length = len(api.backup_event_list())

        self._create_backup_event_solo("second_unittest_backup_event")
        self.assertTrue(len(api.backup_event_list()) == original_length+1)

        self._create_backup_event_solo("third_unittest_backup_event")
        self.assertTrue(len(api.backup_event_list()) >= original_length+2)

        self.assertTrue(
            any(
                be["name"] == "third_unittest_backup_event"
                and be["scheduleName"] == "unittest_schedule_be"
                and be["mediaPool"] == "unittest_mp_be"
                for be in api.backup_event_list()
            )
        )

    def test_backup_event_get(self):
        self.assertEqual(api.backup_event_get(self.backup_event_ids[0])[
                         "name"], "unittest_backup_event")

    def test_backup_event_find(self):
        self.assertTrue(len(api.backup_event_find(
            **{"taskName": "unittest_backup_task_be"})) == 1)

        self._create_backup_event_solo("second_unittest_backup_event")
        self.assertTrue(len(api.backup_event_find(
            **{"taskName": "unittest_backup_task_be"})) == 2)

        self.backup_tasks.append(
            api.backup_task_create(
                "second_unittest_backup_task_be",
                **{"client": api.client_list()[0]["name"],
                   "source": "C:/tmp"}
            )["name"])
        self.create_backup_event_solo(
            "third_unittest_backup_event", "second_unittest_backup_task_be", self.schedules[0], self.media_pools[0])
        self.assertTrue(len(api.backup_event_find(
            **{"taskName": "unittest_backup_task_be"})) == 2)

    def test_backup_event_update(self):
        self.assertEqual(
            api.backup_event_update(
                self.backup_event_ids[0],
                "unittest_backup_task_be",
                "unittest_mp_be",
                **{"name": "new_unittest_backup_event"}
            )["name"],
            "new_unittest_backup_event")

    ### HELPER METHODS ###
    def create_backup_event_initial(self, backup_event_name, backup_task_name, schedule_name, drive_group_name, media_pool_name):
        self.backup_tasks.append(
            api.backup_task_create(
                backup_task_name,
                **{"client": api.client_list()[0]["name"], "source": "C:/tmp"}
            )["name"]
        )
        self.schedules.append(
            api.schedule_create(
                **{"name": schedule_name,
                   "absFlag": True,
                   "tu": True,
                   "pBase": "DAILY"}
            )["name"]
        )
        self.drive_groups.append(
            int(api.drive_group_create(drive_group_name)["id"]))
        self.media_pools.append(
            api.media_pool_create(
                media_pool_name,
                **{"driveGroupId": self.drive_groups[0]}
            )["name"]
        )
        self.create_backup_event_solo(
            backup_event_name, backup_task_name, schedule_name, media_pool_name)

    def _create_backup_event_solo(self, backup_event_name):
        self.create_backup_event_solo(
            backup_event_name, self.backup_tasks[0], self.schedules[0], self.media_pools[0])

    def create_backup_event_solo(self, backup_event_name, backup_task_name, schedule_name, media_pool_name):
        result = api.backup_event_create(backup_task_name,
                                         **{
                                             "name": backup_event_name,
                                             "scheduleName": schedule_name,
                                             "grpFlag": False,
                                             "fdiType": {
                                                 "value": "F",
                                                 "cfdi": "FULL"
                                             },
                                             "mediaPool": media_pool_name
                                         }
                                         )
        self.backup_event_ids.append(result["id"])
        self.backup_events.append(result["name"])
