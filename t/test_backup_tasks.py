import unittest
import logging
from t.config import api

#testing backup tasks
class TestBackupTasks(unittest.TestCase):
    task_name = "unittest_backup_task"
    logger = logging.getLogger("sepsesam")
    old_level = logger.level

    def setUp(self):
        try:
            api.backup_task_create(self.task_name, **{"client": api.client_list()[0]["name"], "source": "C:/tmp"})
        except:
            pass

    def tearDown(self):
        try:
            if api.backup_task_get(self.task_name) is not None:
                api.backup_task_delete(self.task_name)
        except:
            pass
        self.logger.setLevel(self.old_level)

    def test_backup_task_create(self):
        self.assertEqual(api.backup_task_create(name= "second_unittest_backup_task", **{"client": api.client_list()[0]["name"], "source": "C:/tmp"})["name"], "second_unittest_backup_task")
        api.backup_task_delete("second_unittest_backup_task")

    def test_backup_task_is_delete(self):
        self.logger.setLevel(logging.CRITICAL)
        api.backup_task_delete(self.task_name)
        self.assertIsNone(api.backup_task_get(self.task_name))

    def test_backup_task_get(self):
        self.assertEqual(api.backup_task_get(self.task_name)["name"], self.task_name)
        self.assertEqual(api.backup_task_get(self.task_name)["client"]["name"], api.client_list()[0]["name"])
        self.assertEqual(api.backup_task_get(self.task_name)["client"]["id"], 0)
        self.assertNotEqual(api.backup_task_get(self.task_name), None)

    def test_backup_task_list(self):
        self.assertTrue(
            any(
                bck["name"] == self.task_name
                for bck in api.backup_task_list()
            )
        )
        api.backup_task_delete(self.task_name)
        self.logger.setLevel(logging.CRITICAL)
        self.assertFalse(
            any(
                bck["name"] == self.task_name
                for bck in api.backup_task_list()
            )
        )

    def test_backup_task_find(self):
        tasks = api.backup_task_find(name = "unittest_backup_task")
        self.assertTrue(any(task["name"] == "unittest_backup_task" for task in tasks))
        api.backup_task_delete(self.task_name)
        self.logger.setLevel(logging.CRITICAL)
        tasks = api.backup_task_find(name = "unittest_backup_task")
        self.assertFalse(any(task["name"] == "unittest_backup_task" for task in tasks))

    def test_backup_task_update(self):
        new_source = "/"
        api.backup_task_create(name= "second_unittest_backup_task", **{"client": api.client_list()[0]["name"], "source": "C:/tmp"})
        result = api.backup_task_update(
            name= "second_unittest_backup_task", client = api.client_list()[0], source = new_source
        )
        self.assertEqual(result["source"], new_source)

        updated_task = api.backup_task_get("second_unittest_backup_task")
        self.assertIsNotNone(updated_task)
        self.assertEqual(updated_task["source"], new_source)
        api.backup_task_delete("second_unittest_backup_task")