import unittest
from t.config import api
import logging

#testing drive groups
class TestDriveGroups(unittest.TestCase):
    logger = logging.getLogger("sepsesam")
    old_level = logger.level
    drive_groups = []
    drive_group_ids = []

    def setUp(self):
        self.drive_groups = []
        self.drive_group_ids = []
        self.create_drive_group("unittest_drive_group")

    def tearDown(self):
        self.logger.setLevel(logging.CRITICAL)
        for dg in self.drive_group_ids:
            try:
                api.drive_group_delete(int(dg))
            except:
                pass
        self.logger.setLevel(self.old_level)

    def test_drive_group_create(self):
        self.assertEqual(self.drive_groups[0], "unittest_drive_group")

    def test_drive_group_delete(self):
        self.assertEqual(api.drive_group_delete(int(self.drive_group_ids[0])), self.drive_group_ids[0])
        self.drive_group_ids.pop(0)

    def test_drive_group_list(self):
        original_length = len(api.drive_group_list())
        self.create_drive_group("second_unittest_drive_group")
        self.assertTrue(len(api.drive_group_list()) == original_length+1)
        self.create_drive_group("third_unittest_drive_group")
        self.assertTrue(len(api.drive_group_list()) >= original_length+2)
        self.assertTrue(
            any(
                dg["name"] == "third_unittest_drive_group"
                and dg["usercomment"] == "unittest_comment"
                for dg in api.drive_group_list()
            )
        )

    def test_drive_group_get(self):
        self.assertEqual(api.drive_group_get(self.drive_group_ids[0])["usercomment"], "unittest_comment")

    def test_drive_group_find(self):
        self.assertTrue(len(api.drive_group_find(**{"usercomment":"unittest_comment"})) == 1) 
        self.create_drive_group("second_unittest_drive_group")
        self.assertTrue(len(api.drive_group_find(**{"usercomment":"unittest_comment"})) == 2) 

    def test_drive_group_ResolveDriveGroupToId(self):
        self.assertEqual(api.drive_group_resolveDriveGroupToId(self.drive_groups[0]), self.drive_group_ids[0])

    #helper methods
    def create_drive_group(self, name):
        result = api.drive_group_create(name, **{"usercomment":"unittest_comment"}) 
        self.drive_groups.append(result["name"])
        self.drive_group_ids.append(result["id"])