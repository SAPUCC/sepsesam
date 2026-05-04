import unittest
from t.config import api
import logging

# testing media pools


class TestMediaPools(unittest.TestCase):
    logger = logging.getLogger("sepsesam")
    old_level = logger.level
    media_pools = []
    media_pool_ids = []
    drive_groups = []

    def setUp(self):
        self.media_pools = []
        self.drive_groups = []

        dg_id = self.createDriveGroup("unittest_mp_dg")
        self.createMediaPool("unittest_mp", dg_id)

    def tearDown(self):
        self.logger.setLevel(logging.CRITICAL)
        for pool in self.media_pools:
            try:
                api.media_pool_delete(pool)
            except Exception:
                pass
        for dg in self.drive_groups:
            try:
                api.drive_group_delete(int(dg))
            except Exception:
                pass
        self.logger.setLevel(self.old_level)

    def test_media_pool_create(self):
        self.assertEqual(self.media_pools[0], "unittest_mp")

    def test_media_pool_delete(self):
        self.assertEqual(api.media_pool_delete(
            self.media_pools[0]), self.media_pools[0])
        self.media_pools.pop(0)

    def test_media_pool_find(self):
        self.assertEqual(len(api.media_pool_find(
            **{"driveGroups": [str(self.drive_groups[0])]})), 1)
        self.createMediaPool("unittest_mp_2", self.drive_groups[0])
        self.assertEqual(len(api.media_pool_find(
            **{"driveGroups": [str(self.drive_groups[0])]})), 2)
        self.assertTrue(
            any(
                mp["name"] == "unittest_mp_2"
                and mp["driveGroupId"] == self.drive_groups[0]
                and mp["descript"] == "unittest_media_pool_description"
                for mp in api.media_pool_find(**{"driveGroups": [str(self.drive_groups[0])]})
            )
        )

    def test_media_pool_get(self):
        self.assertEqual(
            api.media_pool_get(self.media_pools[0])[
                "descript"], "unittest_media_pool_description"
        )

    def test_media_pool_list(self):
        original_length = len(api.media_pool_list())
        self.createMediaPool("unittest_mp_2", self.drive_groups[0])
        self.createMediaPool("unittest_mp_3", self.drive_groups[0])
        self.assertTrue(len(api.media_pool_list()) > original_length)
        self.assertTrue(
            any(
                mp["name"] == "unittest_mp_2"
                and mp["driveGroupId"] == self.drive_groups[0]
                and mp["descript"] == "unittest_media_pool_description"
                for mp in api.media_pool_list()
            )
        )

    def test_media_pool_update(self):
        new_dg = self.createDriveGroup("unittest_mp_dg_2")
        self.assertEqual(
            api.media_pool_update(self.media_pool_ids[0], self.media_pools[0], self.drive_groups[0], **{
                                  "descript": "new_unittest_description"})["descript"],
            "new_unittest_description"
        )
        self.assertEqual(
            api.media_pool_update(self.media_pool_ids[0], self.media_pools[0], new_dg)[
                "driveGroupId"],
            new_dg
        )

    ### HELPER METHODS ###
    def createMediaPool(self, name, id):
        result = api.media_pool_create(
            name, **{"driveGroupId": id, "descript": "unittest_media_pool_description"})
        self.media_pools.append(result["name"])
        self.media_pool_ids.append(result["id"])

    def createDriveGroup(self, name):
        dg_id = api.drive_group_create(name)["id"]
        self.drive_groups.append(int(dg_id))
        return dg_id
