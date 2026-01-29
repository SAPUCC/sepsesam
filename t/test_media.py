import unittest
import logging
import time
from t.config import api

# testing media


class TestMedia(unittest.TestCase):
    logger = logging.getLogger("sepsesam")
    old_level = logger.level
    media_pools = []
    drive_groups = []
    media = []
    media_ids = []

    def setUp(self):
        self.media_pools = []
        self.drive_groups = []
        self.media = []
        self.media_ids = []

        dg_id = self.create_drive_group("unittest_mp_dg")
        self.create_media_pool("unittest_mp", dg_id)
        self.create_media("unittest_media", "unittest_mp")

    def tearDown(self):
        self.logger.setLevel(logging.DEBUG)
        for media in self.media:
            try:
                api.media_delete(media)
            except Exception:
                pass
        time.sleep(2)
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

    def test_media_create(self):
        self.assertEqual(self.media[0], "unittest_media")

    def test_media_delete(self):
        self.assertEqual(api.media_delete(self.media[0]), self.media[0])
        self.media.pop(0)

    def test_media_find(self):
        self.assertEqual(
            len(api.media_find(**{"pool": [str(self.media_pools[0])]})), 1)
        self.create_media("unittest_media_2", self.media_pools[0])
        self.assertEqual(
            len(api.media_find(**{"pool": [str(self.media_pools[0])]})), 2)
        self.assertTrue(
            any(
                m["name"] == "unittest_media_2"
                and m["poolName"] == self.media_pools[0]
                and m["sesamDate"] == 1503698400000
                for m in api.media_find(**{"pool": [str(self.media_pools[0])]})
            )
        )

    def test_media_get(self):
        self.assertEqual(
            api.media_get(self.media[0])["label"], "Unittest_Label"
        )

    def test_media_list(self):
        original_length = len(api.media_list())
        self.create_media("unittest_media_2", self.media_pools[0])
        self.assertTrue(len(api.media_list()) > original_length)
        self.assertTrue(
            any(
                m["name"] == "unittest_media_2"
                and m["poolName"] == self.media_pools[0]
                and m["sesamDate"] == 1503698400000
                for m in api.media_list()
            )
        )

    def test_media_update(self):
        self.assertEqual(
            api.media_update(self.media_ids[0], "UNLOCKED", "LTO_Tape", self.media[0],
                             self.media_pools[0], 1503698400000, **{"label": "New_Label"})["label"],
            "New_Label"
        )
        self.create_media_pool("unittest_mp_2", self.drive_groups[0])
        self.assertEqual(
            api.media_update(self.media_ids[0], "UNLOCKED", "LTO_Tape",
                             self.media[0], self.media_pools[1], 1503698400000, )["poolName"],
            "unittest_mp_2"
        )

    ### HELPER METHODS ###
    def create_media_pool(self, name, id):
        result = api.media_pool_create(
            name, **{"driveGroupId": id, "descript": "unittest_media_pool_description"})
        self.media_pools.append(result["name"])

    def create_drive_group(self, name):
        dg_id = api.drive_group_create(name)["id"]
        self.drive_groups.append(int(dg_id))
        return int(dg_id)

    def create_media(self, name, pool_name):
        media = api.media_create(
            name,
            pool_name,
            "LTO_Tape",
            **{"locked": "UNLOCKED", "idNum": 999, "id": 999, "sesamDate": 1503698400000, "loaderNum": 1, "slot": 999, "label": "Unittest_Label"}
        )
        self.media.append(media["name"])
        self.media_ids.append(media["id"])
