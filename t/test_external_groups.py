import unittest
from t.config import api

# testing external groups


class TestExternalGroups(unittest.TestCase):
    group_ids = []
    group_names = []

    def setUp(self):
        self.group_ids = []
        self.group_names = []
        self.create_external_group("unittest_external_group")

    def tearDown(self):
        for id in self.group_ids:
            api.external_group_delete(id)

    def test_external_group_create(self):
        self.assertEqual(self.group_names[0], "unittest_external_group")

    def test_external_group_list(self):
        original_length = len(api.external_group_list())
        self.create_external_group("second_unittest_external_group")
        self.create_external_group("third_unittest_external_group")
        self.assertTrue(len(api.external_group_list()) > original_length)
        self.assertTrue(
            any(
                cmd["externalId"] == "unittest_external_group"
                and cmd["id"] == self.group_ids[0]
                for cmd in api.external_group_list()
            )
        )

    def test_external_group_delete(self):
        api.external_group_delete(self.group_ids[0])
        self.group_ids.pop(0)
        self.assertEqual(api.external_group_list(), [])

    def test_external_group_get(self):
        self.assertEqual(
            api.external_group_get(id=self.group_ids[0])[
                "externalId"], "unittest_external_group"
        )

    def test_external_group_find(self):
        self.assertEqual(
            api.external_group_find(
                **{"externalId": "unittest_external_group", "id": self.group_ids[0]}
            )[0]["externalId"],
            "unittest_external_group",
        )

    def test_external_group_update(self):
        self.assertEqual(
            api.external_group_update(
                externalId="unittest_external_group", enabled=False
            )["enabled"],
            False,
        )
        self.assertEqual(
            api.external_group_update(
                externalId="renamed_unittest_external_group", id=self.group_ids[0]
            )["externalId"],
            "renamed_unittest_external_group",
        )

    def test_external_group_relation_update(self):
        groups = ["OPERATOR", "BACKUP"]
        relating_groups = api.external_group_update_relations(
            externalId="unittest_external_group", groups=groups
        )
        self.assertEqual(
            [group["name"] for group in relating_groups], ["OPERATOR", "BACKUP"]
        )

    def test_external_group_realtions_get(self):
        relating_groups = api.external_group_get_relations(
            externalId="unittest_external_group"
        )
        self.assertEqual(
            [group["name"] for group in relating_groups], []
        )
        groups = ["OPERATOR", "BACKUP"]
        relating_groups = api.external_group_update_relations(
            externalId="unittest_external_group", groups=groups
        )
        self.assertEqual(
            [group["name"] for group in relating_groups], ["OPERATOR", "BACKUP"]
        )
        relating_groups = api.external_group_get_relations(
            id=self.group_ids[0]
        )
        self.assertEqual(
            [group["name"] for group in relating_groups], ["OPERATOR", "BACKUP"]
        )

    ### HELPER METHODS ###
    def create_external_group(self, externalId: str):
        result = api.external_group_create(externalId=externalId, enabled=True)
        self.group_ids.append(result["id"])
        self.group_names.append(result["externalId"])
