import unittest
from t.config import api

#testing groups
class TestGroups(unittest.TestCase):
    def setUp(self):
        if(self._testMethodName != 'test_group_create'):
            api.group_create(5, **{"name": "unittest_group", "enabled": True, "rolesList": ["ReadOnly"]})
    
    def tearDown(self):
        api.group_delete(5)
        
    def test_group_create(self):
        self.assertEqual(
            api.group_create(
                5,
                **{"name": "unittest_group", "enabled": True, "rolesList": ["ReadOnly"]},
            )["id"],
            5,
        )

    def test_group_list(self):
        self.assertEqual(
            api.group_list()[5]["name"],
            "unittest_group"
        )

    def test_group_find(self):
        self.assertEqual(
            api.group_find(name="unittest_group")[0]["name"],
            "unittest_group"
        )

    def test_group_get(self):
        self.assertEqual(
            api.group_get(5)["name"],
            "unittest_group"
        )

    def test_group_update(self):
        self.assertEqual(
            api.group_update(id="5", name="renamed_unittest_group")["name"],
            "renamed_unittest_group"
        )

    def test_group_roles(self):
        self.assertEqual(
            api.group_get_roles(id="5")[0]["name"],
            "ReadOnly"
        )

    def test_group_delete(self):
        self.assertEqual(api.group_delete(5), 5)