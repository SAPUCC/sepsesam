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
    """ sepsesam.api unittests """

    #Backup-task-get
    def test_backupTaskGet(self):
        self.assertEqual(api.backup_task_get("SESAM_BACKUP")["name"], "SESAM_BACKUP")
        self.assertEqual(api.backup_task_get("SESAM_BACKUP")["client"]["id"], 0)

    #backup_task_create
    # def test_backupTaskCreate(self):
    #     api.backup_task_create("UnittestBackup", **{"task.client": "localhost"})
    #     self.assertEqual(api.backup_task_get("UnittestBackup")["name"], "UnittestBackup")
    
    #backup_task_delete
    # def test_backupTaskDelete(self):
    #     self.assertEqual()

    # Managing Clients


    #client_find
    def test_ClientFind(self):
        self.assertGreater(len(api.client_find(name="*")), 0)

    #client_create
    def test_ClientCreate(self):
        self.assertEqual(api.client_create("unittest")["id"], 1)

    #client_update - fügt dem client "usercomment": "test" hinzu
    def test_ClientUpdate(self):
        self.assertRaises(Exception, api.client_update, None, None)
        self.assertEqual(api.client_update(0, "localhost",**{"usercomment": "test"})["usercomment"], "test")
        # ToDo

    #client_delete
    def test_ClientDelete(self):
        self.assertEqual(api.client_delete("1"), 1)

    
    """TO DO"""
    #Manage external groups

        #external_group_find

        #external_group_create

        #external_group_delete

    
    #Manage groups

    #group_create
    def test_GroupCreate(self):
        self.assertEqual(api.group_create(5,**{"name": "UnittestGroup","enabled": True, "rolesList": ['ReadOnly']})["id"],5)

        #group_delete
        self.assertEqual(api.group_delete(5),5)
               


    #Manage locations

    #location_create and location_delete
    def test_LocationsCreate(self):
        
        #location create
        self.assertEqual(api.location_create("UNITTEST")["id"], 1)
        #location_delete
        self.assertEqual(api.location_delete(1), 1)

        """Not working yet"""
        #Client must not be found, if it has been deleted earlier
        #self.assertEqual(api.client_get(1)["id"], None)
        
        #Exception should be raised, when the id ist not unique (test is not yet working)
        #self.assertRaises(Exception, api.location_create("UNITTEST2", **{"id": 1}))

    
    #location_resolve_to_id
    def test_LocationResolvetoID(self):
        self.assertEqual(api.location_resolve_to_id("LOCAL"), 0)


if __name__ == "__main__":
    unittest.main()

