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


    """Managing Backup Tasks"""

    

    #backup_task_create
    def test_backupTaskCreate(self):

        #backup_task_create
        api.backup_task_create("Unittest_BackupTask", **{"client": {"name": "localhost"}, "source": "C:/tmp"})
       

        #Backup-task-get
        self.assertEqual(api.backup_task_get("Unittest_BackupTask")["name"], "Unittest_BackupTask")
        self.assertEqual(api.backup_task_get("Unittest_BackupTask")["client"]["id"], 0)
        

        #backup_task_delete
        api.backup_task_delete("Unittest_BackupTask")
        with self.assertRaises(sepsesam.api.SEPSesamAPIError) as context:
           
            api.backup_task_get("Unittest_BackupTask")
            self.assertEqual(api.backup_task_get("Unittest_BackupTask")["error"], "object.not.found.id")
        
         

    """Managing Clients"""

    def test_Clients(self):
        
        #client create
        self.assertEqual(api.client_create("unittest_Client")["id"], 1)


        #client_find
        self.assertGreater(len(api.client_find(name="*")), 1)
        self.assertEqual(api.client_find(**{"name": "unittest_Client"})[0]["name"], "unittest_Client")


        #client update
        self.assertRaises(Exception, api.client_update, None, None)
        self.assertEqual(api.client_update(0, "localhost",**{"usercomment": "test"})["usercomment"], "test")


        #client delete
        self.assertEqual(api.client_delete("1"), 1)
        self.assertLess(len(api.client_find(name="*")), 2)
    




    
    """Manage external groups"""

    def test_externalGroups(self):
        #external_group_create
        self.assertEqual(api.external_group_create("Unittest_ExternalGroup",True)["externalId"], "Unittest_ExternalGroup")


        #external_group_find
        self.assertEqual(api.external_group_find(**{"externalId": "Unittest_ExternalGroup", "id": 1})[0]["externalId"], "Unittest_ExternalGroup")


        #external_group_delete
        api.external_group_delete(1)
        

    
    """Manage Groups"""
    
    def test_GroupCreateAndDelete(self):

        #group_create
        self.assertEqual(api.group_create(5,**{"name": "UnittestGroup","enabled": True, "rolesList": ['ReadOnly']})["id"],5)


        #group_delete
        self.assertEqual(api.group_delete(5),5)
               


    """Manage locations"""

    #location_create and location_delete
    def test_LocationsCreateAndDelete(self):
        
        #location create
        self.assertEqual(api.location_create("UNITTEST_LOCATION")["id"], 1)


        #location_resolve_to_id
        self.assertEqual(api.location_resolve_to_id("UNITTEST_LOCATION"), 1)
    

        #id has to be unique    
        with self.assertRaises(sepsesam.api.SEPSesamAPIError) as context:
            self.assertEqual(api.location_create("UNITTEST_LOCATION2", **{"id": 1})["error"], "duplicate.entry" )


        #location delete
        api.location_delete(1)
        self.assertEqual(api.location_get(1),None)




if __name__ == "__main__":
    unittest.main()

