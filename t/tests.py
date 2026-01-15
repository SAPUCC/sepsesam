import unittest

#testing backup tasks
from t.test_backup_tasks import TestBackupTasks

#testing clients
from t.test_clients import TestClients

#testing external groups
from t.test_external_groups import TestExternalGroups

#testing groups
from t.test_groups import TestGroups

#testing locations
from t.test_locations import TestLocations

#testing commands
from t.test_commands import TestCommands

#testing command events
from t.test_command_events import TestCommandEvents

#testing schedules
from t.test_schedule import TestSchedules

#testing backup events
from t.test_backup_events import TestBackupEvents

#testing drive groups
from t.test_drive_groups import TestDriveGroups

#testing media pools
from t.test_media_pools import TestMediaPools

#testing media
from t.test_media import TestMedia

if __name__ == "__main__":
    unittest.main()