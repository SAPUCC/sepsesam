import unittest

# testing backup events
from .test_backup_events import TestBackupEvents

# testing backup tasks
from .test_backup_tasks import TestBackupTasks

# testing clients
from .test_clients import TestClients

# testing command events
from .test_command_events import TestCommandEvents

# testing commands
from .test_commands import TestCommands

# testing drive groups
from .test_drive_groups import TestDriveGroups

# testing external groups
from .test_external_groups import TestExternalGroups

# testing groups
from .test_groups import TestGroups

# testing locations
from .test_locations import TestLocations

# testing media pools
from .test_media_pools import TestMediaPools

# testing media
from .test_media import TestMedia

# testing schedules
from .test_schedule import TestSchedules

if __name__ == "__main__":
    unittest.main()
