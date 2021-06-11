#!/usr/bin/env
import json
import pprint
import sepsesam.api

cred = {
    "url": "http://my.sesam.de:11401",
    "username": "Administrator",
    "password": "Abcd1234!"
}

with sepsesam.api.Api(**cred) as api:
    # create default space
    api.location_create(name="GERMANY")

    # create schedule
    api.schedule_create(
        name="WEEKLY_00_SUNDAY",
        cycFlag=True,
        absFlag=True,
        pCount=1,
        pSubCount=0,
        pBase="WEEKLY",
        mo=False,
        tu=False,
        we=False,
        th=False,
        fr=False,
        sa=False,
        su=True,
        startDate=1585004400000,
        startTime=61200000,
        exec=True,
        lifeTime=600,
    )

    # create datastore
    api.datastore_create(
        name="FULL",
        typeId="Path",
    )

    # corresponding drive groups "ds-<datastore name>" are created automatically

    # create further topology
    loc_id_root = api.location_resolve_to_id(name="GERMANY")
    data = api.location_create(name="MUC", parentId=loc_id_root)
    loc_id_muc = data["id"]

    # create internal / external groups and mapping
    group = {
        "name": "MUC_ADM",
        "enabled": True,
        "usercomment": "Munich admin group"
    }
    data = api.group_create(**group)
    internal_group_id = data["id"]
    data = api.role_relation_create(group_id=internal_group_id, role_id=2) # 2=All
    ext_group = {
        "externalId": "de_muc_admins",
        "enabled": True
    }
    data = api.external_group_create(**ext_group)
    external_group_id = data["id"]
    api.ext_group_relation_create(internal_group_id=internal_group_id, external_group_id=external_group_id)

    # create ACLs
    permission = [
        {
            "id": internal_group_id,
            "type": "GROUP",
            "permissions": {
                "allow": "f---"  # ALL
            }
        },
    ]
    api.acl_create(object=loc_id_muc, origin="LocationsDao", value=json.dumps(permission))

    # get drive groups IDs")
    data = api.drive_group_find(name="ds-FULL")
    full_dg_id = data[0]["id"]

    # create media pools
    api.media_pool_create(
        name="MUC_FULL_28",
        eol=28,
        driveGroupId=full_dg_id
    )

    # create client
    loc_id_root = api.location_resolve_to_id(name="GERMANY/MUC")
    data = api.client_create(name="db2.prod.muc", location={"id": loc_id_root}, accessmode="SMSSH")
    client_id = data["id"]

    # create ACLs
    permission = [
        {
            "id": internal_group_id,
            "type": "GROUP",
            "permissions": {
                "allow": "f---"  # ALL
            }
        }
    ]
    api.acl_create(object=client_id, origin="ClientsDao", value=json.dumps(permission))

    # at this point, "sesam_cli" must be installed on the client machine

    # at this point, the server must be set on the client over /opt/sesam/bin/sesam/sm_setup set_client <sesam server>

    # add task definitions
    api.task_create(
        name="DE_MUC_db2_FULL",
        client=client_id,
        comment="auto generated",
        type={
            "name": "DB2_UDB"
        },
        source="DB2"
    )
    api.task_create(
        name="DE_MUC_db2_ARCHIVE",
        client=client_id,
        comment="auto generated",
        type={
            "name": "DB2_UDB"
        },
        source="DB2"
    )

    # add task event and schedule
    data = api.media_pool_find(name="MUC_FULL_28")
    media_pool_id = data[0]["id"]
    api.task_event_create(
        mediaPool=media_pool_id,
        task="DE_MUC_db2_ARCHIVE",
        scheduleName="DE_MUC_db2_ARCHIVE",
        fdiType="F"
    )


