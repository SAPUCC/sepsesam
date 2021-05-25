# -*- coding: utf-8 -*-
"""

--- SEP Sesam API ---

Example:

    import pprint
    import sepsesam.api

    cred = {
        "url": "http://sesam.my.doamin:11401",
        "username": "Administrator",
        "password": "Abcd1234!"
    }

    data = {}

    with sepsesam.api.V2(**cred) as api:
        data = api.location_list()

    pprint.pprint(data)
"""

# import python libraries
import logging
import pprint
import json.decoder

# import third-party libraries
import requests

# globals
ERROR_CODES = {
    400: {
        "error": "CLIENT_ERROR_BAD_REQUEST",
        "message": "Something is not correct in the request sent by the client"
    },
    401: {
        "error": "CLIENT_ERROR_UNAUTHORIZED",
        "messge": "The client is not authenticated to do the request"
    },
    403: {
        "error": "CLIENT_ERROR_FORBIDDEN",
        "message": "The authenticated user does not have the required permissions to do the request"
    },
    404: {
        "error": "CLIENT_ERROR_NOT_FOUND",
        "message": "The requested endpoint does not exist"
    },
    405: {
        "error": "CLIENT_ERROR_METHOD_NOT_ALLOWED",
        "message": "The target object is not editable (error type = ‘NOT_EDITABLE’)"
    },
    500: {
        "error": "SERVER_ERROR_INTERNAL",
        "message": "A general error occurred on the server while processing the request"
    },
    503: {
        "error": "SERVER_ERROR_SERVICE_UNAVAILABLE",
        "message": "The connection to the server is unavailable or got terminated"
    }
}


class SEPSesamAPIError(Exception):
    """ error from the API """
    
    def __init__(self, status_code, error, message, parameter, type, url):
        self.status_code = status_code
        self.error = error
        self.message = message
        self.parameter = parameter
        self.type = type
        self.url = url


class Api:
    """
    Implements version 2 of the SEP sesam API
    """

    def __init__(self, url, username, password, verify=True, log_level="INFO"):
        """
        Initialize API

        :param url: URL of the SEP sesam server including protocol and port, e.g https://sesam.my.domain:11401
        :param username: Username used for operations
        :param password: Password user for logon
        :param verify: Boolean if the SEP server certificate should be verified (default: True)
        :param log_level: Log level for the logger "sepsesam" as uppercase string (default: INFO)
        """
        self.url = url
        self.username = username
        self.password = password
        self.session_id = None
        self.verify = verify
        self.log = logging.getLogger("sepsesam")
        level = logging.getLevelName(log_level)
        self.log.setLevel(level)

    def __enter__(self):
        """
        For usage with the 'with' operator
        """
        self.login()
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        """
        For usage with the 'with' operator
        """
        self.logout()

    def _process_error(self, response):
        """
        Process errors and raise exception
        """
        if response.ok:
            return True
        # get data
        try:
            data = response.json()
            data["status_code"] = response.status_code
        except json.decoder.JSONDecodeError:
            self.log.debug("Could not retrieve error description")
            sc = response.status_code
            data = {
                "status_code": sc,
                "error": ERROR_CODES.get(sc, {}).get("error", "UNKNOWN ERROR"),
                "message": ERROR_CODES.get(sc, {}).get("message", "UNKNOWN ERROR"),
                "parameter": getattr(response.request, "body", None),
                "type": "GENERAL ERROR",
                "url": response.request.url,
            }
        data["status_code"] = response.status_code
        self.log.error("An error occured:\n{}".format(pprint.pformat(data)))
        raise SEPSesamAPIError(**data)

    ##### Version 2 API #####

    ### v2 GENERAL FUNCTIONS ###

    def login(self):
        """
        Logon to the SEP sesam v2 API
        """
        self.log.debug("Running function")
        endpoint = "sep/api/v2/auth/login"
        data = {
            "username": self.username,
            "secret": self.password,
            "type": "CLASSIC"
        }
        url = "{}{}".format(
            self.url if self.url[-1] == "/" else self.url + "/",
            endpoint if endpoint[0] != "/" else endpoint[1:]
        )
        response = requests.post(url=url, json=data, verify=self.verify)
        self._process_error(response)
        resp_data = response.json()
        self.session_id = resp_data
        self.log.debug("Got response:\n{}".format(pprint.pformat(resp_data)))
        return True

    def logout(self):
        """
        Logout and cleanup session
        """
        self.log.debug("Running function")
        endpoint = "sep/api/v2/auth/logout"
        if self.session_id:
            url = "{}{}".format(
                self.url if self.url[-1] == "/" else self.url + "/",
                endpoint if endpoint[0] != "/" else endpoint[1:]
            )
            headers = {"X-SEP-Session": self.session_id}
            requests.get(url=url, headers=headers, verify=self.verify)

    def get_server_info(self):
        """
        Retrieve server information
        """
        self.log.debug("Running function")
        endpoint = "sep/api/v2/server/info"
        if not self.session_id:
            self.login()
        url = "{}{}".format(
            self.url if self.url[-1] == "/" else self.url + "/",
            endpoint if endpoint[0] != "/" else endpoint[1:]
        )
        headers = {"X-SEP-Session": self.session_id}
        response = requests.get(url=url, headers=headers, verify=self.verify)
        self._process_error(response)
        data = response.json()
        self.log.debug("Got response:\n{}".format(pprint.pformat(data)))
        return data 

    ### v2 CREDENTIAL HANDLING ###

    # /sep/api/v2/credentials

    # /sep/api/v2/credentials/<id>

    # /sep/api/v2/credentials/find

    # /sep/api/v2/credentials/create

    # /sep/api/v2/credentials/update

    # /sep/api/v2/credentials/delete


    ### v2 CLIENT HANDLING ###

    def client_list(self):
        """
        Return a list of clients
        """
        self.log.debug("Running function")
        endpoint = "/sep/api/v2/clients"
        if not self.session_id:
            self.login()
        url = "{}{}".format(
            self.url if self.url[-1] == "/" else self.url + "/",
            endpoint if endpoint[0] != "/" else endpoint[1:]
        )
        headers = {"X-SEP-Session": self.session_id}
        response = requests.get(url=url, headers=headers, verify=self.verify)
        self._process_error(response)
        data = response.json()
        self.log.debug("Got response:\n{}".format(pprint.pformat(data)))
        return data

    def client_get(self, id):
        """
        Return a client for a given ID
        """
        self.log.debug("Running function")
        endpoint = "/sep/api/v2/clients/{}".format(id)
        if not self.session_id:
            self.login()
        url = "{}{}".format(
            self.url if self.url[-1] == "/" else self.url + "/",
            endpoint if endpoint[0] != "/" else endpoint[1:]
        )
        headers = {"X-SEP-Session": self.session_id}
        response = requests.get(url=url, headers=headers, verify=self.verify)
        self._process_error(response)
        data = response.json()
        self.log.debug("Got response:\n{}".format(pprint.pformat(data)))
        return data        

    
    def client_find(self, queryMode="DEFAULT", **kwargs):
        """
        Find a client by properties. Returns a list of clients.

        :param name:               The name of the client. (string)
        :param location:           The ID of the parent location. (integer)
        :param accessMode:         A list of access modes to match. See the client properties description for valid values. ([string])
        :param accessState:        A list of access states to match. See the client properties description for valid values. ([int])
        :param permit:             The enabled state. Either true or false.
        :param operSystem:         A list of operating system names to match. [dict]
        :param vmServerType:       The virtualization server type. See the client properties description for valid values. (string)
        :param vmName:             The name of the virtual machine the client is representing. (string)
        :param matchWithSavesetID: A save set ID. When specified, the filter returns a list of clients compatible with the backup’s type. (string)
        :param queryMode:          The query mode. Valid values are DEFAULT or RESTORE. When omitted, the query mode defaults to DEFAULT. (string)
        """
        self.log.debug("Running function")
        endpoint = "/sep/api/v2/clients/find"
        if not self.session_id:
            self.login()
        url = "{}{}".format(
            self.url if self.url[-1] == "/" else self.url + "/",
            endpoint if endpoint[0] != "/" else endpoint[1:]
        )
        headers = {"X-SEP-Session": self.session_id}
        data = {
            "queryMode": queryMode
        }
        for param in ["id", "name", "location", "accessMode", "accessState", "permit", "operSystem", "vmServerType", "vmName", "matchWithSavesetID", "queryMode"]:
            if param in kwargs:
                data[param] = kwargs[param]
        response = requests.post(url=url, json=data, headers=headers, verify=self.verify)
        self._process_error(response)
        data = response.json()
        self.log.debug("Got response:\n{}".format(pprint.pformat(data)))
        return data

    def client_create(self, name, **kwargs):
        """
        Create a client with the given parameters.

        Check the SEP Sesam REST API documentation for applicable parameters:
        https://wiki.sep.de/wiki/index.php/4_4_3_Beefalo:Using_SEP_sesam_REST_API
        """
        self.log.debug("Running function")
        endpoint = "/sep/api/v2/clients/create"
        if not self.session_id:
            self.login()
        url = "{}{}".format(
            self.url if self.url[-1] == "/" else self.url + "/",
            endpoint if endpoint[0] != "/" else endpoint[1:]
        )
        headers = {"X-SEP-Session": self.session_id}
        kwargs["name"] = name
        response = requests.post(url=url, json=kwargs, headers=headers, verify=self.verify)
        self._process_error(response)
        data = response.json()
        self.log.debug("Got response:\n{}".format(pprint.pformat(data)))
        return data

    def client_update(self, id=None, name=None, **kwargs):
        """
        Update a client with the given parameters. Either "id" or "name" must be given.

        Check the SEP Sesam REST API documentation for applicable parameters:
        https://wiki.sep.de/wiki/index.php/4_4_3_Beefalo:Using_SEP_sesam_REST_API
        """
        self.log.debug("Running function")
        if id:
            kwargs["id"] = id
        elif name:
            kwargs["name"] = name
        else:
            raise Exception("Either 'id' or 'name' must be specified")
        endpoint = "/sep/api/v2/clients/update"
        if not self.session_id:
            self.login()
        url = "{}{}".format(
            self.url if self.url[-1] == "/" else self.url + "/",
            endpoint if endpoint[0] != "/" else endpoint[1:]
        )
        headers = {"X-SEP-Session": self.session_id}
        response = requests.post(url=url, json=kwargs, headers=headers, verify=self.verify)
        self._process_error(response)
        data = response.json()
        self.log.debug("Got response:\n{}".format(pprint.pformat(data)))
        return data

    def client_delete(self, id):
        """
        Delete a client
        """
        self.log.debug("Running function")
        endpoint = "/sep/api/v2/clients/delete"
        if not self.session_id:
            self.login()
        url = "{}{}".format(
            self.url if self.url[-1] == "/" else self.url + "/",
            endpoint if endpoint[0] != "/" else endpoint[1:]
        )
        headers = {"X-SEP-Session": self.session_id}
        # for delete, we need to provide the data as a string and not form / json encoded
        response = requests.post(url=url, data=str(id), headers=headers, verify=self.verify)
        self._process_error(response)
        data = response.json()
        self.log.debug("Got response:\n{}".format(pprint.pformat(data)))
        return data   
 
    # TODO: implement client tasks

    ### v2 LOCATION HANDLING ###

    def location_list(self):
        """
        List all locations
        """
        self.log.debug("Running function")
        endpoint = "/sep/api/v2/locations"
        if not self.session_id:
            self.login()
        url = "{}{}".format(
            self.url if self.url[-1] == "/" else self.url + "/",
            endpoint if endpoint[0] != "/" else endpoint[1:]
        )
        headers = {"X-SEP-Session": self.session_id}
        response = requests.get(url=url, headers=headers, verify=self.verify)
        self._process_error(response)
        data = response.json()
        self.log.debug("Got response:\n{}".format(pprint.pformat(data)))
        return data
 
    def location_get(self, id):
        """
        Retrieve a location
        """
        self.log.debug("Running function")
        endpoint = "/sep/api/v2/locations/{}".format(id)
        if not self.session_id:
            self.login()
        url = "{}{}".format(
            self.url if self.url[-1] == "/" else self.url + "/",
            endpoint if endpoint[0] != "/" else endpoint[1:]
        )
        headers = {"X-SEP-Session": self.session_id}
        data = {"id": id}
        response = requests.get(url=url, json=data, headers=headers, verify=self.verify)
        self._process_error(response)
        data = response.json()
        self.log.debug("Got response:\n{}".format(pprint.pformat(data)))
        return data

    def location_find(self, parent):
        """
        Find a location.

        :param parent: The ID of the parent location. (int)
        """
        self.log.debug("Running function")
        endpoint = "/sep/api/v2/locations/find/"
        if not self.session_id:
            self.login()
        url = "{}{}".format(
            self.url if self.url[-1] == "/" else self.url + "/",
            endpoint if endpoint[0] != "/" else endpoint[1:]
        )
        headers = {"X-SEP-Session": self.session_id}
        data = {"parent": parent}
        response = requests.post(url=url, json=data, headers=headers, verify=self.verify)
        self._process_error(response)
        data = response.json()
        self.log.debug("Got response:\n{}".format(pprint.pformat(data)))
        return data

    def location_create(self, name, **kwargs):
        """
        Create a location.

        Check the SEP Sesam REST API documentation for applicable parameters: 
        https://wiki.sep.de/wiki/index.php/4_4_3_Beefalo:Using_SEP_sesam_REST_API
        """
        self.log.debug("Running function")
        endpoint = "/sep/api/v2/locations/create"
        if not self.session_id:
            self.login()
        url = "{}{}".format(
            self.url if self.url[-1] == "/" else self.url + "/",
            endpoint if endpoint[0] != "/" else endpoint[1:]
        )
        headers = {"X-SEP-Session": self.session_id}
        kwargs["name"] = name
        #if "parentId" not in kwargs:
        #     kwargs["parentId"] = 
        #print("kwargs:{}".format(pprint.pformat(kwargs)))
        response = requests.post(url=url, json=kwargs, headers=headers, verify=self.verify)
        self._process_error(response)
        data = response.json()
        self.log.debug("Got response:\n{}".format(pprint.pformat(data)))        
        return data

    def location_update(self, id=None, name=None, **kwargs):
        """
        Update a location. Either id or name must be specified.

        Check the SEP Sesam REST API documentation for applicable parameters:
        https://wiki.sep.de/wiki/index.php/4_4_3_Beefalo:Using_SEP_sesam_REST_API
        """
        self.log.debug("Running function")
        if id:
            kwargs["id"] = id
        elif name:
            kwargs["name"] = name
        else:
            raise Exception("Either 'id' or 'name' must be specified")
        endpoint = "/sep/api/v2/locations/update"
        if not self.session_id:
            self.login()
        url = "{}{}".format(
            self.url if self.url[-1] == "/" else self.url + "/",
            endpoint if endpoint[0] != "/" else endpoint[1:]
        )
        headers = {"X-SEP-Session": self.session_id}
        response = requests.post(url=url, json=kwargs, headers=headers, verify=self.verify)
        self._process_error(response)
        data = response.json()
        self.log.debug("Got response:\n{}".format(pprint.pformat(data)))
        return data


    def location_delete(self, id):
        """
        Deletes a location
        """
        self.log.debug("Running function")
        endpoint = "/sep/api/v2/locations/delete"
        if not self.session_id:
            self.login()
        url = "{}{}".format(
            self.url if self.url[-1] == "/" else self.url + "/",
            endpoint if endpoint[0] != "/" else endpoint[1:]
        )
        headers = {"X-SEP-Session": self.session_id}
        # for delete, we need to provide the data as a string and not form / json encoded
        response = requests.post(url=url, data=str(id), headers=headers, verify=self.verify)
        self._process_error(response)
        data = response.json()
        self.log.debug("Got response:\n{}".format(pprint.pformat(data)))
        return data

  
    def location_resolve_to_id(self, name):
        """
        Resolve a given name or path to an id
        """
        self.log.debug("Running function")
        endpoint = "/sep/api/v2/locations/resolveLocationToId"
        if not self.session_id:
            self.login()
        url = "{}{}".format(
            self.url if self.url[-1] == "/" else self.url + "/",
            endpoint if endpoint[0] != "/" else endpoint[1:]
        )
        headers = {"X-SEP-Session": self.session_id}
        data = {"name": name}
        response = requests.post(url=url, json=data, headers=headers, verify=self.verify)
        self._process_error(response)
        data = response.json()
        self.log.debug("Got response:\n{}".format(pprint.pformat(data)))
        return data

    ### v2 ACL HANDLING ###

    def acl_list(self):
        """
        List ACLs
        """
        self.log.debug("Running function")
        endpoint = "/sep/api/v2/acls"
        if not self.session_id:
            self.login()
        url = "{}{}".format(
            self.url if self.url[-1] == "/" else self.url + "/",
            endpoint if endpoint[0] != "/" else endpoint[1:]
        )
        headers = {"X-SEP-Session": self.session_id}
        response = requests.get(url=url, headers=headers, verify=self.verify)
        self._process_error(response)
        data = response.json()
        self.log.debug("Got response:\n{}".format(pprint.pformat(data)))
        return data

    def acl_get(self, id):
        """
        Get an ACL
        """
        self.log.debug("Running function")
        endpoint = "/sep/api/v2/acls/{}".format(id)
        if not self.session_id:
            self.login()
        url = "{}{}".format(
            self.url if self.url[-1] == "/" else self.url + "/",
            endpoint if endpoint[0] != "/" else endpoint[1:]
        )
        headers = {"X-SEP-Session": self.session_id}
        response = requests.get(url=url, headers=headers, verify=self.verify)
        self._process_error(response)
        data = response.json()
        self.log.debug("Got response:\n{}".format(pprint.pformat(data)))
        return data

    def acl_find(self, **kwargs):
        """
        Find an ACL

        :param object: The object ID. (string)
        :param origin: The object origin (string)
        """
        self.log.debug("Running function")
        endpoint = "/sep/api/v2/acls/find"
        if not self.session_id:
            self.login()
        url = "{}{}".format(
            self.url if self.url[-1] == "/" else self.url + "/",
            endpoint if endpoint[0] != "/" else endpoint[1:]
        )
        headers = {"X-SEP-Session": self.session_id}
        data = {
            "queryMode": queryMode
        }
        for param in ["object", "origin"]:
            if param in kwargs:
                data[param] = kwargs[param]
        response = requests.post(url=url, json=data, headers=headers, verify=self.verify)
        self._process_error(response)
        data = response.json()
        self.log.debug("Got response:\n{}".format(pprint.pformat(data)))
        return data

    def acl_create(self, object, origin, value, id=None):
        """
        Create an ACL.

        :param object: The unique ID of the object the ACL is associated with. If the object ID is ‘-1’, 
                       then the ACL describes the default permissions set for objects from the origin set. (string)
        :param origin: The object origin. The origin is the name of the database table in capitalized form
                       and without any separator. In example, if the object is a data store (DB:data_stores),
                       then the origin is “Datastores”. (string)
        :param value:  The encoded access control list. The access control list is persisted as a list of JSON
                       objects, each object describing the granted or denied permissions for a user or
                       group. (string)
        :param id:     The unique ID of the ACL. If none is given, one will be created.
        """
        self.log.debug("Running function")
        endpoint = "/sep/api/v2/acls/create"
        data = {
            "object": object,
            "origin": origin,
            "value": value
        }
        if id:
            data["id"] = id
        if not self.session_id:
            self.login()
        url = "{}{}".format(
            self.url if self.url[-1] == "/" else self.url + "/",
            endpoint if endpoint[0] != "/" else endpoint[1:]
        )
        headers = {"X-SEP-Session": self.session_id}
        response = requests.post(url=url, json=data, headers=headers, verify=self.verify)
        self._process_error(response)
        data = response.json()
        self.log.debug("Got response:\n{}".format(pprint.pformat(data)))
        return data

    def acl_update(self, id, **kwargs):
        """
        Update an ACL

        Check the SEP Sesam REST API documentation for applicable parameters:
        https://wiki.sep.de/wiki/index.php/4_4_3_Beefalo:Using_SEP_sesam_REST_API
        """
        self.log.debug("Running function")
        kwargs["id"] = id
        endpoint = "/sep/api/v2/acls/update"
        if not self.session_id:
            self.login()
        url = "{}{}".format(
            self.url if self.url[-1] == "/" else self.url + "/",
            endpoint if endpoint[0] != "/" else endpoint[1:]
        )
        headers = {"X-SEP-Session": self.session_id}
        response = requests.post(url=url, json=kwargs, headers=headers, verify=self.verify)
        self._process_error(response)
        data = response.json()
        self.log.debug("Got response:\n{}".format(pprint.pformat(data)))
        return data

    def acl_delete(self, id):
        """
        Delete an ACL
        """
        self.log.debug("Running function")
        endpoint = "/sep/api/v2/acls/delete"
        if not self.session_id:
            self.login()
        url = "{}{}".format(
            self.url if self.url[-1] == "/" else self.url + "/",
            endpoint if endpoint[0] != "/" else endpoint[1:]
        )
        headers = {"X-SEP-Session": self.session_id}
        # for delete, we need to provide the data as a string and not form / json encoded
        response = requests.post(url=url, data=str(id), headers=headers, verify=self.verify)
        self._process_error(response)
        data = response.json()
        self.log.debug("Got response:\n{}".format(pprint.pformat(data)))
        return data

    ### DATASTORE HANDLING ###

    # TODO: check if this should be implemented

    def datastore_list(self):
        endpoint = "/sep/api/v2/datastores"
        # GET
        pass

    def datastore_get(self, id):
        endpoint = "/sep/api/v2/datastores/{}".format(id)
        # GET
        pass

    def datastore_find(self):
        endpoint = "/sep/api/v2/datastores/find"
        # POST
        pass

    def datastore_create(self):
        endpoint = "/sep/api/v2/datastores/create"
        # POST
        pass

    def datastore_update(self):
        endpoint = "/sep/api/v2/datastores/update"
        # POST
        pass

    def datastore_delete(self):
        endpoint = "/sep/api/v2/datastores/delete"
        # POST
        pass

    def datastore_drives_list(self):
        endpoint = "/sep/api/v2/datastores/<name>/drives"
        # GET
        pass

    def datastore_drives_find(self):
        endpoint = "/sep/api/v2/datastores/<name>/drives"
        # POST
        pass

    def datastore_drivegroups_list(self):
        endpoint = "/sep/api/v2/datastores/<name>/driveGroups"
        # GET
        pass

    def datastore_drivegroups_find(self):
        endpoint = "/sep/api/v2/datastores/<name>/driveGroups"
        # POST
        pass

    def datastore_mediapools_list(self):
        endpoint = "/sep/api/v2/datastores/<name>/mediaPools"
        # GET
        pass

    def datastore_mediapools_find(self):
        endpoint = "/sep/api/v2/datastores/<name>/mediaPools"
        # POST
        pass


    ##### Version 1 API #####

    # TODO: /sep/api/groups
    """
    {
        id: 1,
        name: "ADMIN",
        enabled: true,
        usercomment: "Automatically generated administration group with all permissions",
        mtime: 1621955342000
    }
    """
    def group_list(self):
        """
        List all groups
        """
        self.log.debug("Running function")
        endpoint = "/sep/api/groups"
        url = "{}{}".format(
            self.url if self.url[-1] == "/" else self.url + "/",
            endpoint if endpoint[0] != "/" else endpoint[1:]
        )
        response = requests.get(url=url, auth=(self.username, self.password), verify=self.verify)
        self._process_error(response)
        data = response.json()
        self.log.debug("Got response:\n{}".format(pprint.pformat(data)))
        return data

    def group_create(self, **kwargs):
        """
        Create a new group
        """
        self.log.debug("Running function")
        endpoint = "/sep/api/groups"
        url = "{}{}".format(
            self.url if self.url[-1] == "/" else self.url + "/",
            endpoint if endpoint[0] != "/" else endpoint[1:]
        )
        response = requests.post(url=url, auth=(self.username, self.password), json=kwargs, verify=self.verify)
        self._process_error(response)
        data = response.json()
        self.log.debug("Got response:\n{}".format(pprint.pformat(data)))
        return data

    # TODO: /sep/api/roleRelations

    def role_relation_create(self, group_id, role_id):
        """
        Create a new role <> group relation
        """
        self.log.debug("Running function")
        endpoint = "/sep/api/roleRelations"
        url = "{}{}".format(
            self.url if self.url[-1] == "/" else self.url + "/",
            endpoint if endpoint[0] != "/" else endpoint[1:]
        )
        data = {
            "groupId": group_id,
            "roleId": role_id,
        }
        response = requests.post(url=url, auth=(self.username, self.password), json=data, verify=self.verify)
        self._process_error(response)
        data = response.json()
        self.log.debug("Got response:\n{}".format(pprint.pformat(data)))
        return data

     # TODO: /sep/api/externalGroups

    def external_group_create(self, **kwargs):
        """
        Create an external group 
        """
        self.log.debug("Running function")
        endpoint = "/sep/api/externalGroups"
        url = "{}{}".format(
            self.url if self.url[-1] == "/" else self.url + "/",
            endpoint if endpoint[0] != "/" else endpoint[1:]
        )
        response = requests.post(url=url, auth=(self.username, self.password), json=kwargs, verify=self.verify)
        self._process_error(response)
        data = response.json()
        self.log.debug("Got response:\n{}".format(pprint.pformat(data)))
        return data

    # TODO: /sep/api/externalGroupRelations

    def ext_group_relation_create(self, internal_group_id, external_group_id):
        """
        Create a new internal <> external group relation
        """
        self.log.debug("Running function")
        endpoint = "/sep/api/externalGroupRelations"
        url = "{}{}".format(
            self.url if self.url[-1] == "/" else self.url + "/",
            endpoint if endpoint[0] != "/" else endpoint[1:]
        )
        data = {
            "groupId": internal_group_id,
            "externalGroupId": external_group_id,
        }
        response = requests.post(url=url, auth=(self.username, self.password), json=data, verify=self.verify)
        self._process_error(response)
        data = response.json()
        self.log.debug("Got response:\n{}".format(pprint.pformat(data)))
        return data
