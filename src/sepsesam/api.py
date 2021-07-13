# -*- coding: utf-8 -*-
"""
SEP Sesam REST API Wrapper
"""

# import python libraries
import logging
import uuid
import pprint
import json.decoder
import collections.abc

# import third-party libraries
import requests

# globals
ERROR_CODES = {
    400: {
        "error": "CLIENT_ERROR_BAD_REQUEST",
        "message": "Something is not correct in the request sent by the client",
    },
    401: {"error": "CLIENT_ERROR_UNAUTHORIZED", "messge": "The client is not authenticated to do the request"},
    403: {
        "error": "CLIENT_ERROR_FORBIDDEN",
        "message": "The authenticated user does not have the required permissions to do the request",
    },
    404: {"error": "CLIENT_ERROR_NOT_FOUND", "message": "The requested endpoint does not exist"},
    405: {
        "error": "CLIENT_ERROR_METHOD_NOT_ALLOWED",
        "message": "The target object is not editable (error type = ‘NOT_EDITABLE’)",
    },
    500: {
        "error": "SERVER_ERROR_INTERNAL",
        "message": "A general error occurred on the server while processing the request",
    },
    503: {
        "error": "SERVER_ERROR_SERVICE_UNAVAILABLE",
        "message": "The connection to the server is unavailable or got terminated",
    },
}

# set logger
log = logging.getLogger("sepsesam")


def update(d, u):
    """
    Recursivly update a dictionary, taken from
    https://stackoverflow.com/questions/3232943/update-value-of-a-nested-dictionary-of-varying-depth
    """
    for k, v in u.items():
        if isinstance(v, collections.abc.Mapping):
            d[k] = update(d.get(k, {}), v)
        else:
            d[k] = v
    return d


class SEPSesamAPIError(Exception):
    """error from the API"""

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

    def __init__(self, url, username, password, verify=True):
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
            log.debug("Could not retrieve error description")
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
        log.error("An error occured:\n{}".format(pprint.pformat(data)))
        raise SEPSesamAPIError(**data)

    def _urlexpand(self, endpoint):
        """
        Return full URL to endpoint
        """
        return "{}{}".format(
            self.url if self.url[-1] == "/" else self.url + "/",
            endpoint if endpoint[0] != "/" else endpoint[1:],
        )

    def _filter(self, obj_list, kwargs):
        """
        Find an object based on attributes. Based on list due to missing support in API v1
        """
        log.debug("Running function")
        data = []
        for obj in obj_list:
            valid_entry = True
            for k, v in kwargs.items():
                if obj.get(k) != v:
                    valid_entry = False
                    break
            if valid_entry:
                data.append(obj)
        log.debug("Got response:\n{}".format(pprint.pformat(data)))
        return data


    #################### Version 2 API ####################

    ### v2 GENERAL FUNCTIONS ###

    def login(self):
        """
        Logon to the SEP sesam v2 API
        """
        log.debug("Running function")
        endpoint = "sep/api/v2/auth/login"
        data = {"username": self.username, "secret": self.password, "type": "CLASSIC"}
        url = self._urlexpand(endpoint)
        response = requests.post(url=url, json=data, verify=self.verify)
        self._process_error(response)
        resp_data = response.json()
        self.session_id = resp_data
        log.debug("Got response:\n{}".format(pprint.pformat(resp_data)))
        return True

    def logout(self):
        """
        Logout and cleanup session
        """
        log.debug("Running function")
        endpoint = "sep/api/v2/auth/logout"
        if self.session_id:
            url = self._urlexpand(endpoint)
            headers = {"X-SEP-Session": self.session_id}
            requests.get(url=url, headers=headers, verify=self.verify)

    def get_server_info(self):
        """
        Retrieve server information
        """
        log.debug("Running function")
        endpoint = "sep/api/v2/server/info"
        if not self.session_id:
            self.login()
        url = self._urlexpand(endpoint)
        headers = {"X-SEP-Session": self.session_id}
        response = requests.get(url=url, headers=headers, verify=self.verify)
        self._process_error(response)
        data = response.json()
        log.debug("Got response:\n{}".format(pprint.pformat(data)))
        return data

    ### v2 CLIENT HANDLING ###

    def client_list(self):
        """
        Return a list of clients
        """
        log.debug("Running function")
        endpoint = "/sep/api/v2/clients"
        if not self.session_id:
            self.login()
        url = self._urlexpand(endpoint)
        headers = {"X-SEP-Session": self.session_id}
        response = requests.get(url=url, headers=headers, verify=self.verify)
        self._process_error(response)
        data = response.json()
        log.debug("Got response:\n{}".format(pprint.pformat(data)))
        return data

    def client_get(self, id):
        """
        Return a client for a given ID
        """
        log.debug("Running function")
        endpoint = "/sep/api/v2/clients/{}".format(id)
        if not self.session_id:
            self.login()
        url = self._urlexpand(endpoint)
        headers = {"X-SEP-Session": self.session_id}
        response = requests.get(url=url, headers=headers, verify=self.verify)
        self._process_error(response)
        data = response.json()
        log.debug("Got response:\n{}".format(pprint.pformat(data)))
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
        log.debug("Running function")
        endpoint = "/sep/api/v2/clients/find"
        if not self.session_id:
            self.login()
        url = self._urlexpand(endpoint)
        headers = {"X-SEP-Session": self.session_id}
        data = {"queryMode": queryMode}
        for param in [
            "id",
            "name",
            "location",
            "accessMode",
            "accessState",
            "permit",
            "operSystem",
            "vmServerType",
            "vmName",
            "matchWithSavesetID",
            "queryMode",
        ]:
            if param in kwargs:
                data[param] = kwargs[param]
        response = requests.post(url=url, json=data, headers=headers, verify=self.verify)
        self._process_error(response)
        data = response.json()
        log.debug("Got response:\n{}".format(pprint.pformat(data)))
        return data

    def client_create(self, name, **kwargs):
        """
        Create a client with the given parameters.

        Check the SEP Sesam REST API documentation for applicable parameters:
        https://wiki.sep.de/wiki/index.php/4_4_3_Beefalo:Using_SEP_sesam_REST_API
        """
        log.debug("Running function")
        endpoint = "/sep/api/v2/clients/create"
        if not self.session_id:
            self.login()
        url = self._urlexpand(endpoint)
        headers = {"X-SEP-Session": self.session_id}
        kwargs["name"] = name
        response = requests.post(url=url, json=kwargs, headers=headers, verify=self.verify)
        self._process_error(response)
        data = response.json()
        log.debug("Got response:\n{}".format(pprint.pformat(data)))
        return data

    def client_update(self, id=None, name=None, **kwargs):
        """
        Update a client with the given parameters. Either "id" or "name" must be given.

        Check the SEP Sesam REST API documentation for applicable parameters:
        https://wiki.sep.de/wiki/index.php/4_4_3_Beefalo:Using_SEP_sesam_REST_API
        """
        log.debug("Running function")
        if id:
            kwargs["id"] = id
        elif name:
            kwargs["name"] = name
        else:
            raise Exception("Either 'id' or 'name' must be specified")
        endpoint = "/sep/api/v2/clients/update"
        if not self.session_id:
            self.login()
        url = self._urlexpand(endpoint)
        headers = {"X-SEP-Session": self.session_id}
        response = requests.post(url=url, json=kwargs, headers=headers, verify=self.verify)
        self._process_error(response)
        data = response.json()
        log.debug("Got response:\n{}".format(pprint.pformat(data)))
        return data

    def client_delete(self, id):
        """
        Delete a client
        """
        log.debug("Running function")
        endpoint = "/sep/api/v2/clients/delete"
        if not self.session_id:
            self.login()
        url = self._urlexpand(endpoint)
        headers = {"X-SEP-Session": self.session_id}
        # for delete, we need to provide the data as a string and not form / json encoded
        response = requests.post(url=url, data=str(id), headers=headers, verify=self.verify)
        self._process_error(response)
        data = response.json()
        log.debug("Got response:\n{}".format(pprint.pformat(data)))
        return data

    ### v2 LOCATION HANDLING ###

    def location_list(self):
        """
        List all locations
        """
        log.debug("Running function")
        endpoint = "/sep/api/v2/locations"
        if not self.session_id:
            self.login()
        url = self._urlexpand(endpoint)
        headers = {"X-SEP-Session": self.session_id}
        response = requests.get(url=url, headers=headers, verify=self.verify)
        self._process_error(response)
        data = response.json()
        log.debug("Got response:\n{}".format(pprint.pformat(data)))
        return data

    def location_get(self, id):
        """
        Retrieve a location
        """
        log.debug("Running function")
        endpoint = "/sep/api/v2/locations/{}".format(id)
        if not self.session_id:
            self.login()
        url = self._urlexpand(endpoint)
        headers = {"X-SEP-Session": self.session_id}
        data = {"id": id}
        response = requests.get(url=url, json=data, headers=headers, verify=self.verify)
        self._process_error(response)
        data = response.json()
        log.debug("Got response:\n{}".format(pprint.pformat(data)))
        return data

    def location_find(self, parent):
        """
        Find a location.

        :param parent: The ID of the parent location. (int)
        """
        log.debug("Running function")
        endpoint = "/sep/api/v2/locations/find/"
        if not self.session_id:
            self.login()
        url = self._urlexpand(endpoint)
        headers = {"X-SEP-Session": self.session_id}
        data = {"parent": parent}
        response = requests.post(url=url, json=data, headers=headers, verify=self.verify)
        self._process_error(response)
        data = response.json()
        log.debug("Got response:\n{}".format(pprint.pformat(data)))
        return data

    def location_create(self, name, **kwargs):
        """
        Create a location.

        Check the SEP Sesam REST API documentation for applicable parameters:
        https://wiki.sep.de/wiki/index.php/4_4_3_Beefalo:Using_SEP_sesam_REST_API
        """
        log.debug("Running function")
        endpoint = "/sep/api/v2/locations/create"
        if not self.session_id:
            self.login()
        url = self._urlexpand(endpoint)
        headers = {"X-SEP-Session": self.session_id}
        kwargs["name"] = name
        response = requests.post(url=url, json=kwargs, headers=headers, verify=self.verify)
        self._process_error(response)
        data = response.json()
        log.debug("Got response:\n{}".format(pprint.pformat(data)))
        return data

    def location_update(self, id=None, name=None, **kwargs):
        """
        Update a location. Either id or name must be specified.

        Check the SEP Sesam REST API documentation for applicable parameters:
        https://wiki.sep.de/wiki/index.php/4_4_3_Beefalo:Using_SEP_sesam_REST_API
        """
        log.debug("Running function")
        if id:
            kwargs["id"] = id
        elif name:
            kwargs["name"] = name
        else:
            raise Exception("Either 'id' or 'name' must be specified")
        endpoint = "/sep/api/v2/locations/update"
        if not self.session_id:
            self.login()
        url = self._urlexpand(endpoint)
        headers = {"X-SEP-Session": self.session_id}
        response = requests.post(url=url, json=kwargs, headers=headers, verify=self.verify)
        self._process_error(response)
        data = response.json()
        log.debug("Got response:\n{}".format(pprint.pformat(data)))
        return data

    def location_delete(self, id):
        """
        Deletes a location
        """
        log.debug("Running function")
        endpoint = "/sep/api/v2/locations/delete"
        if not self.session_id:
            self.login()
        url = self._urlexpand(endpoint)
        headers = {"X-SEP-Session": self.session_id}
        # for delete, we need to provide the data as a string and not form / json encoded
        response = requests.post(url=url, data=str(id), headers=headers, verify=self.verify)
        self._process_error(response)
        data = response.json()
        log.debug("Got response:\n{}".format(pprint.pformat(data)))
        return data

    def location_resolve_to_id(self, name):
        """
        Resolve a given name or path to an id
        """
        log.debug("Running function")
        endpoint = "/sep/api/v2/locations/resolveLocationToId"
        if not self.session_id:
            self.login()
        url = self._urlexpand(endpoint)
        headers = {"X-SEP-Session": self.session_id}
        # data is provided as is, but with a strange formatting
        response = requests.post(url=url, data='"{}"'.format(name), headers=headers, verify=self.verify)
        self._process_error(response)
        data = response.json()
        log.debug("Got response:\n{}".format(pprint.pformat(data)))
        return data

    ### v2 ACL HANDLING ###

    def acl_list(self):
        """
        List ACLs
        """
        log.debug("Running function")
        endpoint = "/sep/api/v2/acls"
        if not self.session_id:
            self.login()
        url = self._urlexpand(endpoint)
        headers = {"X-SEP-Session": self.session_id}
        response = requests.get(url=url, headers=headers, verify=self.verify)
        self._process_error(response)
        data = response.json()
        log.debug("Got response:\n{}".format(pprint.pformat(data)))
        return data

    def acl_get(self, id):
        """
        Get an ACL
        """
        log.debug("Running function")
        endpoint = "/sep/api/v2/acls/{}".format(id)
        if not self.session_id:
            self.login()
        url = self._urlexpand(endpoint)
        headers = {"X-SEP-Session": self.session_id}
        response = requests.get(url=url, headers=headers, verify=self.verify)
        self._process_error(response)
        data = response.json()
        log.debug("Got response:\n{}".format(pprint.pformat(data)))
        return data

    def acl_find(self, **kwargs):
        """
        Find an ACL

        :param object: The object ID. (string)
        :param origin: The object origin (string)
        """
        log.debug("Running function")
        endpoint = "/sep/api/v2/acls/find"
        if not self.session_id:
            self.login()
        url = self._urlexpand(endpoint)
        headers = {"X-SEP-Session": self.session_id}
        data = {}
        if "queryMode" in kwargs:
            data = {"queryMode": queryMode}
        for param in ["object", "origin"]:
            if param in kwargs:
                data[param] = kwargs[param]
        response = requests.post(url=url, json=data, headers=headers, verify=self.verify)
        self._process_error(response)
        data = response.json()
        log.debug("Got response:\n{}".format(pprint.pformat(data)))
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
        log.debug("Running function")
        endpoint = "/sep/api/v2/acls/create"
        data = {"object": object, "origin": origin, "value": value}
        if id:
            data["id"] = id
        if not self.session_id:
            self.login()
        url = self._urlexpand(endpoint)
        headers = {"X-SEP-Session": self.session_id}
        response = requests.post(url=url, json=data, headers=headers, verify=self.verify)
        self._process_error(response)
        data = response.json()
        log.debug("Got response:\n{}".format(pprint.pformat(data)))
        return data

    def acl_update(self, id, **kwargs):
        """
        Update an ACL

        Check the SEP Sesam REST API documentation for applicable parameters:
        https://wiki.sep.de/wiki/index.php/4_4_3_Beefalo:Using_SEP_sesam_REST_API
        """
        log.debug("Running function")
        kwargs["id"] = id
        endpoint = "/sep/api/v2/acls/update"
        if not self.session_id:
            self.login()
        url = self._urlexpand(endpoint)
        headers = {"X-SEP-Session": self.session_id}
        response = requests.post(url=url, json=kwargs, headers=headers, verify=self.verify)
        self._process_error(response)
        data = response.json()
        log.debug("Got response:\n{}".format(pprint.pformat(data)))
        return data

    def acl_delete(self, id):
        """
        Delete an ACL
        """
        log.debug("Running function")
        endpoint = "/sep/api/v2/acls/delete"
        if not self.session_id:
            self.login()
        url = self._urlexpand(endpoint)
        headers = {"X-SEP-Session": self.session_id}
        # for delete, we need to provide the data as a string and not form / json encoded
        response = requests.post(url=url, data=str(id), headers=headers, verify=self.verify)
        self._process_error(response)
        data = response.json()
        log.debug("Got response:\n{}".format(pprint.pformat(data)))
        return data

    ### v2 CREDENTIAL HANDLING ###

    def credential_list(self):
        """
        List credentials
        """
        log.debug("Running function")
        endpoint = "/sep/api/v2/credentials"
        if not self.session_id:
            self.login()
        url = self._urlexpand(endpoint)
        headers = {"X-SEP-Session": self.session_id}
        response = requests.get(url=url, headers=headers, verify=self.verify)
        self._process_error(response)
        data = response.json()
        log.debug("Got response:\n{}".format(pprint.pformat(data)))
        return data

    def credential_get(self, id):
        """
        Get a credential
        """
        log.debug("Running function")
        endpoint = "/sep/api/v2/credentials/{}".format(id)
        if not self.session_id:
            self.login()
        url = self._urlexpand(endpoint)
        headers = {"X-SEP-Session": self.session_id}
        response = requests.get(url=url, headers=headers, verify=self.verify)
        self._process_error(response)
        data = response.json()
        log.debug("Got response:\n{}".format(pprint.pformat(data)))
        return data

    def credential_find(self, type):
        """
        Find a credential

        :param type: The credential type. (string)
        """
        log.debug("Running function")
        endpoint = "/sep/api/v2/credentials/find"
        if not self.session_id:
            self.login()
        url = self._urlexpand(endpoint)
        headers = {"X-SEP-Session": self.session_id}
        data = {"type": type}
        response = requests.post(url=url, json=data, headers=headers, verify=self.verify)
        self._process_error(response)
        data = response.json()
        log.debug("Got response:\n{}".format(pprint.pformat(data)))
        return data

    def credential_create(self, type, **kwargs):
        """
        Create an ACL.

        :param name:         The name of the credential set. When not specified, an auto name has to be
                             generated in the format ‘auth.<type>.<uuid>’. (string)
        :param type:         The credentials type. The following values are currently defined: ‘LDAP’, ‘AD’, ‘HPE
                             Storeonce’ and ‘AWS S3’. (string)
        :param enabled:      The credentials enabled flag. This flag is used for ‘LDAP’ or ‘AD’ type credentials only. (boolean)
        :param accessName:   The access name. For ‘HPE Storeonce’ type credentials, this is the identifier. For
                             ‘AWS S3’ type credentials, this is the access key. For ‘LDAP’ type credentials, this is
                             the user base. (string)
        :param osAccessName: The OS access name. For ‘LDAP’ type credentials, this is the manager user DN to
                             access the LDAP server. (string)
        :param secret:       The secret. For ‘HPE Storeonce’ type credentials, this is the password. For ‘AWS S3’
                             type credentials, this is the secret access key. For ‘LDAP’ type credentials, this is the
                             password to access the LDAP server. (string)
        :param privateKey:   The private key. (string)
        :param publicKey:    The public key. For ‘LDAP’ type credentials, this is the group base. For ‘AD’ type
                              credentials, this is the root DN. (string)
        :param hostName:     The host name. For ‘HPE Storeonce’ type credentials, this is the host name of the
                             HPE Storeonce system. For ‘AWS S3’ type credentials, this is the name of the
                             endpoint. For ‘AD’ type credentials, this is the domain name. (string)
        :param port:         The port. (int)
        :param storeName:    The store name. For ‘AWS S3’ type credentials, this is the bucket name. For ‘LDAP’
                             type credentials, this is the group filter. For ‘AD’ type credentials, this is the search
                             filter. (string)
        :param path:         The path. For ‘AWS S3’ type credentials, this is the prefix. For ‘LDAP’ and ‘AD’ type
                             credentials, this is the URL. (string)
        :paaram rank:        The rank. Used to determine the order of credentials of the same type. Only used for
                             ‘LDAP’ or ‘AD’ type credentials. (int)
        :param userComment:  The description or users comment. (string)
        :param id:           The unique ID of the credential. If none is given, one will be created.
        """
        log.debug("Running function")
        endpoint = "/sep/api/v2/credentials/create"
        data = {"type": type}
        for param in [
            "name",
            "enabled",
            "accessName",
            "osAccessName",
            "secret",
            "privateKey",
            "publicKey",
            "hostName",
            "port",
            "storeName",
            "path",
            "rank",
            "userComment",
            "id",
        ]:
            if param in kwargs:
                data[param] = kwargs[param]
        if "name" not in data:
            data["name"] = "auth.{}.{}".format(type, uuid.uuid4())
        if not self.session_id:
            self.login()
        url = self._urlexpand(endpoint)
        headers = {"X-SEP-Session": self.session_id}
        response = requests.post(url=url, json=data, headers=headers, verify=self.verify)
        self._process_error(response)
        data = response.json()
        log.debug("Got response:\n{}".format(pprint.pformat(data)))
        return data

    def credential_update(self, id, **kwargs):
        """
        Update a credential

        Check the SEP Sesam REST API documentation for applicable parameters:
        https://wiki.sep.de/wiki/index.php/4_4_3_Beefalo:Using_SEP_sesam_REST_API
        """
        log.debug("Running function")
        kwargs["id"] = id
        endpoint = "/sep/api/v2/credentials/update"
        if not self.session_id:
            self.login()
        url = self._urlexpand(endpoint)
        headers = {"X-SEP-Session": self.session_id}
        response = requests.post(url=url, json=kwargs, headers=headers, verify=self.verify)
        self._process_error(response)
        data = response.json()
        log.debug("Got response:\n{}".format(pprint.pformat(data)))
        return data

    def credential_delete(self, id):
        """
        Delete a credential
        """
        log.debug("Running function")
        endpoint = "/sep/api/v2/credentials/delete"
        if not self.session_id:
            self.login()
        url = self._urlexpand(endpoint)
        headers = {"X-SEP-Session": self.session_id}
        # for delete, we need to provide the data as a string and not form / json encoded
        response = requests.post(url=url, data=str(id), headers=headers, verify=self.verify)
        self._process_error(response)
        data = response.json()
        log.debug("Got response:\n{}".format(pprint.pformat(data)))
        return data

    ### v2 DATASTORE HANDLING ###

    def datastore_list(self):
        """
        List datastores
        """
        log.debug("Running function")
        endpoint = "/sep/api/v2/datastores"
        if not self.session_id:
            self.login()
        url = self._urlexpand(endpoint)
        headers = {"X-SEP-Session": self.session_id}
        response = requests.get(url=url, headers=headers, verify=self.verify)
        self._process_error(response)
        data = response.json()
        log.debug("Got response:\n{}".format(pprint.pformat(data)))
        return data

    def datastore_get(self, id):
        """
        Get a datastore
        """
        log.debug("Running function")
        endpoint = "/sep/api/v2/datastores/{}".format(id)
        if not self.session_id:
            self.login()
        url = self._urlexpand(endpoint)
        headers = {"X-SEP-Session": self.session_id}
        response = requests.get(url=url, headers=headers, verify=self.verify)
        self._process_error(response)
        data = response.json()
        log.debug("Got response:\n{}".format(pprint.pformat(data)))
        return data

    def datastore_find(self, **kwargs):
        """
        Find a datastore

        :param name:            The unique data store name. (string)
        :param types:           The list of data store types to match. ([JSON object])
        :param driveGroupNames: The list of drive group names to match. ([string])
        :param mediaPoolNames:  The list of media pool names to match. ([string])
        """
        log.debug("Running function")
        endpoint = "/sep/api/v2/datastores/find"
        if not self.session_id:
            self.login()
        url = self._urlexpand(endpoint)
        headers = {"X-SEP-Session": self.session_id}
        data = {}
        for param in ["name", "types", "driveGroupNames", "mediaPoolNames"]:
            if param in kwargs:
                data[param] = kwargs[param]
        response = requests.post(url=url, json=data, headers=headers, verify=self.verify)
        self._process_error(response)
        data = response.json()
        log.debug("Got response:\n{}".format(pprint.pformat(data)))
        return data

    def datastore_create(self, name, **kwargs):
        """
        Create a datastore

        Check the SEP Sesam REST API documentation for applicable parameters:
        https://wiki.sep.de/wiki/index.php/4_4_3_Beefalo:Using_SEP_sesam_REST_API
        """
        log.debug("Running function")
        endpoint = "/sep/api/v2/datastores/create"
        if len(name) > 32:
            log.error("Datastore name has a maximum length of 32")
            raise Exception("Datastore name has a maximum length of 32")
        kwargs["name"] = name
        if not self.session_id:
            self.login()
        url = self._urlexpand(endpoint)
        headers = {"X-SEP-Session": self.session_id}
        response = requests.post(url=url, json=kwargs, headers=headers, verify=self.verify)
        self._process_error(response)
        data = response.json()
        log.debug("Got response:\n{}".format(pprint.pformat(data)))
        return data

    def datastore_update(self, name, **kwargs):
        """
        Update a datastore

        Check the SEP Sesam REST API documentation for applicable parameters:
        https://wiki.sep.de/wiki/index.php/4_4_3_Beefalo:Using_SEP_sesam_REST_API
        """
        log.debug("Running function")
        kwargs["name"] = name
        endpoint = "/sep/api/v2/datastores/update"
        if not self.session_id:
            self.login()
        url = self._urlexpand(endpoint)
        headers = {"X-SEP-Session": self.session_id}
        response = requests.post(url=url, json=kwargs, headers=headers, verify=self.verify)
        self._process_error(response)
        data = response.json()
        log.debug("Got response:\n{}".format(pprint.pformat(data)))
        return data

    def datastore_delete(self, name):
        """
        Delete a datastore
        """
        log.debug("Running function")
        endpoint = "/sep/api/v2/datastores/delete"
        if not self.session_id:
            self.login()
        url = self._urlexpand(endpoint)
        headers = {"X-SEP-Session": self.session_id}
        # for delete, we need to provide the data as a string and not form / json encoded
        response = requests.post(url=url, data=str(name), headers=headers, verify=self.verify)
        self._process_error(response)
        data = response.json()
        log.debug("Got response:\n{}".format(pprint.pformat(data)))
        return data

    # TODO: check if this should be implemented

    def datastore_drives_list(self):
        endpoint = "/sep/api/v2/datastores/<name>/drives"
        # GET
        raise RuntimeError('Not implemented')

    def datastore_drives_find(self):
        endpoint = "/sep/api/v2/datastores/<name>/drives"
        # POST
        raise RuntimeError('Not implemented')

    def datastore_drivegroups_list(self):
        endpoint = "/sep/api/v2/datastores/<name>/driveGroups"
        # GET
        raise RuntimeError('Not implemented')

    def datastore_drivegroups_find(self):
        endpoint = "/sep/api/v2/datastores/<name>/driveGroups"
        # POST
        raise RuntimeError('Not implemented')

    def datastore_mediapools_list(self):
        endpoint = "/sep/api/v2/datastores/<name>/mediaPools"
        # GET
        raise RuntimeError('Not implemented')

    def datastore_mediapools_find(self):
        endpoint = "/sep/api/v2/datastores/<name>/mediaPools"
        # POST
        raise RuntimeError('Not implemented')

    #################### Version 1 API ####################

    ### v1 GROUP HANDLING ###

    def group_list(self):
        """
        List all groups
        """
        log.debug("Running function")
        endpoint = "/sep/api/groups"
        url = self._urlexpand(endpoint)
        response = requests.get(url=url, auth=(self.username, self.password), verify=self.verify)
        self._process_error(response)
        data = response.json()
        log.debug("Got response:\n{}".format(pprint.pformat(data)))
        return data

    def group_get(self, id):
        """
        Get a group
        """
        log.debug("Running function")
        endpoint = "/sep/api/groups/{}".format(id)
        url = self._urlexpand(endpoint)
        response = requests.get(url=url, auth=(self.username, self.password), verify=self.verify)
        self._process_error(response)
        data = response.json()
        log.debug("Got response:\n{}".format(pprint.pformat(data)))
        return data

    def group_find(self, **kwargs):
        """
        Find a group. Based on list due to missing support in API v1
        """
        return self._filter(self.group_list(), kwargs)

    def group_create(self, id=None, **kwargs):
        """
        Create a new group
        """
        log.debug("Running function")
        endpoint = "/sep/api/groups"
        url = self._urlexpand(endpoint)
        if id:
            kwargs["id"] = id
        response = requests.post(url=url, auth=(self.username, self.password), json=kwargs, verify=self.verify)
        self._process_error(response)
        data = response.json()
        log.debug("Got response:\n{}".format(pprint.pformat(data)))
        return data

    def group_update(self, id, **kwargs):
        """
        Update group
        """
        log.debug("Running function")
        data = self.group_get(id=id)
        kwargs = update(data, kwargs)
        self.group_delete(id=id)
        return self.group_create(**kwargs)

    def group_delete(self, id):
        """
        Delete a group
        """
        log.debug("Running function")
        endpoint = "/sep/api/groups/{}/delete".format(id)
        url = self._urlexpand(endpoint)
        response = requests.get(url=url, auth=(self.username, self.password), verify=self.verify)
        self._process_error(response)
        data = response.json()
        log.debug("Got response:\n{}".format(pprint.pformat(data)))
        return data

    ### v1 ROLE HANDLING ###

    def role_list(self):
        """
        List all roles
        """
        log.debug("Running function")
        endpoint = "/sep/api/roles"
        url = self._urlexpand(endpoint)
        response = requests.get(url=url, auth=(self.username, self.password), verify=self.verify)
        self._process_error(response)
        data = response.json()
        log.debug("Got response:\n{}".format(pprint.pformat(data)))
        return data

    def role_find(self, **kwargs):
        """
        Find a role. Based on list due to missing support in API v1
        """
        return self._filter(self.role_list(), kwargs)

    ### v1 ROLE RELATION HANDLING ###

    def role_relation_list(self):
        """
        List all roleRelations
        """
        log.debug("Running function")
        endpoint = "/sep/api/roleRelations"
        url = self._urlexpand(endpoint)
        response = requests.get(url=url, auth=(self.username, self.password), verify=self.verify)
        self._process_error(response)
        data = response.json()
        log.debug("Got response:\n{}".format(pprint.pformat(data)))
        return data

    def role_relation_get(self, id):
        """
        Get a role relation
        """
        log.debug("Running function")
        endpoint = "/sep/api/roleRelations/{}".format(id)
        url = self._urlexpand(endpoint)
        response = requests.get(url=url, auth=(self.username, self.password), verify=self.verify)
        self._process_error(response)
        data = response.json()
        log.debug("Got response:\n{}".format(pprint.pformat(data)))
        return data

    def role_relation_find(self, **kwargs):
        """
        Find a role relation. Based on list due to missing support in API v1
        """
        return self._filter(self.role_relation_list(), kwargs)

    def role_relation_create(self, group_id, role_id, id=None):
        """
        Create a new role <> group relation
        """
        log.debug("Running function")
        endpoint = "/sep/api/roleRelations"
        url = self._urlexpand(endpoint)
        data = {
            "groupId": group_id,
            "roleId": role_id,
        }
        if id:
            data["id"] = id
        response = requests.post(url=url, auth=(self.username, self.password), json=data, verify=self.verify)
        self._process_error(response)
        data = response.json()
        log.debug("Got response:\n{}".format(pprint.pformat(data)))
        return data

    def role_relation_update(self, id, group_id, role_id):
        """
        Update a role <> group relation.
        """
        log.debug("Running function")
        self.role_relation_delete(id=id)
        # it looks like the delete command is async
        # since we do not reference the role relation id somewhere else, we just do not care
        return self.role_relation_create(group_id=group_id, role_id=role_id)

    def role_relation_delete(self, id):
        """
        Delete a role relation
        """
        log.debug("Running function")
        endpoint = "/sep/api/roleRelations/{}/delete".format(id)
        url = self._urlexpand(endpoint)
        response = requests.get(url=url, auth=(self.username, self.password), verify=self.verify)
        self._process_error(response)
        data = response.json()
        log.debug("Got response:\n{}".format(pprint.pformat(data)))
        return data

    ### v1 EXTERNAL GROUP HANDLING ###

    def external_group_list(self):
        """
        List all external gruops
        """
        log.debug("Running function")
        endpoint = "/sep/api/externalGroups"
        url = self._urlexpand(endpoint)
        response = requests.get(url=url, auth=(self.username, self.password), verify=self.verify)
        self._process_error(response)
        data = response.json()
        log.debug("Got response:\n{}".format(pprint.pformat(data)))
        return data

    def external_group_get(self, id):
        """
        Get an external group
        """
        log.debug("Running function")
        endpoint = "/sep/api/externalGroups/{}".format(id)
        url = self._urlexpand(endpoint)
        response = requests.get(url=url, auth=(self.username, self.password), verify=self.verify)
        self._process_error(response)
        data = response.json()
        log.debug("Got response:\n{}".format(pprint.pformat(data)))
        return data

    def external_group_find(self, **kwargs):
        """
        Find an external group. Based on list due to missing support in API v1
        """
        return self._filter(self.external_group_list(), kwargs)

    def external_group_create(self, id=None, **kwargs):
        """
        Create an external group
        """
        log.debug("Running function")
        endpoint = "/sep/api/externalGroups"
        url = self._urlexpand(endpoint)
        if id:
            kwargs["id"] = id
        response = requests.post(url=url, auth=(self.username, self.password), json=kwargs, verify=self.verify)
        self._process_error(response)
        data = response.json()
        log.debug("Got response:\n{}".format(pprint.pformat(data)))
        return data

    def external_group_upsert(self, id, **kwargs):
        """
        Create/Update an external group
        """
        log.debug("Running function")
        self.external_group_delete(id=id)
        return self.external_group_create(id=id, **kwargs)

    def external_group_delete(self, id):
        """
        Delete an external group
        """
        log.debug("Running function")
        endpoint = "/sep/api/externalGroups/{}/delete".format(id)
        url = self._urlexpand(endpoint)
        response = requests.get(url=url, auth=(self.username, self.password), verify=self.verify)
        self._process_error(response)
        data = response.json()
        log.debug("Got response:\n{}".format(pprint.pformat(data)))
        return data

    ### v1 EXTERNAL GROUP RELATION HANDLING

    def ext_group_relation_list(self):
        """
        List all internal <> external group relations
        """
        log.debug("Running function")
        endpoint = "/sep/api/externalGroupRelations"
        url = self._urlexpand(endpoint)
        response = requests.get(url=url, auth=(self.username, self.password), verify=self.verify)
        self._process_error(response)
        data = response.json()
        log.debug("Got response:\n{}".format(pprint.pformat(data)))
        return data

    def ext_group_relation_get(self, id):
        """
        Get an internal <> external group relation
        """
        log.debug("Running function")
        endpoint = "/sep/api/externalGroupRelations/{}".format(id)
        url = self._urlexpand(endpoint)
        response = requests.get(url=url, auth=(self.username, self.password), verify=self.verify)
        self._process_error(response)
        data = response.json()
        log.debug("Got response:\n{}".format(pprint.pformat(data)))
        return data

    def ext_group_relation_find(self, **kwargs):
        """
        Find an internal <> external group relation. Based on list due to missing support in API v1
        """
        return self._filter(self.ext_group_relation_list(), kwargs)

    def ext_group_relation_create(self, internal_group_id, external_group_id, id=None):
        """
        Create a new internal <> external group relation
        """
        log.debug("Running function")
        endpoint = "/sep/api/externalGroupRelations"
        url = self._urlexpand(endpoint)
        data = {
            "groupId": internal_group_id,
            "externalGroupId": external_group_id,
        }
        if id:
            data["id"] = id
        response = requests.post(url=url, auth=(self.username, self.password), json=data, verify=self.verify)
        self._process_error(response)
        data = response.json()
        log.debug("Got response:\n{}".format(pprint.pformat(data)))
        return data

    def ext_group_relation_update(self, id, internal_group_id, external_group_id):
        """
        Update a internal <> external group relation
        """
        log.debug("Running function")
        self.ext_group_relation_delete(id=id)
        return self.ext_group_relation_create(
            id=id,
            internal_group_id=internal_group_id,
            external_group_id=external_group_id
        )

    def ext_group_relation_delete(self, id):
        """
        Delete an internal <> external group relation
        """
        log.debug("Running function")
        endpoint = "/sep/api/externalGroupRelations/{}/delete".format(id)
        url = self._urlexpand(endpoint)
        response = requests.get(url=url, auth=(self.username, self.password), verify=self.verify)
        self._process_error(response)
        data = response.json()
        log.debug("Got response:\n{}".format(pprint.pformat(data)))
        return data

    ### v1 SCHEDULE HANDLING ###

    def schedule_list(self):
        """
        List all schedules
        """
        log.debug("Running function")
        endpoint = "/sep/api/schedules"
        url = self._urlexpand(endpoint)
        response = requests.get(url=url, auth=(self.username, self.password), verify=self.verify)
        self._process_error(response)
        data = response.json()
        log.debug("Got response:\n{}".format(pprint.pformat(data)))
        return data

    def schedule_get(self, name):
        """
        Get a schedule
        """
        log.debug("Running function")
        endpoint = "/sep/api/schedules/{}".format(name)
        url = self._urlexpand(endpoint)
        response = requests.get(url=url, auth=(self.username, self.password), verify=self.verify)
        self._process_error(response)
        data = response.json()
        log.debug("Got response:\n{}".format(pprint.pformat(data)))
        return data

    def schedule_find(self, **kwargs):
        """
        Find a schedule. Based on list due to missing support in API v1
        """
        return self._filter(self.schedule_list(), kwargs)

    def schedule_create(self, name, **kwargs):
        """
        Create a schedule
        """
        log.debug("Running function")
        endpoint = "/sep/api/schedules"
        url = self._urlexpand(endpoint)
        kwargs["name"] = name
        response = requests.post(url=url, auth=(self.username, self.password), json=kwargs, verify=self.verify)
        self._process_error(response)
        data = response.json()
        log.debug("Got response:\n{}".format(pprint.pformat(data)))
        return data

    def schedule_update(self, name, **kwargs):
        """
        Update a schedule
        """
        log.debug("Running function")
        data = self.schedule_get(name=name)
        kwargs = update(data, kwargs)
        self.schedule_delete(name=name)
        return self.schedule_create(**kwargs)

    def schedule_delete(self, name):
        """
        Delete a schedule
        """
        log.debug("Running function")
        endpoint = "/sep/api/schedules/{}/delete".format(name)
        url = self._urlexpand(endpoint)
        response = requests.get(url=url, auth=(self.username, self.password), verify=self.verify)
        self._process_error(response)
        data = response.json()
        log.debug("Got response:\n{}".format(pprint.pformat(data)))
        return data

    ### v1 TASK HANDLING ###

    def task_list(self):
        """
        List all tasks
        """
        log.debug("Running function")
        endpoint = "/sep/api/tasks"
        url = self._urlexpand(endpoint)
        response = requests.get(url=url, auth=(self.username, self.password), verify=self.verify)
        self._process_error(response)
        data = response.json()
        log.debug("Got response:\n{}".format(pprint.pformat(data)))
        return data

    def task_get(self, name):
        """
        Get a task
        """
        log.debug("Running function")
        endpoint = "/sep/api/tasks/{}".format(name)
        url = self._urlexpand(endpoint)
        response = requests.get(url=url, auth=(self.username, self.password), verify=self.verify)
        self._process_error(response)
        data = response.json()
        log.debug("Got response:\n{}".format(pprint.pformat(data)))
        return data

    def task_find(self, **kwargs):
        """
        Find a task. Based on list due to missing support in API v1
        """
        return self._filter(self.task_list(), kwargs)

    def task_create(self, name, **kwargs):
        """
        Create a task
        """
        log.debug("Running function")
        endpoint = "/sep/api/tasks"
        url = self._urlexpand(endpoint)
        kwargs["name"] = name
        response = requests.post(url=url, auth=(self.username, self.password), json=kwargs, verify=self.verify)
        self._process_error(response)
        data = response.json()
        log.debug("Got response:\n{}".format(pprint.pformat(data)))
        return data

    def task_update(self, name, **kwargs):
        """
        Update a task
        """
        log.debug("Running function")
        data = self.task_get(name=name)
        kwargs = update(data, kwargs)
        self.task_delete(name=name)
        return self.task_create(**kwargs)

    def task_delete(self, name):
        """
        Delete a task
        """
        log.debug("Running function")
        endpoint = "/sep/api/tasks/{}/forceRemove".format(name)  # this will NOT take care of references
        url = self._urlexpand(endpoint)
        response = requests.get(url=url, auth=(self.username, self.password), verify=self.verify)
        self._process_error(response)
        data = response.json()
        log.debug("Got response:\n{}".format(pprint.pformat(data)))
        return data

    ### v1 TASK EVENT HANDLING ###

    def task_event_list(self):
        """
        List all task events
        """
        log.debug("Running function")
        endpoint = "/sep/api/taskEvents"
        url = self._urlexpand(endpoint)
        response = requests.get(url=url, auth=(self.username, self.password), verify=self.verify)
        self._process_error(response)
        data = response.json()
        log.debug("Got response:\n{}".format(pprint.pformat(data)))
        return data

    def task_event_get(self, id):
        """
        Get a task event
        """
        log.debug("Running function")
        endpoint = "/sep/api/taskEvents/{}".format(id)
        url = self._urlexpand(endpoint)
        response = requests.get(url=url, auth=(self.username, self.password), verify=self.verify)
        self._process_error(response)
        data = response.json()
        log.debug("Got response:\n{}".format(pprint.pformat(data)))
        return data

    def task_event_find(self, **kwargs):
        """
        Find a task event. Based on list due to missing support in API v1
        """
        return self._filter(self.task_event_list(), kwargs)

    def task_event_create(self, id=None, **kwargs):
        """
        Create/Update a task event
        """
        log.debug("Running function")
        endpoint = "/sep/api/taskEvents"
        url = self._urlexpand(endpoint)
        if id:
            kwargs["id"] = id
        response = requests.post(url=url, auth=(self.username, self.password), json=kwargs, verify=self.verify)
        self._process_error(response)
        data = response.json()
        log.debug("Got response:\n{}".format(pprint.pformat(data)))
        return data

    def task_event_update(self, id, **kwargs):
        """
        Update a task event
        """
        log.debug("Running function")
        data = self.task_event_get(id=id)
        kwargs = update(data, kwargs)
        self.task_event_delete(id=id)
        return self.task_event_create(**kwargs)

    def task_event_delete(self, id):
        """
        Delete a task event
        """
        log.debug("Running function")
        endpoint = "/sep/api/taskEvents/{}/delete".format(id)
        url = self._urlexpand(endpoint)
        response = requests.get(url=url, auth=(self.username, self.password), verify=self.verify)
        self._process_error(response)
        data = response.json()
        log.debug("Got response:\n{}".format(pprint.pformat(data)))
        return data

    ### v1 COMMAND HANDLING ###

    def command_list(self):
        """
        List all commands
        """
        log.debug("Running function")
        endpoint = "/sep/api/commands"
        url = self._urlexpand(endpoint)
        response = requests.get(url=url, auth=(self.username, self.password), verify=self.verify)
        self._process_error(response)
        data = response.json()
        log.debug("Got response:\n{}".format(pprint.pformat(data)))
        return data

    def command_get(self, id):
        """
        Get a command
        """
        log.debug("Running function")
        endpoint = "/sep/api/commands/{}".format(id)
        url = self._urlexpand(endpoint)
        response = requests.get(url=url, auth=(self.username, self.password), verify=self.verify)
        self._process_error(response)
        data = response.json()
        log.debug("Got response:\n{}".format(pprint.pformat(data)))
        return data

    def command_find(self, **kwargs):
        """
        Find a command. Based on list due to missing support in API v1
        """
        return self._filter(self.command_list(), kwargs)

    def command_create(self, id=None, **kwargs):
        """
        Update a command
        """
        log.debug("Running function")
        endpoint = "/sep/api/commands"
        url = self._urlexpand(endpoint)
        if id:
            kwargs["id"] = id
        response = requests.post(url=url, auth=(self.username, self.password), json=kwargs, verify=self.verify)
        self._process_error(response)
        data = response.json()
        log.debug("Got response:\n{}".format(pprint.pformat(data)))
        return data

    def command_update(self, **kwargs):
        """
        Update a command
        """
        log.debug("Running function")
        data = self.command_get(id=id)
        kwargs = update(data, kwargs)
        self.command_delete(id=id)
        return self.command_create(**kwargs)

    def command_delete(self, id):
        """
        Delete a command
        """
        log.debug("Running function")
        endpoint = "/sep/api/commands/{}/delete".format(id)
        url = self._urlexpand(endpoint)
        response = requests.get(url=url, auth=(self.username, self.password), verify=self.verify)
        self._process_error(response)
        data = response.json()
        log.debug("Got response:\n{}".format(pprint.pformat(data)))
        return data

    ### v1 COMMAND EVENT HANDLING ###

    def command_event_list(self):
        """
        List all command events
        """
        log.debug("Running function")
        endpoint = "/sep/api/commandEvents"
        url = self._urlexpand(endpoint)
        response = requests.get(url=url, auth=(self.username, self.password), verify=self.verify)
        self._process_error(response)
        data = response.json()
        log.debug("Got response:\n{}".format(pprint.pformat(data)))
        return data

    def command_event_get(self, id):
        """
        Get a command event
        """
        log.debug("Running function")
        endpoint = "/sep/api/commandEvents/{}".format(id)
        url = self._urlexpand(endpoint)
        response = requests.get(url=url, auth=(self.username, self.password), verify=self.verify)
        self._process_error(response)
        data = response.json()
        log.debug("Got response:\n{}".format(pprint.pformat(data)))
        return data

    def command_event_find(self, **kwargs):
        """
        Find a command event. Based on list due to missing support in API v1
        """
        return self._filter(self.command_event_list(), kwargs)

    def command_event_create(self, id=None, **kwargs):
        """
        Create a command event
        """
        log.debug("Running function")
        endpoint = "/sep/api/commandEvents"
        url = self._urlexpand(endpoint)
        if id:
            kwargs["id"] = id
        response = requests.post(url=url, auth=(self.username, self.password), json=kwargs, verify=self.verify)
        self._process_error(response)
        data = response.json()
        log.debug("Got response:\n{}".format(pprint.pformat(data)))
        return data

    def command_event_update(self, id, **kwargs):
        """
        Update a command event
        """
        log.debug("Running function")
        data = self.command_event_get(id=id)
        kwargs = update(data, kwargs)
        self.command_event_delete(id=id)
        return self.command_event_create(**kwargs)

    def command_event_delete(self, id):
        """
        Delete a command event
        """
        log.debug("Running function")
        endpoint = "/sep/api/commandEvents/{}/delete".format(id)
        url = self._urlexpand(endpoint)
        response = requests.get(url=url, auth=(self.username, self.password), verify=self.verify)
        self._process_error(response)
        data = response.json()
        log.debug("Got response:\n{}".format(pprint.pformat(data)))
        return data

    ### v1 MEDIA POOL HANDLING ###

    def media_pool_list(self):
        """
        List all media pools
        """
        log.debug("Running function")
        endpoint = "/sep/api/mediaPools"
        url = self._urlexpand(endpoint)
        response = requests.get(url=url, auth=(self.username, self.password), verify=self.verify)
        self._process_error(response)
        data = response.json()
        log.debug("Got response:\n{}".format(pprint.pformat(data)))
        return data

    def media_pool_get(self, id):
        """
        Get a media pool
        """
        log.debug("Running function")
        endpoint = "/sep/api/mediaPools/{}".format(id)
        url = self._urlexpand(endpoint)
        response = requests.get(url=url, auth=(self.username, self.password), verify=self.verify)
        self._process_error(response)
        data = response.json()
        log.debug("Got response:\n{}".format(pprint.pformat(data)))
        return data

    def media_pool_find(self, **kwargs):
        """
        Find a media pool. Based on list due to missing support in API v1
        """
        return self._filter(self.media_pool_list(), kwargs)

    def media_pool_create(self, id=None, **kwargs):
        """
        Create a media pool
        """
        log.debug("Running function")
        endpoint = "/sep/api/mediaPools"
        url = self._urlexpand(endpoint)
        if id:
            kwargs["id"] = id
        response = requests.post(url=url, auth=(self.username, self.password), json=kwargs, verify=self.verify)
        self._process_error(response)
        data = response.json()
        log.debug("Got response:\n{}".format(pprint.pformat(data)))
        return data

    def media_pool_update(self, id, **kwargs):
        """
        Create/Update a media pool
        """
        log.debug("Running function")
        data = self.media_pool_get(id=id)
        kwargs = update(data, kwargs)
        self.media_pool_delete(id=id)
        return self.media_pool_create(**kwargs)

    def media_pool_delete(self, id):
        """
        Delete a media pool
        """
        log.debug("Running function")
        endpoint = "/sep/api/mediaPools/{}/delete".format(id)
        url = self._urlexpand(endpoint)
        response = requests.get(url=url, auth=(self.username, self.password), verify=self.verify)
        self._process_error(response)
        data = response.json()
        log.debug("Got response:\n{}".format(pprint.pformat(data)))
        return data

    ### v1 DRIVE GROUPS ###

    def drive_group_list(self):
        """
        List all drive groups
        """
        log.debug("Running function")
        endpoint = "/sep/api/driveGroups"
        url = self._urlexpand(endpoint)
        response = requests.get(url=url, auth=(self.username, self.password), verify=self.verify)
        self._process_error(response)
        data = response.json()
        log.debug("Got response:\n{}".format(pprint.pformat(data)))
        return data

    def drive_group_get(self, id):
        """
        Get a drive group
        """
        log.debug("Running function")
        endpoint = "/sep/api/driveGroups/{}".format(id)
        url = self._urlexpand(endpoint)
        response = requests.get(url=url, auth=(self.username, self.password), verify=self.verify)
        self._process_error(response)
        data = response.json()
        log.debug("Got response:\n{}".format(pprint.pformat(data)))
        return data

    def drive_group_find(self, **kwargs):
        """
        Find a drive group. Based on list due to missing support in API v1
        """
        return self._filter(self.drive_group_list(), kwargs)

