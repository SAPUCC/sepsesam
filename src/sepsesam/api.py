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
    401: {
        "error": "CLIENT_ERROR_UNAUTHORIZED",
        "message": "The client is not authenticated to do the request",
    },
    403: {
        "error": "CLIENT_ERROR_FORBIDDEN",
        "message": "The authenticated user does not have the required permissions to do the request",
    },
    404: {
        "error": "CLIENT_ERROR_NOT_FOUND",
        "message": "The requested endpoint does not exist",
    },
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
    Recursively update a dictionary, taken from
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

    def __repr__(self):
        return f"""
SEPSesamAPIError:
    status_code: {self.status_code},
    error: {self.error},
    message: {self.message},
    parameter: {self.parameter},
    type: {self.type},
    url: {self.url}
"""

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
        self.headers = None

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
        log.error("An error occurred:\n{}".format(pprint.pformat(data)))
        raise SEPSesamAPIError(**data)

    def _urlexpand(self, endpoint):
        """
        Return full URL to endpoint
        """
        return "{}{}".format(
            self.url if self.url[-1] == "/" else self.url + "/",
            endpoint if endpoint[0] != "/" else endpoint[1:],
        )

    def _auth(func):
        """Check if session is set, and if not, authenticate before
        executing function
        """

        def _doauth(*args, **kwargs):
            self = args[0]
            if not self.session_id:
                self.login()
            return func(*args, **kwargs)

        return _doauth

    def _filter(self, obj_list, **kwargs):
        """
        Find an object based on attributes. Based on list due to missing support in API v1
        """
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
        endpoint = "sep/api/v2/auth/login"
        data = {"username": self.username, "secret": self.password, "type": "CLASSIC"}
        url = self._urlexpand(endpoint)
        response = requests.post(url=url, json=data, verify=self.verify)
        self._process_error(response)
        resp_data = response.json()
        self.session_id = resp_data
        self.headers = {"X-SEP-Session": self.session_id}
        log.debug("Got response:\n{}".format(pprint.pformat(resp_data)))
        return True

    def logout(self):
        """
        Logout and cleanup session
        """
        endpoint = "sep/api/v2/auth/logout"
        if self.session_id:
            url = self._urlexpand(endpoint)
            requests.get(url=url, headers=self.headers, verify=self.verify)

    @_auth
    def get_server_info(self):
        """
        Retrieve server information
        """
        endpoint = "sep/api/v2/server/info"
        url = self._urlexpand(endpoint)
        response = requests.get(url=url, headers=self.headers, verify=self.verify)
        self._process_error(response)
        data = response.json()
        log.debug("Got response:\n{}".format(pprint.pformat(data)))
        return data

    ### v2 CLIENT HANDLING ###

    @_auth
    def client_list(self):
        """
        Return a list of clients
        """
        endpoint = "/sep/api/v2/clients"
        url = self._urlexpand(endpoint)
        response = requests.get(url=url, headers=self.headers, verify=self.verify)
        self._process_error(response)
        data = response.json()
        log.debug("Got response:\n{}".format(pprint.pformat(data)))
        return data

    @_auth
    def client_get(self, id):
        """
        Return a client for a given ID
        """
        endpoint = "/sep/api/v2/clients/{}".format(id)
        url = self._urlexpand(endpoint)
        response = requests.get(url=url, headers=self.headers, verify=self.verify)
        self._process_error(response)
        data = response.json()
        log.debug("Got response:\n{}".format(pprint.pformat(data)))
        return data

    @_auth
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
        endpoint = "/sep/api/v2/clients/find"
        url = self._urlexpand(endpoint)
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
        response = requests.post(
            url=url, json=data, headers=self.headers, verify=self.verify
        )
        self._process_error(response)
        data = response.json()
        log.debug("Got response:\n{}".format(pprint.pformat(data)))
        return data

    @_auth
    def client_create(self, name, **kwargs):
        """
        Create a client with the given parameters.

        Check the SEP Sesam REST API documentation for applicable parameters:
        https://wiki.sep.de/wiki/index.php/File:SEP_sesam-REST-API-V2-Jaglion.pdf
        """
        endpoint = "/sep/api/v2/clients/create"
        url = self._urlexpand(endpoint)
        kwargs["name"] = name
        response = requests.post(
            url=url, json=kwargs, headers=self.headers, verify=self.verify
        )
        self._process_error(response)
        data = response.json()
        log.debug("Got response:\n{}".format(pprint.pformat(data)))
        return data

    @_auth
    def client_update(self, id=None, name=None, **kwargs):
        """
        Update a client with the given parameters. Either "id" or "name" must be given.

        Check the SEP Sesam REST API documentation for applicable parameters:
        https://wiki.sep.de/wiki/index.php/File:SEP_sesam-REST-API-V2-Jaglion.pdf
        """
        if id:
            kwargs["id"] = id
        elif name:
            kwargs["name"] = name
        else:
            raise Exception("Either 'id' or 'name' must be specified")
        endpoint = "/sep/api/v2/clients/update"
        url = self._urlexpand(endpoint)
        response = requests.post(
            url=url, json=kwargs, headers=self.headers, verify=self.verify
        )
        self._process_error(response)
        data = response.json()
        log.debug("Got response:\n{}".format(pprint.pformat(data)))
        return data

    @_auth
    def client_delete(self, id):
        """
        Delete a client
        """
        endpoint = "/sep/api/v2/clients/delete"
        url = self._urlexpand(endpoint)
        # for delete, we need to provide the data as a string and not form / json encoded
        response = requests.post(
            url=url, data=str(id), headers=self.headers, verify=self.verify
        )
        self._process_error(response)
        data = response.json()
        log.debug("Got response:\n{}".format(pprint.pformat(data)))
        return data

    ### v2 LOCATION HANDLING ###

    @_auth
    def location_list(self):
        """
        List all locations
        """
        endpoint = "/sep/api/v2/locations"
        url = self._urlexpand(endpoint)
        response = requests.get(url=url, headers=self.headers, verify=self.verify)
        print(response.text)
        self._process_error(response)
        data = response.json()
        log.debug("Got response:\n{}".format(pprint.pformat(data)))
        return data

    @_auth
    def location_get(self, id):
        """
        Retrieve a location
        """
        endpoint = "/sep/api/v2/locations/{}".format(id)
        url = self._urlexpand(endpoint)
        data = {"id": id}
        response = requests.get(
            url=url, json=data, headers=self.headers, verify=self.verify
        )
        self._process_error(response)
        data = response.json()
        log.debug("Got response:\n{}".format(pprint.pformat(data)))
        return data

    @_auth
    def location_find(self, parent):
        """
        Find a location.

        :param parent: The ID of the parent location. (int)
        """
        endpoint = "/sep/api/v2/locations/find/"
        url = self._urlexpand(endpoint)
        data = {"parent": parent}
        response = requests.post(
            url=url, json=data, headers=self.headers, verify=self.verify
        )
        self._process_error(response)
        data = response.json()
        log.debug("Got response:\n{}".format(pprint.pformat(data)))
        return data

    @_auth
    def location_create(self, name, **kwargs):
        """
        Create a location.

        Check the SEP Sesam REST API documentation for applicable parameters:
        https://wiki.sep.de/wiki/index.php/File:SEP_sesam-REST-API-V2-Jaglion.pdf
        """
        endpoint = "/sep/api/v2/locations/create"
        url = self._urlexpand(endpoint)
        kwargs["name"] = name
        response = requests.post(
            url=url, json=kwargs, headers=self.headers, verify=self.verify
        )
        self._process_error(response)
        data = response.json()
        log.debug("Got response:\n{}".format(pprint.pformat(data)))
        return data

    @_auth
    def location_update(self, id=None, name=None, **kwargs):
        """
        Update a location. Either id or name must be specified.

        Check the SEP Sesam REST API documentation for applicable parameters:
        https://wiki.sep.de/wiki/index.php/File:SEP_sesam-REST-API-V2-Jaglion.pdf
        """
        if id:
            kwargs["id"] = id
        elif name:
            kwargs["name"] = name
        else:
            raise Exception("Either 'id' or 'name' must be specified")
        endpoint = "/sep/api/v2/locations/update"
        url = self._urlexpand(endpoint)
        response = requests.post(
            url=url, json=kwargs, headers=self.headers, verify=self.verify
        )
        self._process_error(response)
        data = response.json()
        log.debug("Got response:\n{}".format(pprint.pformat(data)))
        return data

    @_auth
    def location_delete(self, id):
        """
        Deletes a location
        """
        endpoint = "/sep/api/v2/locations/delete"
        url = self._urlexpand(endpoint)
        # for delete, we need to provide the data as a string and not form / json encoded
        response = requests.post(
            url=url, data=str(id), headers=self.headers, verify=self.verify
        )
        self._process_error(response)
        data = response.json()
        log.debug("Got response:\n{}".format(pprint.pformat(data)))
        return data

    @_auth
    def location_resolve_to_id(self, name):
        """
        Resolve a given name or path to an id
        """
        endpoint = "/sep/api/v2/locations/resolveLocationToId"
        url = self._urlexpand(endpoint)
        # data is provided as is, but with a strange formatting
        response = requests.post(
            url=url, data='"{}"'.format(name), headers=self.headers, verify=self.verify
        )
        self._process_error(response)
        data = response.json()
        log.debug("Got response:\n{}".format(pprint.pformat(data)))
        return data

    ### v2 ACL HANDLING ###

    @_auth
    def acl_list(self):
        """
        List ACLs
        """
        endpoint = "/sep/api/v2/acls"
        url = self._urlexpand(endpoint)
        response = requests.get(url=url, headers=self.headers, verify=self.verify)
        self._process_error(response)
        data = response.json()
        log.debug("Got response:\n{}".format(pprint.pformat(data)))
        return data

    @_auth
    def acl_get(self, id):
        """
        Get an ACL
        """
        endpoint = "/sep/api/v2/acls/{}".format(id)
        url = self._urlexpand(endpoint)
        response = requests.get(url=url, headers=self.headers, verify=self.verify)
        self._process_error(response)
        data = response.json()
        log.debug("Got response:\n{}".format(pprint.pformat(data)))
        return data

    @_auth
    def acl_find(self, **kwargs):
        """
        Find an ACL

        :param object: The object ID. (string)
        :param origin: The object origin (string)
        """
        endpoint = "/sep/api/v2/acls/find"
        url = self._urlexpand(endpoint)
        data = {}
        for param in ["object", "origin"]:
            if param in kwargs:
                data[param] = kwargs[param]
        response = requests.post(
            url=url, json=data, headers=self.headers, verify=self.verify
        )
        self._process_error(response)
        data = response.json()
        log.debug("Got response:\n{}".format(pprint.pformat(data)))
        return data

    @_auth
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
        endpoint = "/sep/api/v2/acls/create"
        data = {"object": object, "origin": origin, "value": value}
        if id:
            data["id"] = id
        url = self._urlexpand(endpoint)
        response = requests.post(
            url=url, json=data, headers=self.headers, verify=self.verify
        )
        self._process_error(response)
        data = response.json()
        log.debug("Got response:\n{}".format(pprint.pformat(data)))
        return data

    @_auth
    def acl_update(self, id, **kwargs):
        """
        Update an ACL

        Check the SEP Sesam REST API documentation for applicable parameters:
        https://wiki.sep.de/wiki/index.php/File:SEP_sesam-REST-API-V2-Jaglion.pdf
        """
        kwargs["id"] = id
        endpoint = "/sep/api/v2/acls/update"
        url = self._urlexpand(endpoint)
        response = requests.post(
            url=url, json=kwargs, headers=self.headers, verify=self.verify
        )
        self._process_error(response)
        data = response.json()
        log.debug("Got response:\n{}".format(pprint.pformat(data)))
        return data

    @_auth
    def acl_delete(self, id):
        """
        Delete an ACL
        """
        endpoint = "/sep/api/v2/acls/delete"
        url = self._urlexpand(endpoint)
        # for delete, we need to provide the data as a string and not form / json encoded
        response = requests.post(
            url=url, data=str(id), headers=self.headers, verify=self.verify
        )
        self._process_error(response)
        data = response.json()
        log.debug("Got response:\n{}".format(pprint.pformat(data)))
        return data

    ### v2 CREDENTIAL HANDLING ###

    @_auth
    def credential_list(self):
        """
        List credentials
        """
        endpoint = "/sep/api/v2/credentials"
        url = self._urlexpand(endpoint)
        response = requests.get(url=url, headers=self.headers, verify=self.verify)
        self._process_error(response)
        data = response.json()
        log.debug("Got response:\n{}".format(pprint.pformat(data)))
        return data

    @_auth
    def credential_get(self, id):
        """
        Get a credential
        """
        endpoint = "/sep/api/v2/credentials/{}".format(id)
        url = self._urlexpand(endpoint)
        response = requests.get(url=url, headers=self.headers, verify=self.verify)
        self._process_error(response)
        data = response.json()
        log.debug("Got response:\n{}".format(pprint.pformat(data)))
        return data

    @_auth
    def credential_find(self, type):
        """
        Find a credential

        :param type: The credential type. (string)
        """
        endpoint = "/sep/api/v2/credentials/find"
        url = self._urlexpand(endpoint)
        data = {"type": type}
        response = requests.post(
            url=url, json=data, headers=self.headers, verify=self.verify
        )
        self._process_error(response)
        data = response.json()
        log.debug("Got response:\n{}".format(pprint.pformat(data)))
        return data

    @_auth
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
        url = self._urlexpand(endpoint)
        response = requests.post(
            url=url, json=data, headers=self.headers, verify=self.verify
        )
        self._process_error(response)
        data = response.json()
        log.debug("Got response:\n{}".format(pprint.pformat(data)))
        return data

    @_auth
    def credential_update(self, id, **kwargs):
        """
        Update a credential

        Check the SEP Sesam REST API documentation for applicable parameters:
        https://wiki.sep.de/wiki/index.php/File:SEP_sesam-REST-API-V2-Jaglion.pdf
        """
        kwargs["id"] = id
        endpoint = "/sep/api/v2/credentials/update"
        url = self._urlexpand(endpoint)
        response = requests.post(
            url=url, json=kwargs, headers=self.headers, verify=self.verify
        )
        self._process_error(response)
        data = response.json()
        log.debug("Got response:\n{}".format(pprint.pformat(data)))
        return data

    @_auth
    def credential_delete(self, id):
        """
        Delete a credential
        """
        endpoint = "/sep/api/v2/credentials/delete"
        url = self._urlexpand(endpoint)
        # for delete, we need to provide the data as a string and not form / json encoded
        response = requests.post(
            url=url, data=str(id), headers=self.headers, verify=self.verify
        )
        self._process_error(response)
        data = response.json()
        log.debug("Got response:\n{}".format(pprint.pformat(data)))
        return data

    ### v2 DATASTORE HANDLING ###

    @_auth
    def datastore_list(self):
        """
        List datastores
        """
        endpoint = "/sep/api/v2/datastores"
        url = self._urlexpand(endpoint)
        response = requests.get(url=url, headers=self.headers, verify=self.verify)
        self._process_error(response)
        data = response.json()
        log.debug("Got response:\n{}".format(pprint.pformat(data)))
        return data

    @_auth
    def datastore_get(self, id):
        """
        Get a datastore
        """
        endpoint = "/sep/api/v2/datastores/{}".format(id)
        url = self._urlexpand(endpoint)
        response = requests.get(url=url, headers=self.headers, verify=self.verify)
        self._process_error(response)
        data = response.json()
        log.debug("Got response:\n{}".format(pprint.pformat(data)))
        return data

    @_auth
    def datastore_find(self, **kwargs):
        """
        Find a datastore

        :param name:            The unique data store name. (string)
        :param types:           The list of data store types to match. ([JSON object])
        :param driveGroupNames: The list of drive group names to match. ([string])
        :param mediaPoolNames:  The list of media pool names to match. ([string])
        """
        endpoint = "/sep/api/v2/datastores/find"
        url = self._urlexpand(endpoint)
        data = {}
        for param in ["name", "types", "driveGroupNames", "mediaPoolNames"]:
            if param in kwargs:
                data[param] = kwargs[param]
        response = requests.post(
            url=url, json=data, headers=self.headers, verify=self.verify
        )
        self._process_error(response)
        data = response.json()
        log.debug("Got response:\n{}".format(pprint.pformat(data)))
        return data

    @_auth
    def datastore_create(self, name, **kwargs):
        """
        Create a datastore

        Check the SEP Sesam REST API documentation for applicable parameters:
        https://wiki.sep.de/wiki/index.php/File:SEP_sesam-REST-API-V2-Jaglion.pdf
        """
        endpoint = "/sep/api/v2/datastores/create"
        if len(name) > 32:
            log.error("Datastore name has a maximum length of 32")
            raise Exception("Datastore name has a maximum length of 32")
        kwargs["name"] = name
        if not self.session_id:
            self.login()
        url = self._urlexpand(endpoint)
        response = requests.post(
            url=url, json=kwargs, headers=self.headers, verify=self.verify
        )
        self._process_error(response)
        data = response.json()
        log.debug("Got response:\n{}".format(pprint.pformat(data)))
        return data

    @_auth
    def datastore_update(self, name, **kwargs):
        """
        Update a datastore

        Check the SEP Sesam REST API documentation for applicable parameters:
        https://wiki.sep.de/wiki/index.php/File:SEP_sesam-REST-API-V2-Jaglion.pdf
        """
        kwargs["name"] = name
        endpoint = "/sep/api/v2/datastores/update"
        url = self._urlexpand(endpoint)
        response = requests.post(
            url=url, json=kwargs, headers=self.headers, verify=self.verify
        )
        self._process_error(response)
        data = response.json()
        log.debug("Got response:\n{}".format(pprint.pformat(data)))
        return data

    @_auth
    def datastore_delete(self, name):
        """
        Delete a datastore
        """
        endpoint = "/sep/api/v2/datastores/delete"
        url = self._urlexpand(endpoint)
        # for delete, we need to provide the data as a string and not form / json encoded
        response = requests.post(
            url=url, data=str(name), headers=self.headers, verify=self.verify
        )
        self._process_error(response)
        data = response.json()
        log.debug("Got response:\n{}".format(pprint.pformat(data)))
        return data

    ### v2 BACKUP TASKS HANDLING ###

    @_auth
    def backup_task_list(self):
        """
        List backup tasks
        """
        endpoint = "/sep/api/v2/backups/findTasks"
        url = self._urlexpand(endpoint)
        response = requests.get(url=url, headers=self.headers, verify=self.verify)
        self._process_error(response)
        data = response.json()
        log.debug("Got response:\n{}".format(pprint.pformat(data)))
        return data

    @_auth
    def backup_task_get(self, name):
        """
        Get a backup task
        """
        endpoint = "/sep/api/v2/backups/tasks/{}".format(name)
        url = self._urlexpand(endpoint)
        response = requests.get(url=url, headers=self.headers, verify=self.verify)
        try:
            self._process_error(response)
            data = response.json()
            log.debug("Got response:\n{}".format(pprint.pformat(data)))
            return data
        except SEPSesamAPIError as e:
            if e.error == "object.not.found.id":
                log.debug("Backup task not found.")
                return None
            else:
                raise e

    @_auth
    def backup_task_find(self, **kwargs):
        """
        Find a backup task

        Check the SEP Sesam REST API documentation for applicable parameters:
        https://wiki.sep.de/wiki/index.php/File:SEP_sesam-REST-API-V2-Jaglion.pdf
        """
        endpoint = "/sep/api/v2/backups/findTasks"
        url = self._urlexpand(endpoint)
        response = requests.post(
            url=url, json=kwargs, headers=self.headers, verify=self.verify
        )
        self._process_error(response)
        data = response.json()
        log.debug("Got response:\n{}".format(pprint.pformat(data)))
        return data

    @_auth
    def backup_task_create(self, name, **kwargs):
        """
        Create a backup task

        Check the SEP Sesam REST API documentation for applicable parameters:
        https://wiki.sep.de/wiki/index.php/File:SEP_sesam-REST-API-V2-Jaglion.pdf
        """
        endpoint = "/sep/api/v2/backups/createTask"
        kwargs["name"] = name
        url = self._urlexpand(endpoint)
        response = requests.post(
            url=url, json=kwargs, headers=self.headers, verify=self.verify
        )
        self._process_error(response)
        data = response.json()
        log.debug("Got response:\n{}".format(pprint.pformat(data)))
        return data

    @_auth
    def backup_task_update(self, name, **kwargs):
        """
        Update a backup task

        Check the SEP Sesam REST API documentation for applicable parameters:
        https://wiki.sep.de/wiki/index.php/File:SEP_sesam-REST-API-V2-Jaglion.pdf
        """
        kwargs["name"] = name
        endpoint = "/sep/api/v2/backups/updateTask"
        url = self._urlexpand(endpoint)
        response = requests.post(
            url=url, json=kwargs, headers=self.headers, verify=self.verify
        )
        self._process_error(response)
        data = response.json()
        log.debug("Got response:\n{}".format(pprint.pformat(data)))
        return data

    @_auth
    def backup_task_delete(self, name, **kwargs):
        """
        Delete a backup task
        """
        endpoint = "/sep/api/v2/backups/{}/deleteTask".format(name)
        url = self._urlexpand(endpoint)
        response = requests.post(
            url=url, json=kwargs, headers=self.headers, verify=self.verify
        )
        self._process_error(response)
        data = response.json()
        log.debug("Got response:\n{}".format(pprint.pformat(data)))
        return data

    ### v2 BACKUP EVENTS HANDLING ###

    @_auth
    def backup_event_list(self):
        """
        List backup events
        """
        endpoint = "/sep/api/v2/backupevents"
        url = self._urlexpand(endpoint)
        response = requests.get(url=url, headers=self.headers, verify=self.verify)
        self._process_error(response)
        data = response.json()
        log.debug("Got response:\n{}".format(pprint.pformat(data)))
        return data

    @_auth
    def backup_event_get(self, id):
        """
        Get a backup event
        """
        endpoint = "/sep/api/v2/backupevents/{}".format(id)
        url = self._urlexpand(endpoint)
        response = requests.get(url=url, headers=self.headers, verify=self.verify)
        self._process_error(response)
        data = response.json()
        log.debug("Got response:\n{}".format(pprint.pformat(data)))
        return data

    @_auth
    def backup_event_find(self, **kwargs):
        """
        Find a backup event

        Check the SEP Sesam REST API documentation for applicable parameters:
        https://wiki.sep.de/wiki/index.php/File:SEP_sesam-REST-API-V2-Jaglion.pdf
        """
        endpoint = "/sep/api/v2/backupevents/find"
        url = self._urlexpand(endpoint)
        response = requests.post(
            url=url, json=kwargs, headers=self.headers, verify=self.verify
        )
        self._process_error(response)
        data = response.json()
        log.debug("Got response:\n{}".format(pprint.pformat(data)))
        if "name" in kwargs:
            return self._filter(data, **kwargs)
        return data

    @_auth
    def backup_event_create(self, object, **kwargs):
        """
        Create a backup event

        Check the SEP Sesam REST API documentation for applicable parameters:
        https://wiki.sep.de/wiki/index.php/File:SEP_sesam-REST-API-V2-Jaglion.pdf
        """
        endpoint = "/sep/api/v2/backupevents/create"
        kwargs["object"] = object
        if len(object) > 128:
            log.error("Object name has a maximum length of 32")
            raise Exception("Object name has a maximum length of 32")
        if len(kwargs.get("name", "")) > 255:
            log.error("Name has a maximum length of 32")
            raise Exception("Name has a maximum length of 32")
        if not self.session_id:
            self.login()
        url = self._urlexpand(endpoint)
        response = requests.post(
            url=url, json=kwargs, headers=self.headers, verify=self.verify
        )
        self._process_error(response)
        data = response.json()
        log.debug("Got response:\n{}".format(pprint.pformat(data)))
        return data

    @_auth
    def backup_event_update(self, id, **kwargs):
        """
        Update a backup event

        Check the SEP Sesam REST API documentation for applicable parameters:
        https://wiki.sep.de/wiki/index.php/File:SEP_sesam-REST-API-V2-Jaglion.pdf
        """
        kwargs["id"] = id
        endpoint = "/sep/api/v2/backupevents/update"
        url = self._urlexpand(endpoint)
        response = requests.post(
            url=url, json=kwargs, headers=self.headers, verify=self.verify
        )
        self._process_error(response)
        data = response.json()
        log.debug("Got response:\n{}".format(pprint.pformat(data)))
        return data

    @_auth
    def backup_event_delete(self, id):
        """
        Delete a backup event
        """
        endpoint = "/sep/api/v2/backupevents/delete"
        url = self._urlexpand(endpoint)
        # for delete, we need to provide the data as a string and not form / json encoded
        response = requests.post(
            url=url, data=str(id), headers=self.headers, verify=self.verify
        )
        self._process_error(response)
        data = response.json()
        log.debug("Got response:\n{}".format(pprint.pformat(data)))
        return data

    ### v2 BACKUP HANDLING ###

    @_auth
    def backup_list(self):
        """
        List all backups
        """
        endpoint = "/sep/api/v2/backups"
        url = self._urlexpand(endpoint)
        response = requests.get(url=url, headers=self.headers, verify=self.verify)
        self._process_error(response)
        data = response.json()
        log.debug("Got response:\n{}".format(pprint.pformat(data)))
        return data

    @_auth
    def backup_get(self, savesetId):
        """
        Get a backup
        """
        endpoint = "/sep/api/v2/backups/{}".format(savesetId)
        url = self._urlexpand(endpoint)
        response = requests.get(url=url, headers=self.headers, verify=self.verify)
        self._process_error(response)
        data = response.json()
        log.debug("Got response:\n{}".format(pprint.pformat(data)))
        return data

    @_auth
    def backup_find(self, **kwargs):
        """
        Find a backup
        """
        endpoint = "/sep/api/v2/backups/find"
        url = self._urlexpand(endpoint)
        response = requests.post(
            url=url, headers=self.headers, json=kwargs, verify=self.verify
        )
        self._process_error(response)
        data = response.json()
        log.debug("Got response:\n{}".format(pprint.pformat(data)))
        return data

    @_auth
    def backup_create(self, name, **kwargs):
        """
        Create a backup
        """
        endpoint = "/sep/api/v2/backups/create"
        url = self._urlexpand(endpoint)
        kwargs["name"] = name
        response = requests.post(
            url=url, headers=self.headers, json=kwargs, verify=self.verify
        )
        self._process_error(response)
        data = response.json()
        log.debug("Got response:\n{}".format(pprint.pformat(data)))
        return data

    @_auth
    def backup_update(self, **kwargs):
        """
        Update a backup
        """
        endpoint = "/sep/api/v2/backups/update"
        url = self._urlexpand(endpoint)
        response = requests.post(
            url=url, headers=self.headers, json=kwargs, verify=self.verify
        )
        self._process_error(response)
        data = response.json()
        log.debug("Got response:\n{}".format(pprint.pformat(data)))
        return data

    @_auth
    def backup_start(self, taskName, mediaPoolName, backupLevel="FULL", **kwargs):
        """
        Start a backup
        """
        endpoint = "/sep/api/v2/backups/start"
        url = self._urlexpand(endpoint)
        kwargs["taskName"] = taskName
        kwargs["mediaPoolName"] = mediaPoolName
        kwargs["backupLevel"] = backupLevel
        response = requests.post(
            url=url, json=[kwargs], headers=self.headers, verify=self.verify
        )
        self._process_error(response)
        data = response.json()
        log.debug("Got response:\n{}".format(pprint.pformat(data)))
        return data

    ### v2 MEDIA POOL HANDLING ###

    @_auth
    def media_pool_list(self):
        """
        List all media pools
        """
        endpoint = "/sep/api/v2/mediapools"
        url = self._urlexpand(endpoint)
        response = requests.get(url=url, headers=self.headers, verify=self.verify)
        self._process_error(response)
        data = response.json()
        log.debug("Got response:\n{}".format(pprint.pformat(data)))
        return data

    @_auth
    def media_pool_get(self, name):
        """
        Get a media pool
        """
        endpoint = "/sep/api/v2/mediapools/{}".format(name)
        url = self._urlexpand(endpoint)
        response = requests.get(url=url, headers=self.headers, verify=self.verify)
        self._process_error(response)
        data = response.json()
        log.debug("Got response:\n{}".format(pprint.pformat(data)))
        return data

    @_auth
    def media_pool_find(self, **kwargs):
        """
        Find a media pool. Based on list due to missing support in API v1
        """
        endpoint = "/sep/api/v2/mediapools/find"
        url = self._urlexpand(endpoint)
        response = requests.post(
            url=url, headers=self.headers, json=kwargs, verify=self.verify
        )
        self._process_error(response)
        data = response.json()
        log.debug("Got response:\n{}".format(pprint.pformat(data)))
        return data

    @_auth
    def media_pool_create(self, name, **kwargs):
        """
        Create a media pool
        """
        endpoint = "/sep/api/v2/mediapools/create"
        url = self._urlexpand(endpoint)
        kwargs["name"] = name
        response = requests.post(
            url=url, headers=self.headers, json=kwargs, verify=self.verify
        )
        self._process_error(response)
        data = response.json()
        log.debug("Got response:\n{}".format(pprint.pformat(data)))
        return data

    @_auth
    def media_pool_update(self, **kwargs):
        """
        Update a media pool
        """
        endpoint = "/sep/api/v2/mediapools/update"
        url = self._urlexpand(endpoint)
        response = requests.post(
            url=url, headers=self.headers, json=kwargs, verify=self.verify
        )
        self._process_error(response)
        data = response.json()
        log.debug("Got response:\n{}".format(pprint.pformat(data)))
        return data

    @_auth
    def media_pool_delete(self, name):
        """
        Delete a media pool
        """
        endpoint = "/sep/api/v2/mediapools/deleteByEntity"
        url = self._urlexpand(endpoint)
        response = requests.post(
            url=url, headers=self.headers, json={"name": name}, verify=self.verify
        )
        self._process_error(response)
        data = response.json()
        log.debug("Got response:\n{}".format(pprint.pformat(data)))
        return data

    ### v2 MEDIA HANDLING ###

    @_auth
    def media_list(self):
        """
        List all media
        """
        endpoint = "/sep/api/v2/media"
        url = self._urlexpand(endpoint)
        response = requests.get(url=url, headers=self.headers, verify=self.verify)
        self._process_error(response)
        data = response.json()
        log.debug("Got response:\n{}".format(pprint.pformat(data)))
        return data

    @_auth
    def media_get(self, name):
        """
        Get a media
        """
        endpoint = "/sep/api/v2/media/{}".format(name)
        url = self._urlexpand(endpoint)
        response = requests.get(url=url, headers=self.headers, verify=self.verify)
        self._process_error(response)
        data = response.json()
        log.debug("Got response:\n{}".format(pprint.pformat(data)))
        return data

    @_auth
    def media_find(self, **kwargs):
        """
        Find a media.
        """
        endpoint = "/sep/api/v2/media/find"
        url = self._urlexpand(endpoint)
        response = requests.post(
            url=url, headers=self.headers, json=kwargs, verify=self.verify
        )
        self._process_error(response)
        data = response.json()
        log.debug("Got response:\n{}".format(pprint.pformat(data)))
        return data

    @_auth
    def media_create(self, name, poolName, mediaType, **kwargs):
        """
        Create a media pool
        """
        endpoint = "/sep/api/v2/media/create"
        url = self._urlexpand(endpoint)
        kwargs["name"] = name
        kwargs["poolName"] = poolName
        kwargs["mediaType"] = mediaType
        response = requests.post(
            url=url, headers=self.headers, json=kwargs, verify=self.verify
        )
        self._process_error(response)
        data = response.json()
        log.debug("Got response:\n{}".format(pprint.pformat(data)))
        return data

    @_auth
    def media_update(self, **kwargs):
        """
        Update a media
        """
        endpoint = "/sep/api/v2/media/update"
        url = self._urlexpand(endpoint)
        response = requests.post(
            url=url, headers=self.headers, json=kwargs, verify=self.verify
        )
        self._process_error(response)
        data = response.json()
        log.debug("Got response:\n{}".format(pprint.pformat(data)))
        return data

    @_auth
    def media_delete(self, name, forceRemoveData=True, initialize=False):
        """
        Delete a media
        """
        endpoint = "/sep/api/v2/media/{}/deleteForced".format(name)
        url = self._urlexpand(endpoint)
        response = requests.post(
            url=url,
            headers=self.headers,
            json={"forceRemoveData": forceRemoveData, "initialize": initialize},
            verify=self.verify,
        )
        self._process_error(response)
        data = response.json()
        log.debug("Got response:\n{}".format(pprint.pformat(data)))
        return data

    ### v2 DRIVES HANDLING ###

    @_auth
    def drive_execute(self, id, action):
        """
        Execute an action on a drive
        """
        endpoint = "/sep/api/v2/drives/{}/execute".format(id)
        data = {"action": action}
        url = self._urlexpand(endpoint)
        response = requests.post(
            url=url, headers=self.headers, json=data, verify=self.verify
        )
        self._process_error(response)
        data = response.json()
        log.debug("Got response:\n{}".format(pprint.pformat(data)))
        return data

    ### v2 GROUP HANDLING ###

    def group_list(self):
        """
        List all groups
        """
        endpoint = "/sep/api/v2/groups"
        url = self._urlexpand(endpoint)
        response = requests.get(
            url=url, auth=(self.username, self.password), verify=self.verify
        )
        self._process_error(response)
        data = response.json()
        log.debug("Got response:\n{}".format(pprint.pformat(data)))
        return data

    def group_get(self, id):
        """
        Get a group
        """
        endpoint = f"/sep/api/v2/groups/{id}"
        url = self._urlexpand(endpoint)
        response = requests.get(
            url=url, auth=(self.username, self.password), verify=self.verify
        )
        self._process_error(response)
        data = response.json()
        log.debug("Got response:\n{}".format(pprint.pformat(data)))
        return data

    def group_find(self, **kwargs):
        """
        Find a group. Based on list due to missing support in API v1
        """
        return self._filter(self.group_list(), **kwargs)

    # API V2 (updated to api/v2)
    def group_create(self, id=None, **kwargs):
        """
        Create a new group
        """
        endpoint = "/sep/api/v2/groups/create"
        url = self._urlexpand(endpoint)
        if id:
            kwargs["id"] = id
        response = requests.post(
            url=url,
            auth=(self.username, self.password),
            json=kwargs,
            verify=self.verify,
        )
        self._process_error(response)
        data = response.json()
        log.debug("Got response:\n{}".format(pprint.pformat(data)))
        return data

    def group_update(self, id, **kwargs):
        """
        Update group. Roles can not be updated once the group is created.
        """
        endpoint = "/sep/api/v2/groups/update"
        url = self._urlexpand(endpoint)
        kwargs["id"] = id
        response = requests.post(
            url=url,
            auth=(self.username, self.password),
            json=kwargs,
            verify=self.verify,
        )
        self._process_error(response)
        data = response.json()
        log.debug("Got response:\n{}".format(pprint.pformat(data)))
        return data

    def group_delete(self, id):
        """
        Delete a group
        """
        endpoint = "/sep/api/v2/groups/delete"
        url = self._urlexpand(endpoint)
        response = requests.post(
            url=url,
            auth=(self.username, self.password),
            verify=self.verify,
            data=str(id),
        )
        self._process_error(response)
        data = response.json()
        log.debug("Got response:\n{}".format(pprint.pformat(data)))
        return data

    def group_get_roles(self, id):
        """
        List roles assigned to a group
        """
        endpoint = f"/sep/api/v2/groups/{id}/roles"
        url = self._urlexpand(endpoint)
        response = requests.get(
            url=url,
            auth=(self.username, self.password),
            verify=self.verify,
        )
        self._process_error(response)
        data = response.json()
        log.debug("Got response:\n{}".format(pprint.pformat(data)))
        return data

    ### v1 ROLE HANDLING ###

    def role_list(self):
        """
        List all roles
        """
        endpoint = "/sep/api/roles"
        url = self._urlexpand(endpoint)
        response = requests.get(
            url=url, auth=(self.username, self.password), verify=self.verify
        )
        self._process_error(response)
        data = response.json()
        log.debug("Got response:\n{}".format(pprint.pformat(data)))
        return data

    def role_find(self, **kwargs):
        """
        Find a role. Based on list due to missing support in API v1
        """
        return self._filter(self.role_list(), **kwargs)

    ### v1 ROLE RELATION HANDLING ###

    def role_relation_list(self):
        """
        List all roleRelations
        """
        endpoint = "/sep/api/roleRelations"
        url = self._urlexpand(endpoint)
        response = requests.get(
            url=url, auth=(self.username, self.password), verify=self.verify
        )
        self._process_error(response)
        data = response.json()
        log.debug("Got response:\n{}".format(pprint.pformat(data)))
        return data

    def role_relation_get(self, id):
        """
        Get a role relation
        """
        endpoint = "/sep/api/roleRelations/{}".format(id)
        url = self._urlexpand(endpoint)
        response = requests.get(
            url=url, auth=(self.username, self.password), verify=self.verify
        )
        self._process_error(response)
        data = response.json()
        log.debug("Got response:\n{}".format(pprint.pformat(data)))
        return data

    def role_relation_find(self, **kwargs):
        """
        Find a role relation. Based on list due to missing support in API v1
        """
        return self._filter(self.role_relation_list(), **kwargs)

    def role_relation_create(self, group_id, role_id, id=None):
        """
        Create a new role <> group relation
        """
        endpoint = "/sep/api/roleRelations"
        url = self._urlexpand(endpoint)
        data = {
            "groupId": group_id,
            "roleId": role_id,
        }
        if id:
            data["id"] = id
        response = requests.post(
            url=url, auth=(self.username, self.password), json=data, verify=self.verify
        )
        self._process_error(response)
        data = response.json()
        log.debug("Got response:\n{}".format(pprint.pformat(data)))
        return data

    def role_relation_update(self, id, group_id, role_id):
        """
        Update a role <> group relation.
        """
        self.role_relation_delete(id=id)
        # it looks like the delete command is async
        # since we do not reference the role relation id somewhere else, we just do not care
        return self.role_relation_create(group_id=group_id, role_id=role_id)

    def role_relation_delete(self, id):
        """
        Delete a role relation
        """
        endpoint = "/sep/api/roleRelations/{}/delete".format(id)
        url = self._urlexpand(endpoint)
        response = requests.get(
            url=url, auth=(self.username, self.password), verify=self.verify
        )
        self._process_error(response)
        data = response.json()
        log.debug("Got response:\n{}".format(pprint.pformat(data)))
        return data

    ### EXTERNAL GROUP HANDLING (updated to v2)

    # Updated to api/v2
    def external_group_list(self):
        """
        List all external groups
        """
        endpoint = "/sep/api/v2/externalgroups"
        url = self._urlexpand(endpoint)
        response = requests.get(
            url=url, auth=(self.username, self.password), verify=self.verify
        )
        self._process_error(response)
        data = response.json()
        log.debug("Got response:\n{}".format(pprint.pformat(data)))
        return data

    # Updated to api/v2
    def external_group_get(self, id):
        """
        Get an external group
        """
        endpoint = f"/sep/api/v2/externalgroups/{id}"
        url = self._urlexpand(endpoint)
        response = requests.get(
            url=url, auth=(self.username, self.password), verify=self.verify
        )
        self._process_error(response)
        data = response.json()
        log.debug("Got response:\n{}".format(pprint.pformat(data)))
        return data

    # Updated to api/v2
    def external_group_find(self, **kwargs):
        """
        Find an externalgroups by properties. Returns a list of external groups.

        :param id:                  The unique identifier of the groups object. Must not be null. (int)
        :param externalId:          The external name (i.e. the LDAP name) of the group. required (String)
        :param enabled:             True, if the external group should be enabled, false otherwise. required (bool)
        :param relation:            The list of relations to sesam user groups belonging to this external group. (String or int)
        :param type:                The type of the external group. Valid values are "NONE", "AD" and "LDAP".
        :param mtime:               The time at which the notification object was modified at last.
        :param usercomment:         A comment by the user about the external group.

        """
        endpoint = "/sep/api/v2/externalgroups/find"
        url = self._urlexpand(endpoint)
        data = {}
        for param in [
            "id",
            "externalId",
            "enabled",
            "relation",
            "type",
            "mtime",
            "usercomment",
        ]:
            if param in kwargs:
                data[param] = kwargs[param]
        response = requests.post(
            url=url, json=data, headers=self.headers, verify=self.verify
        )
        self._process_error(response)
        data = response.json()
        log.debug("Got response:\n{}".format(pprint.pformat(data)))
        return data

    # Updated to api/v2
    def external_group_create(self, **kwargs):
        """
        Create an external group
        """
        endpoint = "/sep/api/v2/externalgroups/create"
        url = self._urlexpand(endpoint)
        response = requests.post(
            url=url,
            auth=(self.username, self.password),
            json=kwargs,
            verify=self.verify,
        )
        self._process_error(response)
        data = response.json()
        log.debug("Got response:\n{}".format(pprint.pformat(data)))
        return data

    # Updated to api/v2
    def external_group_update(self, **kwargs):
        """
        Update an external group
        """
        endpoint = "/sep/api/v2/externalgroups/update"
        url = self._urlexpand(endpoint)
        if "externalId" in kwargs and "id" not in kwargs:
            external_groups = self.external_group_find(externalId=kwargs["externalId"])
            if len(external_groups) == 1:
                kwargs["id"] = external_groups[0]["id"]
            else:
                raise Exception(
                    f"Found {len(external_groups)} external groups with externalId={kwargs['externalId']}. Please provide a unique id instead."
                )
        response = requests.post(
            url=url,
            auth=(self.username, self.password),
            json=kwargs,
            verify=self.verify,
        )
        self._process_error(response)
        data = response.json()
        log.debug("Got response:\n{}".format(pprint.pformat(data)))
        return data

    def external_group_upsert(self, id, **kwargs):
        """
        Create/Update an external group
        """
        self.external_group_delete(id=id)
        return self.external_group_create(id=id, **kwargs)

    # Updated to api/v2
    def external_group_delete(self, id):
        """
        Delete an external group
        """
        endpoint = "/sep/api/v2/externalgroups/delete"
        url = self._urlexpand(endpoint)
        response = requests.post(
            url=url, auth=(self.username, self.password), json=id, verify=self.verify
        )
        self._process_error(response)
        data = response.json()
        log.debug("Got response:\n{}".format(pprint.pformat(data)))
        return data

    # Updated to api/v2
    def external_group_update_relations(self, groups: list, **kwargs):
        """
        Sets the sesam user groups associated to the given external group.
        """
        if "externalId" in kwargs and "id" not in kwargs:
            external_groups = self.external_group_find(externalId=kwargs["externalId"])
            if len(external_groups) == 1:
                kwargs["id"] = external_groups[0]["id"]
            else:
                raise Exception(
                    f"Found {len(external_groups)} external groups with externalId={kwargs['externalId']}. Please provide a unique id instead."
                )
        endpoint = f"/sep/api/v2/externalgroups/{kwargs['id']}/groups"
        url = self._urlexpand(endpoint)
        response = requests.post(
            url=url,
            auth=(self.username, self.password),
            json=[groups],
            verify=self.verify,
        )
        self._process_error(response)
        data = response.json()
        log.debug("Got response:\n{}".format(pprint.pformat(data)))
        return data

    # Updated to api/v2
    def external_group_get_relations(self, **kwargs):
        """
        Returns the sesam user groups associated to the given external group.
        """
        if "externalId" in kwargs and "id" not in kwargs:
            external_groups = self.external_group_find(externalId=kwargs["externalId"])
            if len(external_groups) == 1:
                kwargs["id"] = external_groups[0]["id"]
            else:
                raise Exception(
                    f"Found {len(external_groups)} external groups with externalId={kwargs['externalId']}. Please provide a unique id instead."
                )
        endpoint = f"/sep/api/v2/externalgroups/{kwargs['id']}/groups"
        url = self._urlexpand(endpoint)
        response = requests.get(
            url=url, auth=(self.username, self.password), verify=self.verify
        )
        self._process_error(response)
        data = response.json()
        log.debug("Got response:\n{}".format(pprint.pformat(data)))
        return data

    ### SCHEDULE HANDLING (updated to v2) ###

    def schedule_list(self):
        """
        List all schedules
        """
        endpoint = "/sep/api/v2/schedules"
        url = self._urlexpand(endpoint)
        response = requests.get(
            url=url, auth=(self.username, self.password), verify=self.verify
        )
        self._process_error(response)
        data = response.json()
        log.debug("Got response:\n{}".format(pprint.pformat(data)))
        return data

    def schedule_get(self, name):
        """
        Get a schedule
        """
        endpoint = "/sep/api/v2/schedules/{}".format(name)
        url = self._urlexpand(endpoint)
        response = requests.get(
            url=url, auth=(self.username, self.password), verify=self.verify
        )
        self._process_error(response)
        data = response.json()
        log.debug("Got response:\n{}".format(pprint.pformat(data)))
        return data

    def schedule_find(self, **kwargs):
        """
        Find a schedule
        """
        endpoint = "/sep/api/v2/schedules/find"
        url = self._urlexpand(endpoint)
        response = requests.post(
            url=url,
            auth=(self.username, self.password),
            json=kwargs,
            verify=self.verify,
        )
        self._process_error(response)
        data = response.json()
        log.debug("Got response:\n{}".format(pprint.pformat(data)))
        return data

    def schedule_create(self, name, **kwargs):
        """
        Create a schedule
        """
        endpoint = "/sep/api/v2/schedules/create"
        url = self._urlexpand(endpoint)
        kwargs["name"] = name
        response = requests.post(
            url=url,
            auth=(self.username, self.password),
            json=kwargs,
            verify=self.verify,
        )
        self._process_error(response)
        data = response.json()
        log.debug("Got response:\n{}".format(pprint.pformat(data)))
        return data

    def schedule_update(self, name, **kwargs):
        """
        Update a schedule
        """
        endpoint = "/sep/api/v2/schedules/update"
        kwargs["name"] = name
        url = self._urlexpand(endpoint)
        response = requests.post(
            url=url,
            auth=(self.username, self.password),
            json=kwargs,
            verify=self.verify,
        )
        self._process_error(response)
        data = response.json()
        log.debug("Got response:\n{}".format(pprint.pformat(data)))
        return data

    def schedule_delete(self, name):
        """
        Delete a schedule
        """
        endpoint = "/sep/api/v2/schedules/delete"
        url = self._urlexpand(endpoint)
        response = requests.post(
            url=url, auth=(self.username, self.password), json=name, verify=self.verify
        )
        self._process_error(response)
        data = response.json()
        log.debug("Got response:\n{}".format(pprint.pformat(data)))
        return data

    ### COMMAND HANDLING (updated to v2) ###

    def command_list(self):
        """
        List all commands
        """
        endpoint = "/sep/api/v2/commands"
        url = self._urlexpand(endpoint)
        response = requests.get(
            url=url, auth=(self.username, self.password), verify=self.verify
        )
        self._process_error(response)
        data = response.json()
        log.debug("Got response:\n{}".format(pprint.pformat(data)))
        return data

    def command_get(self, name):
        """
        Get a command
        """
        endpoint = "/sep/api/v2/commands/{}".format(name)
        url = self._urlexpand(endpoint)
        response = requests.get(
            url=url, auth=(self.username, self.password), verify=self.verify
        )
        self._process_error(response)
        data = response.json()
        log.debug("Got response:\n{}".format(pprint.pformat(data)))
        return data

    def command_find(self, **kwargs):
        """
        Find a command
        """
        endpoint = "/sep/api/v2/commands/find"
        url = self._urlexpand(endpoint)
        response = requests.post(
            url=url,
            auth=(self.username, self.password),
            json=kwargs,
            verify=self.verify,
        )
        self._process_error(response)
        data = response.json()
        log.debug("Got response:\n{}".format(pprint.pformat(data)))
        return data

    def command_create(self, **kwargs):
        """
        Create a command
        """
        endpoint = "/sep/api/v2/commands/create"
        url = self._urlexpand(endpoint)
        response = requests.post(
            url=url,
            auth=(self.username, self.password),
            json=kwargs,
            verify=self.verify,
        )
        self._process_error(response)
        data = response.json()
        log.debug("Got response:\n{}".format(pprint.pformat(data)))
        return data

    def command_update(self, name, command, **kwargs):
        """
        Update a command
        """
        endpoint = "/sep/api/v2/commands/update"
        kwargs["name"] = name
        kwargs["command"] = command
        url = self._urlexpand(endpoint)
        response = requests.post(
            url=url,
            auth=(self.username, self.password),
            json=kwargs,
            verify=self.verify,
        )
        self._process_error(response)
        data = response.json()
        log.debug("Got response:\n{}".format(pprint.pformat(data)))
        return data

    def command_delete(self, name):
        """
        Delete a command
        """
        endpoint = "/sep/api/v2/commands/delete"
        url = self._urlexpand(endpoint)
        response = requests.post(
            url=url, auth=(self.username, self.password), json=name, verify=self.verify
        )
        self._process_error(response)
        data = response.json()
        log.debug("Got response:\n{}".format(pprint.pformat(data)))
        return data

    ### COMMAND EVENT HANDLING (updated to v2) ###

    def command_event_list(self):
        """
        List all command events
        """
        endpoint = "/sep/api/v2/commandevents"
        url = self._urlexpand(endpoint)
        response = requests.get(
            url=url, auth=(self.username, self.password), verify=self.verify
        )
        self._process_error(response)
        data = response.json()
        log.debug("Got response:\n{}".format(pprint.pformat(data)))
        return data

    def command_event_get(self, id):
        """
        Get a command event
        """
        endpoint = "/sep/api/v2/commandevents/{}".format(id)
        url = self._urlexpand(endpoint)
        response = requests.get(
            url=url, auth=(self.username, self.password), verify=self.verify
        )
        self._process_error(response)
        data = response.json()
        log.debug("Got response:\n{}".format(pprint.pformat(data)))
        return data

    def command_event_find(self, **kwargs):
        """
        Find a command event
        """
        endpoint = "/sep/api/v2/commandevents/find"
        url = self._urlexpand(endpoint)
        response = requests.post(
            url=url,
            auth=(self.username, self.password),
            json=kwargs,
            verify=self.verify,
        )
        self._process_error(response)
        data = response.json()
        log.debug("Got response:\n{}".format(pprint.pformat(data)))
        return data

    def command_event_create(self, **kwargs):
        """
        Create a command event
        """
        endpoint = "/sep/api/v2/commandevents/create"
        url = self._urlexpand(endpoint)
        response = requests.post(
            url=url,
            auth=(self.username, self.password),
            json=kwargs,
            verify=self.verify,
        )
        self._process_error(response)
        data = response.json()
        log.debug("Got response:\n{}".format(pprint.pformat(data)))
        return data

    def command_event_update(self, id, name, clientId, **kwargs):
        """
        Update a command event
        """
        endpoint = "/sep/api/v2/commandevents/update"
        kwargs["id"] = id
        kwargs["name"] = name
        kwargs["clientId"] = clientId
        url = self._urlexpand(endpoint)
        response = requests.post(
            url=url,
            auth=(self.username, self.password),
            json=kwargs,
            verify=self.verify,
        )
        self._process_error(response)
        data = response.json()
        log.debug("Got response:\n{}".format(pprint.pformat(data)))
        return data

    def command_event_delete(self, id):
        """
        Delete a command event
        """
        endpoint = "/sep/api/v2/commandevents/delete"
        url = self._urlexpand(endpoint)
        response = requests.post(
            url=url, auth=(self.username, self.password), json=id, verify=self.verify
        )
        self._process_error(response)
        data = response.json()
        log.debug("Got response:\n{}".format(pprint.pformat(data)))
        return data

    ### DRIVE GROUPS (updated to v2) ###

    def drive_group_list(self):
        """
        List all drive groups
        """
        endpoint = "/sep/api/v2/drivegroups"
        url = self._urlexpand(endpoint)
        response = requests.get(
            url=url, auth=(self.username, self.password), verify=self.verify
        )
        self._process_error(response)
        data = response.json()
        log.debug("Got response:\n{}".format(pprint.pformat(data)))
        return data

    def drive_group_get(self, id=None, name=None):
        """
        Get a drive group
        """
        if name:
            id = self.drive_group_resolveDriveGroupToId(name)

        endpoint = "/sep/api/v2/drivegroups/{}".format(id)
        url = self._urlexpand(endpoint)
        response = requests.get(
            url=url, auth=(self.username, self.password), verify=self.verify
        )
        self._process_error(response)
        data = response.json()
        log.debug("Got response:\n{}".format(pprint.pformat(data)))
        return data

    def drive_group_find(self, **kwargs):
        """
        Find a drive group. Based on list due to missing support in API v1
        It is possible to find a drive group by name and id with drive_group_get()
        """
        return self._filter(self.drive_group_list(), **kwargs)

    def drive_group_resolveDriveGroupToId(self, name):
        endpoint = "/sep/api/v2/drivegroups/resolveDriveGroupToId/"
        url = self._urlexpand(endpoint)
        response = requests.post(
            url=url, auth=(self.username, self.password), json=name, verify=self.verify
        )
        self._process_error(response)
        data = response.json()
        log.debug("Got response:\n{}".format(pprint.pformat(data)))
        return data
