# -*- coding: utf-8 -*-
"""

--- SEP Sesam API ---

"""

# import python libraries
import logging
import pprint
import json.decoder

# import third-party libraries
import requests

# globals
# TODO: unclear if this is actually required
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

log = logging.getLogger("sepsesam")


class SEPSesamAPIError(Exception):
    """ error from the API """
    
    def __init__(self, status_code, error, message, parameter, type, url):
        self.status_code = status_code
        self.error = error
        self.message = message
        self.parameter = parameter
        self.type = type
        self.url = url


class SEPSeasam:

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
        self.logged_in = False
        self.verify = verify
        level = logging.getLevelName(log_level)
        log.setLevel(level)

    def __process_error(self, response):
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
            # could not retrieve error description
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

    def login(self, type_="WEB"):
        """
        Logon to the SEP sesam v2 API
        """
        log.debug("Running function")
        endpoint = "sep/api/v2/auth/login"
        data = {
            "username": self.username,
            "secret": self.password,
            "type": type_
        }
        url = "{}{}".format(
            self.url if self.url[-1] == "/" else self.url + "/",
            endpoint if endpoint[0] != "/" else endpoint[1:]
        )
        response = requests.post(url=url, data=data, verify=self.verify)
        self.__process_errors(response)
        resp_data = response.json()
        log.debug("Got response:\n{}".format(resp_data))
        return True

    def get_server_info():
        """
        Retrieve server information
        """
        endpoint = "/sep/api/v2/server/info"
        # GET
        pass

### client handling

def client_list():
    endpoint = "/sep/api/v2/clients"
    # GET
    pass

def client_get(_id):
    endpoint = "/sep/api/v2/clients/{}".format(_id)
    # GET
    pass
    
def client_find():
    endpoint = "/sep/api/v2/clients/find"
    # POST
    pass

def client_create():
    endpoint = "/sep/api/v2/clients/create"
    # POST
    pass

def client_update():
    endpoint = "/sep/api/v2/clients/update"
    # POST
    pass

def client_delete():
    endpoint = "/sep/api/v2/clients/delete"
    # POST
    pass
    
### location handling

def location_list():
    endpoint = "/sep/api/v2/locations"
    # GET
    pass
    
def location_get(id_):
    endpoint = "/sep/api/v2/locations/{}".format(id_)
    # GET
    pass

def location_find():
    endpoint = "/sep/api/v2/locations/find/"
    # POST
    pass

def location_create():
    endpoint = "/sep/api/v2/locations/create"
    # POST
    pass    

def location_update():
    endpoint = "/sep/api/v2/locations/update"
    # POST
    pass       

def location_delete():
    endpoint = "/sep/api/v2/locations/delete"
    # POST
    pass  

### Datastore handling

def datastore_list():
    endpoint = "/sep/api/v2/datastores"
    # GET
    pass

def datastore_get(name):
    endpoint = "/sep/api/v2/datastores/{}".format(name)
    # GET
    pass

def datastore_find():
    endpoint = "/sep/api/v2/datastores/find"
    # POST
    pass

def datastore_create():
    endpoint = "/sep/api/v2/datastores/create"
    # POST
    pass

def datastore_update():
    endpoint = "/sep/api/v2/datastores/update"
    # POST
    pass

def datastore_delete():
    endpoint = "/sep/api/v2/datastores/delete"
    # POST
    pass

def datastore_drives_list():
    endpoint = "/sep/api/v2/datastores/<name>/drives"
    # GET
    pass

def datastore_drives_find():
    endpoint = "/sep/api/v2/datastores/<name>/drives"
    # POST
    pass

def datastore_drivegroups_list():
    endpoint = "/sep/api/v2/datastores/<name>/driveGroups"
    # GET
    pass

def datastore_drivegroups_find():
    endpoint = "/sep/api/v2/datastores/<name>/driveGroups"
    # POST
    pass

def datastore_mediapools_list():
    endpoint = "/sep/api/v2/datastores/<name>/mediaPools"
    # GET
    pass

def datastore_mediapools_find():
    endpoint = "/sep/api/v2/datastores/<name>/mediaPools"
    # POST
    pass

### ACL handling

def acl_list():
    endpoint = "/sep/api/v2/acls"
    # GET
    pass
    
def acl_get(id_):
    endpoint = "/sep/api/v2/acls/{}".format(id_)
    # GET
    pass

def acl_find():
    endpoint = "/sep/api/v2/acls/find"
    # POST
    pass
    
def acl_create(id_):
    endpoint = "/sep/api/v2/acls/create"
    # POST
    pass
    
def acl_update(id_):
    endpoint = "/sep/api/v2/acls/update"
    # POST
    pass
    
def acl_delete(id_):
    endpoint = "/sep/api/v2/acls/delete"
    # POST
    pass
