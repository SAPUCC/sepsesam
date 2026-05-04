import sepsesam.api

""" Configure before executing unittest suite """

cred = {
    "url": "https://localhost:11401",
    "username": "Administrator",
    "password": "sesam",
}

api = sepsesam.api.Api(**cred, verify=False)