# sepsesam
SEP Sesam Python API

**THIS PROJECT IS NOT ASSOCIATED WITH SEP IN ANY WAY**

SEP Homepage: https://www.sep.de/

This library is a wrapper for the v1 and v2 APIs of the SEP Sesam backup solution.
See: https://wiki.sep.de/wiki/index.php/4_4_3_Beefalo:Using_SEP_sesam_REST_API

Install with pip
```bash
python3 -m pip install sepsesam
```

Example:
```python
import pprint
import sepsesam.api

cred = {
    "url": "http://sesam.my.domain:11401",
    "username": "Administrator",
    "password": "Abcd1234!"
}

data = {}

with sepsesam.api.Api(**cred) as api:
    data = api.location_list()

pprint.pprint(data)
```

**ATTENTION**: This project does not implement all API endpoints offered by the 
SEP Sesam REST API (neither v1 nor v2) but also includes ones that are undocumented
and therefore may be not supported by SEP or could even be removed without any
further notice.

Use this library at your own risk.

In case you find and bugs or if you have any extensions, please open an issue / pull
request.
