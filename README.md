# sepsesam
SEP Sesam Python API

**THIS PROJECT IS NOT ASSOCIATED WITH SEP IN ANY WAY**

SEP Homepage: https://www.sep.de/

This library is a wrapper for the v1 and v2 APIs of the SEP Sesam backup solution.
See: https://wiki.sep.de/wiki/index.php/4_4_3_Beefalo:Using_SEP_sesam_REST_API

Install over pip with
```bash
pip3 install sepsesam
```

Example:
```python
import pprint
import sepsesam.api

cred = {
    "url": "http://sesam.my.doamin:11401",
    "username": "Administrator",
    "password": "Abcd1234!"
}

data = {}

with sepsesam.api.Api(**cred) as api:
    data = api.location_list()

pprint.pprint(data)
```
