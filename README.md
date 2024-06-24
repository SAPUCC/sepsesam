> [!IMPORTANT]  
> This project is not associated with [SEP](https://www.sep.de/) in any way

> [!NOTE]  
> Not all API endpoints offered by the SEP Sesam REST API (neither v1 nor v2) are implemented.
> Some additional, undocumented endpoints are used, which may be not supported by SEP or could even be removed by SEP without any further notice.

# sepsesam
SEP Sesam Python API

This library is a wrapper for the v1 and v2 APIs of the SEP Sesam backup solution.
See: https://wiki.sep.de/wiki/index.php/4_4_3_Beefalo:Using_SEP_sesam_REST_API

## Install
```bash
python3 -m pip install sepsesam
```

## Example usage
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

## Contributing
In case you find and bugs or if you have any extensions, please open an issue / pull
request.
