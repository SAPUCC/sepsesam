## How to run tests
### Install sepsesam in development mode (you do not need to reinstall on changes)
> [!TIP]
> This step is already included in the Dockerfile
```sh
python3 -m pip install --editable ./
```

### Run tests
```sh
python3 -m unittest t/tests.py
```
