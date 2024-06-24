#!/bin/bash
python3 -m pip install -r /workspaces/sepsesam/requirements.txt
python3 -m pip install --editable /workspaces/sepsesam/
/opt/sesam/bin/sesam/sm_main start
