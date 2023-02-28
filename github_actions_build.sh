#!/bin/bash
set -xe

# pip install -r tests/requirements.txt splunk-add-on-ucc-framework splunk-packaging-toolkit

ruff package/bin/*.py tests/*.py --ignore=F401,E501,E402

cd tests; pytest; cd ..

cd tests; pytest -m live; cd ..

pip-audit -S

bandit package/bin/*.py

pycodestyle package/bin/*.py --ignore=E501,W503,W504

pylint --fail-under 5 package/bin/*.py tests/*.py

ucc-gen build && slim package output/TA-MS-AAD && ls -la *.gz && sha1sum *.gz

