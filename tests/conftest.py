import os
import pathlib
import sys


def pytest_sessionstart():

    # Build fake Splunk env
    pathlib.Path("SPLUNK_HOME").mkdir(parents=True, exist_ok=True)

    os.environ["SPLUNK_HOME"] = "SPLUNK_HOME"

    pathlib.Path("SPLUNK_HOME/bin").mkdir(parents=True, exist_ok=True)

    with open("SPLUNK_HOME/bin/splunk", "w") as f:
        f.write("#! /bin/sh")

    os.chmod("SPLUNK_HOME/bin/splunk", 0o744)

    pathlib.Path("SPLUNK_HOME/var/log/splunk").mkdir(parents=True, exist_ok=True)

    # Add bin directory for imports
    bindir = os.getcwd() + "/../package/bin/"
    sys.path.insert(1, bindir)
