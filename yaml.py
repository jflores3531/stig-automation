"""Minimal stand-in for PyYAML on hosts where packages cannot be installed.

netauto.py only ever calls yaml.safe_load(). JSON is a subset of YAML 1.2, so
inventory.yaml is written as JSON here and the stdlib parser reads it. Delete
this file on any host that has real PyYAML installed - a yaml.py in the project
root shadows the installed package.
"""

import json


def safe_load(stream):
    return json.load(stream)
