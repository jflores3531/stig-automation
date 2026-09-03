"""Minimal stand-in for PyYAML on hosts where packages cannot be installed.

netauto.py only ever calls yaml.safe_load(). JSON is a subset of YAML 1.2, so
inventory.yaml is written as JSON here and the stdlib parser reads it. That
also means the same inventory file works unchanged anywhere real PyYAML is
installed, which is why this file ships with the repo rather than being typed
out on each locked-down host.

A yaml.py in the project root shadows an installed PyYAML for anything run
from here. That is harmless while inventory.yaml stays JSON, since JSON parses
under either. What it does break is a YAML-formatted inventory on a machine
that has PyYAML: this file gets the import, and json.load fails with a
JSONDecodeError naming the parser rather than the format - which reads like
broken tooling instead of a file in the wrong dialect. Keep the inventory as
JSON everywhere, or delete this file on hosts where real PyYAML exists.
"""

import json


def safe_load(stream):
    return json.load(stream)
