import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "src"))


def load_json(path):
    with open(path) as f:
        return json.load(f)


def dump_json(path, obj):
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    with open(path, "w") as f:
        json.dump(obj, f, indent=1, default=str)


def fmt_path(path):
    from iamwatch.model import name_of
    parts = []
    for i, h in enumerate(path):
        if i == 0:
            parts.append(name_of(h["src"]))
        parts.append("--%s--> %s" % (h["technique"], name_of(h["dst"])))
    return " ".join(parts)
