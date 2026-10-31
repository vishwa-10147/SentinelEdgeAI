"""Atomic JSON file writes that also work through symlinks into a read-only release directory."""
import json
import os


def write_json_atomic(path, data, **kwargs):
    """Replace `path` with `data` so readers never see a half-written file.

    On a device the state files in the release directory are symlinks into /var/lib/sentinel,
    and the release directory is read-only: the temporary file goes next to the real target.
    """
    target = os.path.realpath(path)
    tmp = target + ".tmp"
    with open(tmp, "w") as f:
        json.dump(data, f, **kwargs)
    os.replace(tmp, target)
