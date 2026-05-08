import os
import tempfile

import core.firewall as firewall


def main():
    backend = os.environ["SENTINEL_FIREWALL_BACKEND"]
    firewall.ROOT = tempfile.mkdtemp(prefix="sentinel-fw-")
    firewall.FIREWALL_DRY_RUN = False
    firewall.FIREWALL_BACKEND = backend

    rule = firewall.add_block("203.0.113.77", ttl=30, reason=f"{backend}-integration")
    if not rule.get("applied"):
        raise SystemExit(f"{backend} add_block did not apply: {rule.get('apply_output')}")

    removed = firewall.remove_block("203.0.113.77")
    if removed.get("removed") != 1:
        raise SystemExit(f"{backend} remove_block failed: {removed}")

    print(f"{backend}: PASS")


if __name__ == "__main__":
    main()
