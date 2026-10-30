import os
import subprocess
import tempfile

import core.firewall as firewall

TEST_IP = "203.0.113.77"


def kernel_ruleset(backend):
    if backend == "nft":
        cmd = ["nft", "list", "ruleset"]
    else:
        cmd = ["iptables-save"]
    return subprocess.run(cmd, check=True, capture_output=True, text=True).stdout


def main():
    backend = os.environ["SENTINEL_FIREWALL_BACKEND"]
    firewall.ROOT = tempfile.mkdtemp(prefix="sentinel-fw-")
    firewall.FIREWALL_DRY_RUN = False
    firewall.FIREWALL_BACKEND = backend

    rule = firewall.add_block(TEST_IP, ttl=30, reason=f"{backend}-integration")
    if not rule.get("applied"):
        raise SystemExit(f"{backend} add_block did not apply: {rule.get('apply_output')}")
    # blocking twice must not duplicate kernel rules
    firewall.add_block(TEST_IP, ttl=60, reason=f"{backend}-integration")

    ruleset = kernel_ruleset(backend)
    if backend == "nft":
        for needed in ("hook input", "hook forward", "ip saddr @blacklist drop", TEST_IP):
            if needed not in ruleset:
                raise SystemExit(f"nft ruleset missing {needed!r}:\n{ruleset}")
    else:
        if ruleset.count(TEST_IP) != 3:
            raise SystemExit(f"expected 3 iptables rules for {TEST_IP}:\n{ruleset}")

    removed = firewall.remove_block(TEST_IP)
    if removed.get("removed") != 1:
        raise SystemExit(f"{backend} remove_block failed: {removed}")
    ruleset = kernel_ruleset(backend)
    if TEST_IP in ruleset:
        raise SystemExit(f"{backend} rule still present after unblock:\n{ruleset}")

    firewall.add_block(TEST_IP, ttl=30, reason=f"{backend}-rollback")
    firewall.rollback_blocks("integration")
    ruleset = kernel_ruleset(backend)
    if "SentinelEdgeAI" in ruleset or "table inet sentinel" in ruleset:
        raise SystemExit(f"{backend} rules still present after rollback:\n{ruleset}")

    print(f"{backend}: PASS")


if __name__ == "__main__":
    main()
