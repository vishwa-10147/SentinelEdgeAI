import os
import subprocess
import tempfile

import core.firewall as firewall

TEST_IPS = ("203.0.113.77", "2001:db8::77")


def kernel_ruleset(backend):
    if backend == "nft":
        cmds = [["nft", "list", "ruleset"]]
    else:
        cmds = [["iptables-save"], ["ip6tables-save"]]
    return "".join(subprocess.run(cmd, check=True, capture_output=True, text=True).stdout for cmd in cmds)


def main():
    backend = os.environ["SENTINEL_FIREWALL_BACKEND"]
    firewall.ROOT = tempfile.mkdtemp(prefix="sentinel-fw-")
    firewall.FIREWALL_DRY_RUN = False
    firewall.FIREWALL_BACKEND = backend

    for ip in TEST_IPS:
        rule = firewall.add_block(ip, ttl=30, reason=f"{backend}-integration")
        if not rule.get("applied"):
            raise SystemExit(f"{backend} add_block({ip}) did not apply: {rule.get('apply_output')}")
        # blocking twice must not duplicate kernel rules
        firewall.add_block(ip, ttl=60, reason=f"{backend}-integration")

    ruleset = kernel_ruleset(backend)
    if backend == "nft":
        needed = ("hook input", "hook forward", "ip saddr @blacklist drop",
                  "ip6 saddr @blacklist6 drop", *TEST_IPS)
        for item in needed:
            if item not in ruleset:
                raise SystemExit(f"nft ruleset missing {item!r}:\n{ruleset}")
    else:
        for ip in TEST_IPS:
            if ruleset.count(ip) != 3:
                raise SystemExit(f"expected 3 rules for {ip}:\n{ruleset}")

    for ip in TEST_IPS:
        removed = firewall.remove_block(ip)
        if removed.get("removed") != 1:
            raise SystemExit(f"{backend} remove_block({ip}) failed: {removed}")
    ruleset = kernel_ruleset(backend)
    for ip in TEST_IPS:
        if ip in ruleset:
            raise SystemExit(f"{backend} rule for {ip} still present after unblock:\n{ruleset}")

    for ip in TEST_IPS:
        firewall.add_block(ip, ttl=30, reason=f"{backend}-rollback")
    firewall.rollback_blocks("integration")
    ruleset = kernel_ruleset(backend)
    if "SentinelEdgeAI" in ruleset or "table inet sentinel" in ruleset:
        raise SystemExit(f"{backend} rules still present after rollback:\n{ruleset}")

    print(f"{backend}: PASS (IPv4 and IPv6)")


if __name__ == "__main__":
    main()
