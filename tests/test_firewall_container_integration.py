import os
import shutil
import subprocess

import pytest


RUN_CONTAINER_TESTS = os.environ.get("SENTINEL_RUN_FIREWALL_CONTAINER_TESTS") == "1"


@pytest.mark.skipif(not RUN_CONTAINER_TESTS, reason="set SENTINEL_RUN_FIREWALL_CONTAINER_TESTS=1 to run Docker firewall integration tests")
@pytest.mark.parametrize("backend", ["nft", "iptables"])
def test_firewall_backend_in_container(backend):
    docker = shutil.which("docker")
    if not docker:
        pytest.skip("docker command not available")

    image = "sentineledgeai-firewall-itest:latest"
    subprocess.run(
        [docker, "build", "-f", "tests/firewall_container/Dockerfile", "-t", image, "."],
        check=True,
    )
    subprocess.run(
        [
            docker,
            "run",
            "--rm",
            "--cap-add",
            "NET_ADMIN",
            "--network",
            "none",
            "-e",
            f"SENTINEL_FIREWALL_BACKEND={backend}",
            image,
        ],
        check=True,
    )
