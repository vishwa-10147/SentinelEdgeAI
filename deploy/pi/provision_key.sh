#!/usr/bin/env bash
# Up to v2.16 this installed the shared HMAC model signing key. Since v2.17 the release model is
# signed with Ed25519 and verified with the public key shipped in the package (pinned in
# /etc/sentinel/model_signing.pub at the first install), so devices need no secret.
# Kept so older install instructions still run; it does nothing.
echo "provision_key.sh: no longer needed (the release model is verified with a public key); nothing to do"
exit 0
