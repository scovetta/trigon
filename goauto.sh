#!/bin/bash
./scripts/rebuild-and-attest.sh "$1" --key ~/.trigon/signing.key --egress mirror-only --image auto
