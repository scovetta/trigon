#!/bin/bash
./scripts/rebuild-and-attest.sh "$1" --key ~/.trigon/signing.key --egress mirror-only --image localhost/trigon-base@sha256:7cdddce4868e731b4e441d8d5f836b97f1e653e8f3cae212a24bb305cf2deec2
