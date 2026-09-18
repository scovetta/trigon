#!/bin/bash
./scripts/rebuild-and-attest.sh "$1" --key ~/.trigon/signing.key --egress mirror-only --image localhost/trigon-python:latest@sha256:fdaef2ba9caea897c7952825ba15e33bb4ce511ad5aba512e04b7669be2091df  
