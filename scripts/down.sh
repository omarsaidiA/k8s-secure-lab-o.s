#!/usr/bin/env bash
# Delete the cluster and everything in it. The encryption key file is kept for the next run.
set -euo pipefail
kind delete cluster --name secure-lab
