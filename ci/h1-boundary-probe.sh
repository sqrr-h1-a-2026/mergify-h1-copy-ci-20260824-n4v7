#!/usr/bin/env bash
set -euo pipefail
mkdir -p boundary-evidence
jq -n '{mode:"harmless-approved",network_writes_attempted:false}' > boundary-evidence/boundary-result.json
