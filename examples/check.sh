#!/usr/bin/env bash
# Ask PATIENCE before acting. Usage: ./examples/check.sh "issue refunds to 12 members totaling $1,800"
URL="${PATIENCE_URL:-http://127.0.0.1:8765}"
AUTH=(); [ -n "$PATIENCE_API_TOKEN" ] && AUTH=(-H "Authorization: Bearer $PATIENCE_API_TOKEN")
ACTION="${1:-Issue refunds to 12 members totaling \$1,800.}"
BODY=$(python3 -c 'import json,sys;print(json.dumps({"action":sys.argv[1],"requester":"curl-example"}))' "$ACTION")
RESP=$(curl -s "${AUTH[@]}" -H "Content-Type: application/json" -d "$BODY" "$URL/v1/check")
echo "$RESP"
RID=$(echo "$RESP" | python3 -c 'import json,sys;print(json.load(sys.stdin)["request_id"])')
echo "Poll status:"; curl -s "${AUTH[@]}" "$URL/v1/requests/$RID"; echo
# A human approver (only if PATIENCE_APPROVER_TOKEN is set on the server):
# curl -s -X POST "${AUTH[@]}" -H "X-Approver-Token: $PATIENCE_APPROVER_TOKEN" "$URL/v1/requests/$RID/approve"
