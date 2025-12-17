#!/usr/bin/env bash
set -euo pipefail

BASE_URL="${BASE_URL:-http://127.0.0.1:5000}"
USERNAME="${USERNAME:-tester_$(date +%s)}"
PASSWORD="${PASSWORD:-P@ssw0rd!}"

echo "Using BASE_URL=${BASE_URL}"
echo "Using USERNAME=${USERNAME}"

echo "1) Health check"
curl -sS "${BASE_URL}/healthz" | jq . || true
echo

echo "2) Access protected endpoint without JWT (should be 401)"
status_code=$(curl -s -o /dev/null -w "%{http_code}" "${BASE_URL}/api/data")
echo "Status: ${status_code}"
if [[ "${status_code}" != "401" ]]; then
  echo "Expected 401 for unauthenticated request" >&2
  exit 1
fi
echo

echo "3) Register user (201 if new, 409 if already exists)"
register_status=$(curl -s -o /dev/null -w "%{http_code}" \
  -X POST "${BASE_URL}/auth/register" \
  -H "Content-Type: application/json" \
  -d "{\"username\": \"${USERNAME}\", \"password\": \"${PASSWORD}\"}")
echo "Status: ${register_status}"
if [[ "${register_status}" != "201" && "${register_status}" != "409" ]]; then
  echo "Registration failed with status ${register_status}" >&2
  exit 1
fi
echo

echo "4) Login and grab JWT"
login_response=$(curl -sS -X POST "${BASE_URL}/auth/login" \
  -H "Content-Type: application/json" \
  -d "{\"username\": \"${USERNAME}\", \"password\": \"${PASSWORD}\"}")
echo "Login response: ${login_response}"
token=$(python3 - <<'PY' "${login_response}"
import json, sys
try:
    data = json.loads(sys.argv[1])
    print(data["access_token"])
except Exception as exc:
    raise SystemExit(f"Failed to parse access_token: {exc}")
PY
)
echo "JWT acquired."
echo

echo "5) Access protected endpoint with JWT (should be 200)"
curl -sS "${BASE_URL}/api/data" -H "Authorization: Bearer ${token}" | jq . || true
echo

echo "6) Create note with JWT (should be 201)"
curl -sS -X POST "${BASE_URL}/api/notes" \
  -H "Authorization: Bearer ${token}" \
  -H "Content-Type: application/json" \
  -d '{"body": "hello from curl smoke test"}' | jq . || true
echo

echo "7) List notes with JWT"
curl -sS "${BASE_URL}/api/notes" -H "Authorization: Bearer ${token}" | jq . || true
echo

echo "8) Access protected endpoint with invalid JWT (should be 401)"
curl -sS "${BASE_URL}/api/data" -H "Authorization: Bearer invalid-jwt-token" | jq . || true
echo

echo "All steps completed."
