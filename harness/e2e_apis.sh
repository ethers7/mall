#!/bin/sh
# Live HTTP functional gate for Harness build validation.
# Hits mall-admin platform APIs only — login, docs, brands. No exploit payloads.
set -eu

BASE="${BASE_URL:-http://127.0.0.1:8080}"
BASE="${BASE%/}"
# NOTE: document/sql/mall.sql no longer ships a real/working bcrypt hash for
# any seeded ums_admin row (those hashes were rotated to a non-functional
# placeholder to remove committed crackable credentials from git, CWE-798).
# This gate therefore provisions its own throwaway admin account at runtime
# via the public /admin/register API using an env-supplied password instead
# of depending on the dump's fixture hash — see the "admin bootstrap" step
# below.
ADMIN_USER="${MALL_ADMIN_USER:-e2e_admin}"
ADMIN_PASS="${MALL_ADMIN_PASS:-e2e-local-only-changeit}"
OUTDIR="${E2E_JUNIT_DIR:-test-results}"
mkdir -p "$OUTDIR"
OUT="$OUTDIR/functional-junit.xml"
BODY="/tmp/mall-e2e-body"

fail=0
n=0
cases=""

record() {
  name="$1"
  ok="$2"
  detail="${3:-}"
  n=$((n + 1))
  if [ "$ok" = "1" ]; then
    echo "PASS $name $detail"
    cases="${cases}ok|$name|$detail
"
  else
    echo "FAIL $name $detail"
    fail=$((fail + 1))
    cases="${cases}fail|$name|$detail
"
  fi
}

code_of() {
  curl -sS -o "$BODY" -w "%{http_code}" "$@"
}

echo "==> e2e against ${BASE}"

sc=$(code_of "${BASE}/actuator/health")
record "actuator_health_200" "$([ "$sc" = "200" ] && echo 1 || echo 0)" "$sc"
if grep -q '"status"[[:space:]]*:[[:space:]]*"UP"' "$BODY" 2>/dev/null; then
  record "actuator_health_up" 1
else
  record "actuator_health_up" 0 "$(head -c 200 "$BODY" 2>/dev/null || true)"
fi

sc=$(code_of "${BASE}/v3/api-docs")
record "openapi_200" "$([ "$sc" = "200" ] && echo 1 || echo 0)" "$sc"
if grep -q '"openapi"' "$BODY" 2>/dev/null; then
  record "openapi_document" 1
else
  record "openapi_document" 0 "$(head -c 200 "$BODY" 2>/dev/null || true)"
fi

sc=$(code_of -L "${BASE}/swagger-ui/index.html")
record "swagger_ui_200" "$([ "$sc" = "200" ] && echo 1 || echo 0)" "$sc"

sc=$(code_of "${BASE}/brand/listAll")
if [ "$sc" = "401" ]; then
  record "brand_list_unauthorized" 1 "$sc"
elif grep -q '"code"[[:space:]]*:[[:space:]]*401' "$BODY"; then
  record "brand_list_unauthorized" 1 "http=${sc} body-code=401"
else
  record "brand_list_unauthorized" 0 "http=${sc} $(head -c 180 "$BODY")"
fi

echo "==> bootstrap: provisioning e2e admin account (best effort, idempotent)"
register_json=$(printf '{"username":"%s","password":"%s","nickName":"e2e","email":"e2e-admin@example.com"}' "$ADMIN_USER" "$ADMIN_PASS")
# Registration is best-effort: on a fresh DB it creates the account; on a
# reused DB the username already exists and the API returns a failure body,
# which is fine here since the account was created by an earlier run with
# the same env-supplied password. Either way, do not fail the gate on this
# step's HTTP status.
code_of -H "Content-Type: application/json" -d "$register_json" "${BASE}/admin/register" >/dev/null || true

login_json=$(printf '{"username":"%s","password":"%s"}' "$ADMIN_USER" "$ADMIN_PASS")
sc=$(code_of -H "Content-Type: application/json" -d "$login_json" "${BASE}/admin/login")
record "admin_login_200" "$([ "$sc" = "200" ] && echo 1 || echo 0)" "$sc"
if grep -q '"code"[[:space:]]*:[[:space:]]*200' "$BODY"; then
  record "admin_login_code_200" 1
else
  record "admin_login_code_200" 0 "$(head -c 300 "$BODY")"
fi

TOKEN=$(python3 - <<'PY'
import json, sys
try:
    doc = json.load(open("/tmp/mall-e2e-body", encoding="utf-8"))
except Exception:
    print("")
    sys.exit(0)
data = doc.get("data") or {}
print(data.get("token") or "")
PY
)
HEAD=$(python3 - <<'PY'
import json
try:
    doc = json.load(open("/tmp/mall-e2e-body", encoding="utf-8"))
except Exception:
    print("Bearer ")
    raise SystemExit(0)
data = doc.get("data") or {}
print(data.get("tokenHead") or "Bearer ")
PY
)

if [ -z "$TOKEN" ]; then
  record "admin_login_token" 0 "empty token"
else
  record "admin_login_token" 1
  AUTH="${HEAD}${TOKEN}"
  sc=$(code_of -H "Authorization: ${AUTH}" "${BASE}/brand/listAll")
  record "brand_list_authed_200" "$([ "$sc" = "200" ] && echo 1 || echo 0)" "$sc"
  if grep -q '"code"[[:space:]]*:[[:space:]]*200' "$BODY"; then
    record "brand_list_authed_code" 1
  else
    record "brand_list_authed_code" 0 "$(head -c 300 "$BODY")"
  fi

  sc=$(code_of -H "Authorization: ${AUTH}" "${BASE}/admin/list?pageNum=1&pageSize=5")
  record "admin_list_200" "$([ "$sc" = "200" ] && echo 1 || echo 0)" "$sc"
fi

{
  echo '<?xml version="1.0" encoding="UTF-8"?>'
  echo "<testsuite name=\"mall_admin_live_http\" tests=\"${n}\" failures=\"${fail}\">"
  printf '%s' "$cases" | while IFS='|' read -r status name detail; do
    [ -z "${status:-}" ] && continue
    echo "  <testcase classname=\"mall.live\" name=\"${name}\">"
    if [ "$status" = "fail" ]; then
      printf '    <failure message="%s"/>\n' "$(printf '%s' "$detail" | tr -d '\n' | sed 's/&/\&amp;/g; s/"/\&quot;/g; s/</\&lt;/g')"
    fi
    echo "  </testcase>"
  done
  echo "</testsuite>"
} >"$OUT"

if [ "$fail" -ne 0 ]; then
  echo "FAILED ${fail}/${n}  junit=${OUT}"
  exit 1
fi
echo "functional_ok  ${n} tests  junit=${OUT}"
