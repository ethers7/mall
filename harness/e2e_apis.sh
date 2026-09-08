#!/bin/sh
# Live HTTP functional gate for Harness build validation.
# Hits mall-admin platform APIs only — login, docs, brands. No exploit payloads.
set -eu

BASE="${BASE_URL:-http://127.0.0.1:8080}"
BASE="${BASE%/}"
ADMIN_USER="${MALL_ADMIN_USER:-admin}"
# No default password: document/sql/mall.sql ships no password hashes, so the
# admin credential is supplied at runtime (env) and applied either by this script
# (mysql path) or by mall-admin's startup bootstrap — see the guard below.
ADMIN_PASS="${MALL_ADMIN_PASS:-}"
OUTDIR="${E2E_JUNIT_DIR:-test-results}"
REPO_ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
SEED_SCRIPT="${REPO_ROOT}/document/sh/seed-credentials.sh"

gen_password() {
  if command -v openssl >/dev/null 2>&1; then
    openssl rand -hex 18
  else
    od -An -tx1 -N18 /dev/urandom | tr -d ' \n'
  fi
}

can_seed() {
  [ -n "${MALL_DB_PASSWORD:-}" ] &&
    [ -f "$SEED_SCRIPT" ] &&
    command -v bash >/dev/null 2>&1 &&
    command -v mysql >/dev/null 2>&1
}

# The seeded accounts are locked ('!LOCKED' placeholder) until a password is
# applied at runtime. Two runtime paths exist, in this order:
#   1. mysql path (can_seed): MALL_DB_PASSWORD + mysql client available, so this
#      script can apply the password itself via document/sh/seed-credentials.sh.
#      Only this path can invent an ephemeral password, because it also writes it.
#   2. application path: when MALL_ADMIN_PASS is exported, mall-admin's
#      AdminPasswordBootstrapRunner applies it to the still-locked account at
#      startup (BCrypt, same encoder as the login path). Nothing to do here — the
#      app must have been started with the same MALL_ADMIN_PASS/MALL_ADMIN_USER,
#      and the login checks below stay real assertions: if the bootstrap did not
#      run, login fails and this gate fails.
# Never fall back to a committed value, and never skip the login assertions.
if can_seed; then
  if [ -z "$ADMIN_PASS" ]; then
    ADMIN_PASS=$(gen_password)
    echo "==> MALL_ADMIN_PASS unset: using an ephemeral password for ${ADMIN_USER}"
  fi
  echo "==> seeding ${ADMIN_USER} credential via document/sh/seed-credentials.sh"
  MALL_ADMIN_USER="$ADMIN_USER" MALL_ADMIN_PASS="$ADMIN_PASS" bash "$SEED_SCRIPT"
elif [ -n "$ADMIN_PASS" ]; then
  echo "==> mysql seeding path unavailable: relying on mall-admin startup bootstrap for ${ADMIN_USER}"
else
  echo "MALL_ADMIN_PASS is required: document/sql/mall.sql contains no password hashes," >&2
  echo "so accounts are locked until a password is applied at runtime. Either export" >&2
  echo "MALL_ADMIN_PASS (mall-admin initialises the locked account with it on startup," >&2
  echo "and it is also used to log in here), or provide MALL_DB_PASSWORD plus the mysql" >&2
  echo "client so this script can run document/sh/seed-credentials.sh itself." >&2
  exit 2
fi
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
