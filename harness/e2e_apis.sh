#!/bin/sh
# Live HTTP functional gate for Harness build validation.
# Hits mall-admin platform APIs only — login, docs, brands. No exploit payloads.
set -eu

BASE="${BASE_URL:-http://127.0.0.1:8080}"
BASE="${BASE%/}"
ADMIN_USER="${MALL_ADMIN_USER:-admin}"
# mall.sql 不再包含可用的口令散列（fail-closed）；口令必须由环境注入（无提交默认值）。
# 本脚本在登录前调用 document/sh/init-db-credentials.sh，用 MALL_ADMIN_PASS
# 的散列覆盖哨兵值，因此无需在流水线里单独执行播种步骤。
ADMIN_PASS="${MALL_ADMIN_PASS:-}"
if [ -z "$ADMIN_PASS" ]; then
  echo "ERROR: MALL_ADMIN_PASS is not set - export the admin password (no committed default exists)" >&2
  exit 1
fi

REPO_ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
SEED_SCRIPT="${REPO_ROOT}/document/sh/init-db-credentials.sh"

# 探测一个可用的 MySQL 主机：口令通过 MYSQL_PWD 传递，绝不出现在命令行上。
db_probe() {
  MYSQL_PWD="$db_pass" mysql \
    --host="$1" --port="$db_port" --user="$db_user" \
    --default-character-set=utf8mb4 --batch --skip-column-names \
    -e 'SELECT 1' "$db_name" >/dev/null 2>&1
}

# 复用 document/sh/init-db-credentials.sh 完成散列与 UPDATE（不重复实现哈希逻辑）。
# 该脚本要求 MALL_ADMIN_PASSWORD / MALL_MEMBER_PASSWORD，而流水线提供的是
# MALL_ADMIN_PASS，因此在这里做映射；e2e 不需要会员登录，会员口令使用一次性随机值。
seed_admin_credentials() {
  if [ ! -f "$SEED_SCRIPT" ]; then
    echo "ERROR: credential seeding script not found: ${SEED_SCRIPT}" >&2
    return 1
  fi
  if ! command -v mysql >/dev/null 2>&1; then
    echo "ERROR: mysql client not found - install default-mysql-client so the admin password can be seeded" >&2
    return 1
  fi
  if ! command -v bash >/dev/null 2>&1; then
    echo "ERROR: bash not found - ${SEED_SCRIPT} requires bash" >&2
    return 1
  fi
  if command -v python3 >/dev/null 2>&1 && python3 -c 'import bcrypt' >/dev/null 2>&1; then
    :
  elif command -v htpasswd >/dev/null 2>&1; then
    :
  else
    echo "ERROR: no BCrypt hashing tool available (python3 'bcrypt' module or htpasswd) - cannot seed the admin password; install python3-bcrypt (or apache2-utils) in the build step" >&2
    return 1
  fi

  db_user="${MYSQL_USER:-root}"
  db_port="${MYSQL_PORT:-3306}"
  db_name="${MYSQL_DATABASE:-mall}"
  db_pass="${MYSQL_PASSWORD:-${MYSQL_PWD:-}}"

  db_host=""
  for cand in "${MYSQL_HOST:-}" 127.0.0.1 mysql; do
    [ -n "$cand" ] || continue
    if db_probe "$cand"; then
      db_host="$cand"
      break
    fi
  done
  if [ -z "$db_host" ]; then
    echo "ERROR: no reachable MySQL for database '${db_name}' as user '${db_user}' (tried ${MYSQL_HOST:+${MYSQL_HOST}, }127.0.0.1, mysql on port ${db_port})" >&2
    return 1
  fi

  # 会员账号只需摆脱哨兵值，e2e 不使用；生成一次性随机口令，避免复用管理员口令。
  member_pass="${MALL_MEMBER_PASS:-}"
  if [ -z "$member_pass" ] && command -v python3 >/dev/null 2>&1; then
    member_pass=$(python3 -c 'import secrets; print(secrets.token_urlsafe(24))' 2>/dev/null) || member_pass=""
  fi
  if [ -z "$member_pass" ] && [ -r /dev/urandom ]; then
    member_pass=$(od -An -tx1 -N24 /dev/urandom 2>/dev/null | tr -d ' \n') || member_pass=""
  fi
  if [ -z "$member_pass" ]; then
    echo "ERROR: unable to generate an ephemeral ums_member password - refusing to seed" >&2
    return 1
  fi

  if ! MALL_ADMIN_PASSWORD="$ADMIN_PASS" \
    MALL_MEMBER_PASSWORD="$member_pass" \
    MYSQL_HOST="$db_host" MYSQL_PORT="$db_port" MYSQL_USER="$db_user" \
    MYSQL_DATABASE="$db_name" MYSQL_PASSWORD="$db_pass" \
    bash "$SEED_SCRIPT"; then
    echo "ERROR: ${SEED_SCRIPT} failed against ${db_host}:${db_port}/${db_name} - admin account still holds the locked sentinel hash" >&2
    return 1
  fi
  echo "==> seeded ums_admin/ums_member password hashes from the environment (${db_host}:${db_port}/${db_name})"
}

if ! seed_admin_credentials; then
  echo "ERROR: cannot seed the admin credential - aborting before login to avoid a misleading auth failure" >&2
  exit 1
fi

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
