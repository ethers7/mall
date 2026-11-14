#!/bin/sh
# Apply env-supplied passwords to the seed accounts at runtime.
# document/sql/mall.sql ships with NULL password columns (fail-closed: nobody can log in
# until a password is applied). Run this after importing the dump and before e2e_apis.sh.
#
# Required env:  MALL_ADMIN_PASS            password for ums_admin user MALL_ADMIN_USER (default: admin)
# Optional env:  MALL_MEMBER_USER/PASS      password for one ums_member user
#                MALL_DB_HOST (127.0.0.1) MALL_DB_PORT (3306) MALL_DB_NAME (mall)
#                MALL_DB_USER (root) MYSQL_PWD (database password, read by the mysql client)
# Needs: mysql client and either python3 "bcrypt" or htpasswd (apache2-utils).
set -eu

: "${MALL_ADMIN_PASS:?MALL_ADMIN_PASS must be supplied via the environment}"
ADMIN_USER="${MALL_ADMIN_USER:-admin}"
DB_HOST="${MALL_DB_HOST:-127.0.0.1}"
DB_PORT="${MALL_DB_PORT:-3306}"
DB_NAME="${MALL_DB_NAME:-mall}"
DB_USER="${MALL_DB_USER:-root}"

check_name() {
  case "$1" in
    *[!A-Za-z0-9_]*|"") echo "invalid username: only [A-Za-z0-9_] allowed" >&2; exit 2 ;;
  esac
}

# Prints a $2a$ bcrypt hash of the password in env var named by $1 (never put on argv).
bcrypt_of() {
  if PW_VAR="$1" python3 -c 'import bcrypt' >/dev/null 2>&1; then
    PW_VAR="$1" python3 -c '
import os, bcrypt
pw = os.environ[os.environ["PW_VAR"]].encode()
print(bcrypt.hashpw(pw, bcrypt.gensalt(10, prefix=b"2a")).decode())'
  elif command -v htpasswd >/dev/null 2>&1; then
    eval "pw=\${$1}"
    printf '%s' "$pw" | htpasswd -niBC 10 x | cut -d: -f2 | sed 's/^\$2y\$/$2a$/'
  else
    echo "need python3 bcrypt or htpasswd to hash passwords" >&2
    exit 3
  fi
}

run_sql() {
  mysql -h "$DB_HOST" -P "$DB_PORT" -u "$DB_USER" "$DB_NAME" -e "$1"
}

check_name "$ADMIN_USER"
hash=$(bcrypt_of MALL_ADMIN_PASS)
run_sql "UPDATE ums_admin SET password='${hash}' WHERE username='${ADMIN_USER}';"
echo "applied admin password for ${ADMIN_USER}"

if [ -n "${MALL_MEMBER_USER:-}" ] && [ -n "${MALL_MEMBER_PASS:-}" ]; then
  check_name "$MALL_MEMBER_USER"
  hash=$(bcrypt_of MALL_MEMBER_PASS)
  run_sql "UPDATE ums_member SET password='${hash}' WHERE username='${MALL_MEMBER_USER}';"
  echo "applied member password for ${MALL_MEMBER_USER}"
fi
