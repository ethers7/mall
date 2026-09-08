#!/usr/bin/env bash
# 为 document/sql/mall.sql 导入的账号设置登录密码。
# mall.sql 中不再保存任何密码哈希（硬编码凭证问题，CWE-798），导入后所有账号的
# password 字段均为占位符 '!LOCKED'，不是合法的BCrypt哈希，因此登录一律失败（fail-closed）。
# 本脚本从环境变量读取明文密码，在运行时生成BCrypt哈希并写入数据库；
# 密码只存在于环境变量与数据库中，不会写入代码仓库。
#
# Seeds runtime credentials for the accounts shipped in document/sql/mall.sql:
# the dump contains no password hashes, this script derives a BCrypt hash from an
# environment-supplied password and applies it to the seeded accounts.
#
# 用法示例 / usage:
#   MALL_DB_PASSWORD='...' MALL_ADMIN_PASS='...' MALL_MEMBER_PASS='...' \
#     bash document/sh/seed-credentials.sh
#
# 支持的环境变量 / environment variables:
#   MALL_DB_HOST      数据库地址，默认127.0.0.1
#   MALL_DB_PORT      数据库端口，默认3306
#   MALL_DB_NAME      数据库名，默认mall
#   MALL_DB_USER      数据库用户，默认root
#   MALL_DB_PASSWORD  数据库密码（必填）
#   MALL_ADMIN_USER   需要设置密码的后台账号，多个用逗号分隔，默认admin
#   MALL_ADMIN_PASS   后台账号密码（不填则跳过后台账号）
#   MALL_MEMBER_USER  需要设置密码的会员账号，多个用逗号分隔，默认member
#   MALL_MEMBER_PASS  会员账号密码（不填则跳过会员账号）
set -euo pipefail

db_host="${MALL_DB_HOST:-127.0.0.1}"
db_port="${MALL_DB_PORT:-3306}"
db_name="${MALL_DB_NAME:-mall}"
db_user="${MALL_DB_USER:-root}"
db_password="${MALL_DB_PASSWORD:-}"
admin_users="${MALL_ADMIN_USER:-admin}"
member_users="${MALL_MEMBER_USER:-member}"
# 不提供任何默认密码，必须由环境变量传入
admin_password="${MALL_ADMIN_PASS:-}"
member_password="${MALL_MEMBER_PASS:-}"

log() {
  echo "seed-credentials: $*"
}

die() {
  echo "seed-credentials: $*" >&2
  exit 1
}

if [[ -z "${db_password}" ]]; then
  die "请设置MALL_DB_PASSWORD（数据库密码）"
fi
if [[ -z "${admin_password}" && -z "${member_password}" ]]; then
  die "请至少设置MALL_ADMIN_PASS或MALL_MEMBER_PASS，脚本不内置任何默认密码"
fi
if ! command -v mysql >/dev/null 2>&1; then
  die "未找到mysql客户端，无法写入数据库"
fi

# 校验用户名，避免把环境变量内容直接拼进SQL造成注入
valid_username() {
  [[ "$1" =~ ^[A-Za-z0-9_.@-]{1,64}$ ]]
}

# 校验生成的哈希格式，只允许BCrypt字符集
valid_bcrypt() {
  [[ "$1" =~ ^\$2[aby]\$[0-9]{2}\$[./A-Za-z0-9]{53}$ ]]
}

# 生成BCrypt哈希：优先python3（密码通过环境变量传入，不出现在进程参数中），
# 其次使用htpasswd（-i表示从标准输入读取密码）。Spring Security的
# BCryptPasswordEncoder同时兼容$2a$/$2b$/$2y$前缀。
bcrypt_hash() {
  local raw="$1"
  local hash=""
  if command -v python3 >/dev/null 2>&1; then
    hash="$(MALL_SEED_RAW="${raw}" python3 - <<'PY' || true
import os
import sys

raw = os.environ["MALL_SEED_RAW"]
try:
    import bcrypt

    print(bcrypt.hashpw(raw.encode(), bcrypt.gensalt(10, prefix=b"2a")).decode())
    sys.exit(0)
except ImportError:
    pass
try:
    from passlib.hash import bcrypt as passlib_bcrypt

    print(passlib_bcrypt.using(rounds=10, ident="2a").hash(raw))
except ImportError:
    sys.exit(1)
PY
)"
  fi
  if [[ -z "${hash}" ]] && command -v htpasswd >/dev/null 2>&1; then
    hash="$(printf '%s\n' "${raw}" | htpasswd -inBC 10 "" | tr -d '\r\n' | cut -d: -f2)"
  fi
  if [[ -z "${hash}" ]]; then
    return 1
  fi
  printf '%s' "${hash}"
}

# 清理Redis中缓存的后台用户信息（键格式见application.yml的redis.database与redis.key.admin），
# 避免应用继续使用锁定状态的旧缓存。redis-cli不存在时静默跳过。
invalidate_admin_cache() {
  local username="$1"
  local redis_host="${MALL_REDIS_HOST:-127.0.0.1}"
  local redis_port="${MALL_REDIS_PORT:-6379}"
  local redis_key_prefix="${MALL_REDIS_ADMIN_KEY_PREFIX:-mall:ums:admin}"

  if command -v redis-cli >/dev/null 2>&1; then
    redis-cli -h "${redis_host}" -p "${redis_port}" DEL "${redis_key_prefix}:${username}" >/dev/null 2>&1 || true
  fi
}

# MYSQL_PWD避免数据库密码出现在进程参数中
run_sql() {
  MYSQL_PWD="${db_password}" mysql --protocol=TCP \
    -h "${db_host}" -P "${db_port}" -u "${db_user}" -D "${db_name}" -N -B -e "$1"
}

seed_account() {
  local table="$1"
  local username="$2"
  local raw="$3"
  local hash
  local exists

  if ! valid_username "${username}"; then
    die "非法用户名：${username}（只允许字母、数字及 _ . @ -）"
  fi
  exists="$(run_sql "SELECT COUNT(*) FROM \`${table}\` WHERE \`username\` = '${username}';")"
  if [[ "${exists}" == "0" ]]; then
    log "跳过 ${table}.${username}：账号不存在"
    return 0
  fi
  if ! hash="$(bcrypt_hash "${raw}")"; then
    die "无法生成BCrypt哈希，请安装python3的bcrypt/passlib模块，或安装htpasswd(apache2-utils)"
  fi
  if ! valid_bcrypt "${hash}"; then
    die "生成的哈希格式不合法，已中止（未修改数据库）"
  fi
  run_sql "UPDATE \`${table}\` SET \`password\` = '${hash}' WHERE \`username\` = '${username}';" >/dev/null
  if [[ "${table}" == "ums_admin" ]]; then
    invalidate_admin_cache "${username}"
  fi
  log "已设置 ${table}.${username} 的密码"
}

seed_accounts() {
  local table="$1"
  local user_list="$2"
  local raw="$3"
  local username
  local -a usernames=()

  if [[ -z "${raw}" ]]; then
    log "跳过 ${table}：未提供密码"
    return 0
  fi
  IFS=',' read -r -a usernames <<<"${user_list}"
  for username in "${usernames[@]}"; do
    username="${username//[[:space:]]/}"
    if [[ -n "${username}" ]]; then
      seed_account "${table}" "${username}" "${raw}"
    fi
  done
}

seed_accounts "ums_admin" "${admin_users}" "${admin_password}"
seed_accounts "ums_member" "${member_users}" "${member_password}"

log "完成。其余演示账号仍为锁定状态，需要时可通过MALL_ADMIN_USER/MALL_MEMBER_USER指定后重新执行。"
log "提示：如果应用已经启动过并缓存了用户信息，请清理Redis中的 mall:ums:admin:* 缓存后再登录。"
