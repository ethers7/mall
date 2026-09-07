#!/usr/bin/env bash
# 导入 document/sql/mall.sql 之后运行，为演示账号设置口令。
# mall.sql 中不再保存任何可用的口令散列（fail-closed），口令只能在运行时由
# 环境变量提供，脚本本身也不包含任何默认口令。
#
# 必需环境变量：
#   MALL_ADMIN_PASSWORD   后台账号(ums_admin)口令
#   MALL_MEMBER_PASSWORD  会员账号(ums_member)口令
# 可选：
#   MYSQL_HOST(127.0.0.1) MYSQL_PORT(3306) MYSQL_USER(root) MYSQL_DATABASE(mall)
#   MYSQL_PASSWORD        MySQL 连接口令（通过 MYSQL_PWD 传给客户端，不出现在命令行）
set -euo pipefail

mysql_host=${MYSQL_HOST:-127.0.0.1}
mysql_port=${MYSQL_PORT:-3306}
mysql_user=${MYSQL_USER:-root}
mysql_db=${MYSQL_DATABASE:-mall}

for var in MALL_ADMIN_PASSWORD MALL_MEMBER_PASSWORD; do
  if [ -z "${!var:-}" ]; then
    echo "ERROR: ${var} is not set - refusing to seed credentials" >&2
    exit 1
  fi
done

# 生成 BCrypt 散列（Spring Security 兼容 $2a$/$2b$/$2y$）。
# 口令通过 stdin 传入，避免出现在进程命令行或 shell 历史中。
bcrypt_hash() {
  local raw=$1
  if command -v python3 >/dev/null 2>&1 &&
    python3 -c 'import bcrypt' >/dev/null 2>&1; then
    printf '%s' "$raw" | python3 -c \
      'import bcrypt,sys; print(bcrypt.hashpw(sys.stdin.buffer.read(), bcrypt.gensalt(10)).decode())'
  elif command -v htpasswd >/dev/null 2>&1; then
    htpasswd -inBC 10 x <<<"$raw" | cut -d: -f2
  else
    echo "ERROR: need python3+bcrypt or htpasswd to hash the password" >&2
    return 1
  fi
}

admin_hash=$(bcrypt_hash "$MALL_ADMIN_PASSWORD")
member_hash=$(bcrypt_hash "$MALL_MEMBER_PASSWORD")

# 散列通过 stdin 传给 mysql，不作为命令行参数，也不打印到日志。
MYSQL_PWD=${MYSQL_PASSWORD:-} mysql \
  --host="$mysql_host" --port="$mysql_port" --user="$mysql_user" \
  --default-character-set=utf8mb4 "$mysql_db" <<SQL
UPDATE \`ums_admin\` SET \`password\` = '${admin_hash}' WHERE \`password\` = '!LOCKED-NO-LOGIN!';
UPDATE \`ums_member\` SET \`password\` = '${member_hash}' WHERE \`password\` = '!LOCKED-NO-LOGIN!';
SQL

echo '----credentials seeded from environment----'
