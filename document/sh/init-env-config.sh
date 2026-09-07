#!/usr/bin/env bash
# 初始化document/docker/docker-compose-env.yml所需的宿主机目录与配置文件
# elasticsearch、logstash、rabbitmq三个容器以只读根文件系统(read_only: true)启动，
# 而它们启动时都需要写入自己的配置目录（生成elasticsearch.keystore、env2yaml改写logstash.yml、
# 入口脚本生成rabbitmq配置），因此配置目录必须挂载为可写的宿主机目录。
# 这里直接从官方镜像中导出默认配置，保证挂载后镜像内置的jvm.options、log4j2.properties、
# pipelines.yml、enabled_plugins、conf.d等文件不会被空目录屏蔽。
# 用法：在执行docker-compose -f docker-compose-env.yml up之前运行一次
#      sudo bash init-env-config.sh
set -euo pipefail

# 数据根目录，需与docker-compose-env.yml中的挂载路径保持一致
data_dir='/mydata'
# 项目document目录
document_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# 与docker-compose-env.yml中一致的镜像版本
elasticsearch_image='elasticsearch:7.17.3'
logstash_image='logstash:7.17.3'
rabbitmq_image='rabbitmq:3.9.11-management'

# 获取镜像默认运行用户的uid:gid，挂载目录需要对该用户可写
image_owner() {
  docker run --rm --entrypoint sh "$1" -c 'printf "%s:%s" "$(id -u)" "$(id -g)"'
}

# 创建挂载目录并设置属主
prepare_dir() {
  local dir="$1" owner="$2"
  mkdir -p "${dir}"
  chown -R "${owner}" "${dir}"
}

# 从镜像中导出配置目录，目录非空时跳过，避免覆盖已有的修改
seed_config_dir() {
  local image="$1" src="$2" dir="$3" owner="$4" container_id
  mkdir -p "${dir}"
  if [ -z "$(ls -A "${dir}")" ]; then
    echo "----seed ${dir} from ${image}----"
    container_id="$(docker create "${image}")"
    docker cp "${container_id}:${src}/." "${dir}"
    docker rm -v "${container_id}" >/dev/null
  else
    echo "----skip ${dir}: already initialized----"
  fi
  chown -R "${owner}" "${dir}"
}

echo '----elasticsearch----'
elasticsearch_owner="$(image_owner "${elasticsearch_image}")"
seed_config_dir "${elasticsearch_image}" '/usr/share/elasticsearch/config' "${data_dir}/elasticsearch/config" "${elasticsearch_owner}"
for sub_dir in plugins data logs tmp; do
  prepare_dir "${data_dir}/elasticsearch/${sub_dir}" "${elasticsearch_owner}"
done

echo '----logstash----'
logstash_owner="$(image_owner "${logstash_image}")"
seed_config_dir "${logstash_image}" '/usr/share/logstash/config' "${data_dir}/logstash/config" "${logstash_owner}"
for sub_dir in data logs tmp; do
  prepare_dir "${data_dir}/logstash/${sub_dir}" "${logstash_owner}"
done
# 管道配置由项目维护，首次部署时从document/elk下复制到宿主机
if [ ! -f "${data_dir}/logstash/logstash.conf" ]; then
  cp "${document_dir}/elk/logstash.conf" "${data_dir}/logstash/logstash.conf"
fi
chown "${logstash_owner}" "${data_dir}/logstash/logstash.conf"

echo '----rabbitmq----'
rabbitmq_owner="$(image_owner "${rabbitmq_image}")"
seed_config_dir "${rabbitmq_image}" '/etc/rabbitmq' "${data_dir}/rabbitmq/conf" "${rabbitmq_owner}"
for sub_dir in data logs; do
  prepare_dir "${data_dir}/rabbitmq/${sub_dir}" "${rabbitmq_owner}"
done

echo '----done----'
