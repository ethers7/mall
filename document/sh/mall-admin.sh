#!/usr/bin/env bash
app_name='mall-admin'
docker stop ${app_name}
echo '----stop container----'
docker rm ${app_name}
echo '----rm container----'
docker rmi `docker images | grep none | awk '{print $3}'`
echo '----rm none images----'
# 容器内以非root用户(uid 1000)运行，需保证挂载的日志目录对该用户可写
mkdir -p /mydata/app/${app_name}/logs
chown -R 1000:1000 /mydata/app/${app_name}/logs
docker run -p 8080:8080 --name ${app_name} \
--read-only \
--tmpfs /tmp \
--security-opt no-new-privileges:true \
--link mysql:db \
--link redis:redis \
-e TZ="Asia/Shanghai" \
-v /etc/localtime:/etc/localtime \
-v /mydata/app/${app_name}/logs:/var/logs \
-d mall/${app_name}:1.0-SNAPSHOT
echo '----start container----'