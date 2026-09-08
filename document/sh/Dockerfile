# 该镜像需要依赖的基础镜像
FROM openjdk:17
# 将当前目录下的jar包复制到docker容器的/目录下
ADD mall-admin-1.0-SNAPSHOT.jar /mall-admin-1.0-SNAPSHOT.jar
# 创建运行服务的非root用户，并准备好日志目录(/var/logs)的读写权限
RUN set -eux; \
    if command -v groupadd >/dev/null 2>&1; then \
        groupadd -r -g 1000 mall; \
        useradd -r -u 1000 -g mall -m -d /home/mall -s /usr/sbin/nologin mall; \
    else \
        addgroup -S -g 1000 mall; \
        adduser -S -u 1000 -G mall -h /home/mall -s /sbin/nologin mall; \
    fi; \
    mkdir -p /var/logs; \
    chown -R mall:mall /var/logs /home/mall /mall-admin-1.0-SNAPSHOT.jar; \
    chmod 755 /var/logs
# 声明服务运行在8080端口
EXPOSE 8080
# 以非root用户运行服务，避免容器内进程拥有root权限
USER mall
# 指定docker容器启动时运行jar包
ENTRYPOINT ["java", "-jar","/mall-admin-1.0-SNAPSHOT.jar"]
# 指定维护者的名字
MAINTAINER macro