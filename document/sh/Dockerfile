# 该镜像需要依赖的基础镜像
FROM openjdk:17
# 创建运行应用的非root用户，并准备好日志目录（挂载宿主机日志目录时需保证其对uid 1000可写）
RUN groupadd -r -g 1000 mall \
    && useradd -r -u 1000 -g mall mall \
    && mkdir -p /var/logs \
    && chown -R mall:mall /var/logs
# 将当前目录下的jar包复制到docker容器的/目录下
ADD --chown=mall:mall mall-admin-1.0-SNAPSHOT.jar /mall-admin-1.0-SNAPSHOT.jar
# 声明服务运行在8080端口
EXPOSE 8080
# 以非root用户运行容器内的进程，避免进程拥有root权限
USER mall
# 指定docker容器启动时运行jar包
ENTRYPOINT ["java", "-jar","/mall-admin-1.0-SNAPSHOT.jar"]
# 指定维护者的名字
MAINTAINER macro
