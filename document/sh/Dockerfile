# 该镜像需要依赖的基础镜像
FROM openjdk:17
# 将当前目录下的jar包复制到docker容器的/目录下
ADD mall-admin-1.0-SNAPSHOT.jar /mall-admin-1.0-SNAPSHOT.jar
# 创建运行应用的非root用户，并使jar包和日志目录对该用户可用
RUN groupadd -g 1000 mall \
    && useradd -u 1000 -g mall -m -d /home/mall mall \
    && mkdir -p /var/logs \
    && chown mall:mall /mall-admin-1.0-SNAPSHOT.jar \
    && chown -R mall:mall /var/logs
# 声明服务运行在8080端口
EXPOSE 8080
# 以非root用户运行容器（宿主机挂载到/var/logs的目录属主需为1000:1000）
USER mall
# 指定docker容器启动时运行jar包
ENTRYPOINT ["java", "-jar","/mall-admin-1.0-SNAPSHOT.jar"]
# 指定维护者的名字
MAINTAINER macro