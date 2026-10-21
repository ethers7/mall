# 该镜像需要依赖的基础镜像
FROM openjdk:17
# 将当前目录下的jar包复制到docker容器的/目录下
ADD mall-admin-1.0-SNAPSHOT.jar /mall-admin-1.0-SNAPSHOT.jar
# 声明服务运行在8080端口
EXPOSE 8080
# 创建非root用户和用户组，并将jar包的所有权赋予该用户，避免容器以root身份运行
RUN groupadd -r mallapp && useradd -r -g mallapp mallapp \
    && chown mallapp:mallapp /mall-admin-1.0-SNAPSHOT.jar
# 切换到非root用户运行容器进程
USER mallapp
# 指定docker容器启动时运行jar包
ENTRYPOINT ["java", "-jar","/mall-admin-1.0-SNAPSHOT.jar"]
# 指定维护者的名字
MAINTAINER macro