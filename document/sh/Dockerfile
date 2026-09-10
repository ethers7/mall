# 该镜像需要依赖的基础镜像
FROM openjdk:17
# 将当前目录下的jar包复制到docker容器的/目录下
ADD mall-admin-1.0-SNAPSHOT.jar /mall-admin-1.0-SNAPSHOT.jar
# 创建非root用户并赋予jar包权限，避免容器以root身份运行
RUN groupadd -r app && useradd -r -g app app \
    && chown app:app /mall-admin-1.0-SNAPSHOT.jar
# 声明服务运行在8080端口
EXPOSE 8080
# 切换到非root用户运行
USER app
# 指定docker容器启动时运行jar包
ENTRYPOINT ["java", "-jar","/mall-admin-1.0-SNAPSHOT.jar"]
# 指定维护者的名字
MAINTAINER macro