# 该镜像需要依赖的基础镜像
FROM openjdk:17
# 创建非root用户和用户组，避免容器以root身份运行
RUN groupadd -r appuser && useradd -r -g appuser appuser
# 将当前目录下的jar包复制到docker容器的/目录下
ADD mall-admin-1.0-SNAPSHOT.jar /mall-admin-1.0-SNAPSHOT.jar
# 将jar包的属主修改为非root用户，确保应用可以正常读取
RUN chown appuser:appuser /mall-admin-1.0-SNAPSHOT.jar
# 声明服务运行在8080端口
EXPOSE 8080
# 切换到非root用户运行容器，降低权限提升风险
USER appuser
# 指定docker容器启动时运行jar包
ENTRYPOINT ["java", "-jar","/mall-admin-1.0-SNAPSHOT.jar"]
# 指定维护者的名字
MAINTAINER macro