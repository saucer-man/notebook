# docker基本命令



## 镜像

```bash
# 拉取镜像
docker pull [选项] [Docker Registry 地址[:端口号]/]仓库名[:标签]
docker pull ubuntu:18.04

# 列举镜像 仓库名、标签、镜像 ID、创建时间以及所占用的空间。
docker image ls
docker image ls -a

# 删除镜像
docker image rm [选项] <镜像1> [<镜像2> ...]
# 删除所有仓库名为 redis 的镜像
docker image rm $(docker image ls -q redis)
# 删除所有在 mongo:3.2 之前的镜像
docker image rm $(docker image ls -q -f before=mongo:3.2)

# 清理不用的镜像
docker image prune
```

## 容器

```bash
# 查看
docker ps
= docker container -a
docker ps -a
= docker container ls -a

# 启动并返回bash
docker run -t -i ubuntu:18.04 /bin/bash --name test
-d参数 # 后台运行，不打印任何东西
docker container logs [container ID or NAMES] # 获取容器的输出信息
docker container start # 启动已经中止的容器


# 启动举例
$ docker run --name webserver -d -p 80:80 nginx
$ docker exec -it webserver bash
root@3729b97e8226:/# echo '<h1>Hello, Docker!</h1>' > /usr/share/nginx/html/index.html
root@3729b97e8226:/# exit
exit
docker diff webserver # 查看改动

# 停止
docker container stop

# 重启
docker container restart

# 进入容器 两种方式
docker attach 243c
docker exec -it 69d1 bash # 推荐(因为这个退出，容器不会停止，上面的会)

# 将容器保存，image 慎用
docker commit [选项] <容器ID或容器名> [<仓库名>[:<标签>]]
docker commit \
    --author "Tao Wang <twang2218@gmail.com>" \
    --message "修改了默认网页" \
    webserver \
    nginx:v2

# 导出容器
$ docker container ls -a
CONTAINER ID        IMAGE               COMMAND             CREATED             STATUS                    PORTS               NAMES
7691a814370e        ubuntu:18.04        "/bin/bash"         36 hours ago        Exited (0) 21 hours ago                       test
$ docker export 7691a814370e > ubuntu.tar

# 导入容器
$ cat ubuntu.tar | docker import - test/ubuntu:v1.0
$ docker image ls
REPOSITORY          TAG                 IMAGE ID            CREATED              VIRTUAL SIZE
test/ubuntu         v1.0                9d37a6082e97        About a minute ago   171.3 MB

# 删除容器 (如果要删除一个运行中的容器，可以添加-f参数)
docker container rm 

# 清理所有停止的容器
docker container prune
```

## Dockerfile写法

文档：[https://docs.docker.com/engine/reference/builder/](https://docs.docker.com/engine/reference/builder/)

```bash
# 构建image的几种方式
# docker build -t nginx:v3 . 
# docker build https://github.com/twang2218/gitlab-ce-zh.git#:11.1
# docker build http://server/context.tar.gz
# docker build - < Dockerfile
# cat Dockerfile | docker build -
# docker build - < context.tar.gz

# 最简单的Dockerfile
FROM nginx
RUN echo '<h1>Hello, Docker!</h1>' > /usr/share/nginx/html/index.html

#以下是一些语法

COPY [--chown=<user>:<group>] <源路径>... <目标路径>
# COPY 指令将从构建上下文目录中 <源路径> 的文件/目录复制到新的一层的镜像内的 <目标路径> 位置。比如：
# COPY package.json /usr/src/app/
# 可以加上 --chown=<user>:<group> 选项来改变文件的所属用户及所属组

CMD echo $HOME 
# 和RUN相似

<ENTRYPOINT> "<CMD>"
# ENTRYPOINT 的目的和 CMD 一样，都是在指定容器启动程序及参数。ENTRYPOINT 在运行时也可以替代，不过比 CMD 要略显繁琐，需要通过 docker run 的参数 --entrypoint 来指定。

ENV VERSION=1.0 DEBUG=on 
# 设置环境变量

ARG <参数名>[=<默认值>]
# 设置环境变量

VOLUME /data
# 定义隐匿卷

EXPOSE 声明端口
# 仅是申明 和-p不同

WORKDIR 指定工作目录

USER <用户名>[:<用户组>]
# 指定用户，仅仅是指定，需要事先创建
```

## docker-compose

```text
docker-compose [-f=<arg>...] [options] [COMMAND] [ARGS...]

命令选项
-f, --file FILE 指定使用的 Compose 模板文件，默认为 docker-compose.yml，可以多次指定。
-p, --project-name NAME 指定项目名称，默认将使用所在目录名称作为项目名。
--x-networking 使用 Docker 的可拔插网络后端特性
--x-network-driver DRIVER 指定网络后端的驱动，默认为 bridge
--verbose 输出更多调试信息。
-v, --version 打印版本并退出。

build  # 构建（重新构建）项目中的服务容器
config  # 验证配置是否正确
images  # 列出 Compose 文件中包含的镜像。
start/stop/restart  # 启动/停止/重启已经存在的服务容器
up/down  # 自动完成包括构建镜像，（重新）创建服务，启动服务，并关联服务相关容器的一系列操作。
```

