# pwntools基本用法

### 安装

```text
# https://pwntoolsdocinzh-cn.readthedocs.io/en/master/install.html
pip install --upgrade pwntools
```



### 全局设置

```text
context.log_level = 'debug'  # 调试级别
context.arch      = 'i386' # 架构
context.os        = 'linux' # 操作系统

也可以写在一起
context(os='linux', arch='amd64', log_level='debug')
```

### 连接

```text
proc= porcess("./level0") # 本地连接
r = remote("127.0.0.1",10001) # 远程连接
r.close()  # 关闭远程连接
e = ELF('./example_file')  # 打开文件
```

### IO设置

```text
r.send(data)  发送数据
r.sendline(data)  发送一行数据，相当于在数据后面加\n
r.sendafter(some_string, payload) 接收到 some_string 后, 发送你的 payload
r.recv(numb = 2048, timeout = dufault)  接受数据，numb指定接收的字节，timeout指定超时
r.recvline(keepends=True)  接受一行数据，keepends为是否保留行尾的\n
r.recvuntil("Hello,World\n",drop=fasle)  接受数据直到我们设置的标志出现
r.recvall()  一直接收直到EOF
r.recvrepeat(timeout = default)  持续接受直到EOF或timeout
r.interactive()  直接进行交互，相当于回到shell的模式，在取得shell之后使用
```

