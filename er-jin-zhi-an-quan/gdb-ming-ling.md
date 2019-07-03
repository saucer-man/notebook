# gdb调试相关

## 安装peda

```text
git clone https://github.com/longld/peda.git ~/peda
echo "source ~/peda/peda.py" >> ~/.gdbinit
```

## gdb-peda 命令

```text
disass/disassemble func # 查看反汇编
pattern_create 200 生成字符串模板
set args 设置参数
pattern_offset xxxxx 查看偏移
print $esp 查看寄存器
objdump -t 文件名   可以查看符号表
b *0x080484f5
r `python -c "print 'A'*256+'BBBB'"`
info breakpoint 查看所有断点
d breakpoint 1 删除第一个断点
p system 寻找libc总system函数地址
find "/bin/sh" 寻找字符串地址
```

## ASLR

```text
# ASLR设置：
# 查看aslr是否开启 
  cat /proc/sys/kernel/randomize_va_space  
# 关闭aslr  
  sudo su  
  echo 0 > /proc/sys/kernel/randomize_va_space
```

## 转储

```text
# 转储设置：
# 查看是否开启：
  ulimit -c   （如果是0就是关着的）
# 开启转储 
  ulimit -c unlimited

# 设置转储文件位置； /tmp/core.%t
  sudo su
  sudo sh -c 'echo "/tmp/core.%t" > /proc/sys/kernel/core_pattern'
```

