# Windows Basics

## Check versions and machine info

```powershell
PS C:\htb> Get-WmiObject -Class win32_OperatingSystem | select Version,BuildNumber

Version    BuildNumber
-------    -----------
10.0.19041 19041
```

can also select `Win32_Process` (process listing), `Win32_Service` (listing of services), and `Win32_Bios` (BIOS info).

## Accessing Windows

Windows is based on the idea of people coming to work on a specific computer and only there. 

Among the many ways of remote access technologies:


- Virtual Private Networks (VPN)
- Secure Shell (SSH)
- File Transfer Protocol (FTP)
- Virtual Network Computing (VNC)
- Windows Remote Management (or PowerShell Remoting) (WinRM)
- Remote Desktop Protocol (RDP)

Windows primarly uses RDP (port 3389).

By default it is disabled and will encourage users to only allow it on a local trusted network. Administrators and anyone with a username:password may access an RDP port.

Accessing from linux:
```bash
$> xfreerdp /v:<targetIp> /u:htb-student /p:Password
```
