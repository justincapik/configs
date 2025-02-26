# SMB (Server Message Block)

SMB (Server Message Block) is a prevalent protocol on Windows machines that provides many vectors for vertical and lateral movement. 

---

## Exploits:

- EthernalBlue (https://www.avast.com/c-eternalblue).
 - https://www.rapid7.com/db/modules/exploit/windows/smb/ms17_010_eternalblue/
 - Metasploit Framework available


## Discovery:

nmap built-in script:
```
nmap --script smb-os-discovery.nse -p445 10.10.10.40

Starting Nmap 7.91 ( https://nmap.org ) at 2020-12-27 00:59 GMT
Nmap scan report for doctors.htb (10.10.10.40)
Host is up (0.022s latency).

PORT    STATE SERVICE
445/tcp open  microsoft-ds

Host script results:
| smb-os-discovery: 
|   OS: Windows 7 Professional 7601 Service Pack 1 (Windows 7 Professional 6.1)
|   OS CPE: cpe:/o:microsoft:windows_7::sp1:professional
|   Computer name: CEO-PC
|   NetBIOS computer name: CEO-PC\x00
|   Workgroup: WORKGROUP\x00
|_  System time: 2020-12-27T00:59:46+00:00

Nmap done: 1 IP address (1 host up) scanned in 2.71 seconds
```

User discovery example:
```
smbclient -N -L \\\\10.129.42.253

	Sharename       Type      Comment
	---------       ----      -------
	print$          Disk      Printer Drivers
	users           Disk      
	IPC$            IPC       IPC Service (gs-svcscan server (Samba, Ubuntu))
SMB1 disabled -- no workgroup available
```

`-N` to supress password prompt
`-L` to retrieve list of available shares on the remote host

Connect as guest user with `smbclient \\\\10.129.42.253\\users`.
You will most likely still need user:passwd combo  to run commands in the smbclient console (can be brute forced with `hydra` on smb1 for example).

---

## Common SMB (smbclient) Commands

Below is a list of frequently used commands when interacting with SMB shares via `smbclient`.  
These commands can be used after running `smbclient //server/share -U <username>` and entering the SMB prompt.

- **Connection**
  - `smbclient //server/share -U <username>` Connect to the `share` on the given `server` with the specified `<username>`.
  - `-L <server>` (e.g., `smbclient -L 10.10.10.5 -U guest`) List available shares on the server (often used before connecting to a specific share).

- **Navigation & Directory Management**
  - `ls` / `dir` List files and directories in the current remote SMB directory.
  - `cd <directory>` Change the current remote directory.
  - `lcd <directory>` Change the local working directory (on your machine).
  - `pwd` Display the current directory on the SMB share.
  - `mkdir <directory>` Create a directory on the SMB share.
  - `rmdir <directory>` Remove an empty directory on the SMB share.

- **File Transfer**
  - `get <filename>` Download a file from the SMB share to the local machine.
  - `mget <file1> <file2> ...` Download multiple files (wildcards like `*` can be used).
  - `put <filename>` Upload a file from the local machine to the SMB share.
  - `mput <file1> <file2> ...` Upload multiple files (wildcards like `*` can be used).

- **Transfer Settings**
  - `prompt` Toggle interactive mode for multiple file operations (`mget`/`mput`). When off, files will transfer without prompting.
  - `recurse` Toggle recursive directory operations. Useful for transferring entire directories.

- **File & Directory Operations**
  - `rm <filename>` Remove a file on the SMB share.
  - `rename <oldname> <newname>` Rename a file or directory on the SMB share.

- **Local Shell Commands**
  - `! <command>` Execute a command on your local machine without leaving the smbclient session. (For example, `! pwd` to see your local directory.)
  - `!` Just typing `!` enters an interactive shell on the local machine; type `exit` or `ctrl+d` to return to smbclient.

- **Help & Exit**
  - `help` Show a list of available smbclient commands.
  - `exit` / `quit` Disconnect and close the SMB session.
