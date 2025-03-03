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
$> xfreerdp /v:<targetIp> /u:Username /p:Password
```

## Operating System Structure

- `Perflogs` &rarr; Can hold Windows performance logs but is empty by default.
- `Program` Files &rarr; On 32-bit systems, all 16-bit and 32-bit programs are installed here. On 64-bit systems, only 64-bit programs are installed here.
- `Program` Files (x86) &rarr; 32-bit and 16-bit programs are installed here on 64-bit editions of Windows.
- `ProgramData` &rarr; This is a hidden folder that contains data that is essential for certain installed programs to run. This data is accessible by the program no matter what user is running it.
- `Users` &rarr; This folder contains user profiles for each user that logs onto the system and contains the two folders Public and Default.
- `Default` &rarr; This is the default user profile template for all created users. Whenever a new user is added to the system, their profile is based on the Default profile.
- `Public` &rarr; This folder is intended for computer users to share files and is accessible to all users by default. This folder is shared over the network by default but requires a valid network account to access.
- `AppData` &rarr; Per user application data and settings are stored in a hidden user subfolder (i.e., cliff.moore\AppData). Each of these folders contains three subfolders. The Roaming folder contains machine-independent data that should follow the user's profile, such as custom dictionaries. The Local folder is specific to the computer itself and is never synchronized across the network. LocalLow is similar to the Local folder, but it has a lower data integrity level. Therefore it can be used, for example, by a web browser set to protected or safe mode.
- `Windows` &rarr; The majority of the files required for the Windows operating system are contained here.
- `System`, `System32`, `SysWOW64` &rarr; Contains all DLLs required for the core features of Windows and the Windows API. The operating system searches these folders any time a program asks to load a DLL without specifying an absolute path.
- `WinSxS` &rarr; The Windows Component Store contains a copy of all Windows components, updates, and service packs.

### commands

- [`dir [folder]`](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/dir) ~> `ls` on linux
- [`tree <folder>`](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/tree) &rarr; same as linux

## File System

Most commonly used are `FAT32`, `exFAT` and `NTFS`.

`FAT32` (File Allocation Table) is mostly used for it's wide compatibility (even MacOS and Linux), but it's very limited size (4Gb) and requirements of third party file encryption makes it less popular.

`NTFS` (New Technology File System) is default since Windows NT 3.1 (1993). It has finer permission controle, more size and built-in logging (!). Most mobile devices and older devices do not support it natively.

We will focus on `NTFS`.

### NTFS permissions

- `Full Control` &rarr; Allows reading, writing, changing, deleting of files/folders.
- `Modify` &rarr; Allows reading, writing, and deleting of files/folders.
- `List Folder Contents` &rarr; Allows for viewing and listing folders and subfolders as well as executing files. Folders only inherit this permission.
- `Read` and Execute &rarr; Allows for viewing and listing files and subfolders as well as executing files. Files and folders inherit this permission.
- `Write` &rarr; Allows for adding files to folders and subfolders and writing to a file.
- `Read` &rarr; Allows for viewing and listing of folders and subfolders and viewing a file's contents.
- `Traverse Folder` &rarr; This allows or denies the ability to move through folders to reach other files or folders. For example, a user may not have permission to list the directory contents or view files in the documents or web apps directory in this example c:\users\bsmith\documents\webapps\backups\backup_02042020.zip but with Traverse Folder permissions applied, they can access the backup archive.

we can use [`icalcs`](https://ss64.com/nt/icacls.html) to view permissions for each group/user:
```
C:\htb> icacls c:\Users
c:\Users NT AUTHORITY\SYSTEM:(OI)(CI)(F)
         BUILTIN\Administrators:(OI)(CI)(F)
         BUILTIN\Users:(RX)
         BUILTIN\Users:(OI)(CI)(IO)(GR,GE)
         Everyone:(RX)
         Everyone:(OI)(CI)(IO)(GR,GE)

Successfully processed 1 files; Failed processing 0 files
```

Inheritance settings:
- (CI): container inherit
- (OI): object inherit
- (IO): inherit only
- (NP): do not propagate inherit
- (I): permission inherited from parent container

Permissions:

- F : full access
- D :  delete access
- N :  no access
- M :  modify access
- RX :  read and execute access
- R :  read-only access
- W :  write-only access

addiional, grant full controle to user joe with:
`icacls c:\users /grant joe:f`

## Share permissions vs NTFS permission

Share permissions involve Full Controle, Change, and Read permissions for `sharing` files of a network, such a with `SMB`. 

NTFS permissions involve more granular permissions, and also add a layer of NTS special permissions.

note: `RDP` connection will only invoke `NTFS` permissions.

Configure folder Share Permissions:

![share permissions example](./share_permissions.webp)

The `ACL` (Access Control List) is similar to `NTFS`. Admins use the `ACL`'s `ACEs` (Access Controle Entries) seen above to comfigure `users` and `groups` (aka security principals) to manage and track access to shared ressources.

we can connect to the machine via SMB:
```
$ smbclient -L SERVER_IP -U htb-student
Enter WORKGROUP\htb-student's password: 

	Sharename       Type      Comment
	---------       ----      -------
	ADMIN$          Disk      Remote Admin
	C$              Disk      Default share
	Company Data    Disk      
	IPC$            IPC       Remote IPC
```

or connect directly to the available file with:
```
$ smbclient '\\SERVER_IP\Company Data' -U htb-student
Password for [WORKGROUP\htb-student]:
Try "help" to get a list of possible commands.

smb: \> 
```