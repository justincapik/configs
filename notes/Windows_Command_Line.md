# Windows Command Line

|PowerShell | Command Prompt|
|--- |---|
|Introduced in 2006 | Introduced in 1981|
|Can run both batch commands and PowerShell cmdlets | Can only run batch commands|
|Supports the use of command aliases | Does not support command aliases|
|Cmdlet output can be passed to other cmdlets | Command output cannot be passed to other commands|
|All output is in the form of an object | Output of commands is text|
|Able to execute a sequence of cmdlets in a script | A command must finish before the next command can run|
|Has an Integrated Scripting Environment (ISE) | Does not have an ISE|
|Can access programming libraries because it is built on the .NET framework | Cannot access these libraries|
|Can be run on Linux systems | Can only be run on Windows systems |

you can run `powershell` commands with `powershell <cmd>` in `cmd`.

# CMD
## Command prompt Basics

How to access it:
#### Locally
- Windows key + `r`, then type `cmd`
- accessing directly `C:\Windows\System32\cmd.exe`

#### Remote Access
- `telnet` (insecure and not recommended)
- `SSH`
- `PsExec`
- `WinRM`
- `RDP`
- ...
  
### Basic Usage

`dir`:
```cmd
C:\Users\htb\Desktop> dir
  
 Volume in drive C has no label.
 Volume Serial Number is DAE9-5896

 Directory of C:\Users\htb\Desktop

06/11/2021  11:59 PM    <DIR>          .
06/11/2021  11:59 PM    <DIR>          ..
06/11/2021  11:57 PM                 0 file1.txt
06/11/2021  11:57 PM                 0 file2.txt
06/11/2021  11:57 PM                 0 file3.txt
04/13/2021  11:24 AM             2,391 Microsoft Teams.lnk
06/11/2021  11:57 PM                 0 super-secret-sauce.txt
06/11/2021  11:59 PM                 0 write-secrets.ps1
               6 File(s)          2,391 bytes
               2 Dir(s)  35,102,117,888 bytes free
```

`help`:
```
C:\htb> help

For more information on a specific command, type HELP command-name
ASSOC          Displays or modifies file extension associations.
ATTRIB         Displays or changes file attributes.
BREAK          Sets or clears extended CTRL+C checking.
BCDEDIT        Sets properties in boot database to control boot loading.
CACLS          Displays or modifies access control lists (ACLs) of files.
CALL           Calls one batch program from another.
CD             Displays the name of or changes the current directory.
CHCP           Displays or sets the active code page number.
CHDIR          Displays the name of or changes the current directory.
CHKDSK         Checks a disk and displays a status report.

<snip>
```
```
C:\htb> help time

Displays or sets the system time.

TIME [/T | time]

Type TIME with no parameters to display the current time setting and a prompt
for a new one. Press ENTER to keep the same time.

If Command Extensions are enabled, the TIME command supports
the /T switch which tells the command to just output the
current time, without prompting for a new time.
```
Commands might not support the `help` utility. you can try `<command> /?`.
Other options include [Microsoft documentation](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/windows-commands) and [ss64](https://ss64.com/nt/).


`cls` to clear screen. 

History commands:
|Key/Command | Description|
|-- | -- |
|doskey /history | doskey /history will print the session's command history to the terminal or output it to a file when specified.|
|page up | Places the first command in our session history to the prompt.|
|page down | Places the last command in history to the prompt.|
|⇧ | Allows us to scroll up through our command history to view previously run commands.|
|⇩ | Allows us to scroll down to our most recent commands run.|
|⇨ | Types the previous command to prompt one character at a time.|
|⇦ | N/A|
|F3 | Will retype the entire previous entry to our prompt.|
|F5 | Pressing F5 multiple times will allow you to cycle through previous commands.|
|F7 | Opens an interactive list of previous commands.|
|F9 | Enters a command to our prompt based on the number specified. The number corresponds to the commands place in our history.|

`Ctrl + C` to interrupt command.

### System Navigation

- `cd` and `chdir` work like the linux `cd` command.
- `tree` command:
  - ```
    C:\htb\student\> tree

    Folder PATH listing
    Volume serial number is 26E7-9EE4
    C:.
    ├───3D Objects
    ├───Contacts
    ├───Desktop
    ├───Documents
    ├───Downloads
    ├───Favorites
    │   └───Links
    ├───Links
    ├───Music
    ├───OneDrive
    ├───Pictures
    │   ├───Camera Roll
    │   └───Saved Pictures
    ├───Saved Games
    ├───Searches
    └───Videos
        └───Captures
    ```
  - use `tree /F` to list files as well.

#### Interesting directories
|Name: | Location: | Description:|
| --- | --- | --- |
|%SYSTEMROOT%\Temp | C:\Windows\Temp | Global directory containing temporary system files accessible to all users on the system. All users, regardless of authority, are provided full read, write, and execute permissions in this directory. Useful for dropping files as a low-privilege user on the system.|
|%TEMP% | C:\Users\<user>\AppData\Local\Temp | Local directory containing a user's temporary files accessible only to the user account that it is attached to. Provides full ownership to the user that owns this folder. Useful when the attacker gains control of a local/domain joined user account.|
|%PUBLIC% | C:\Users\Public | Publicly accessible directory allowing any interactive logon account full access to read, write, modify, execute, etc., files and subfolders within the directory. Alternative to the global Windows Temp Directory as it's less likely to be monitored for suspicious activity.|
|%ProgramFiles% | C:\Program Files | folder containing all 64-bit applications installed on the system. Useful for seeing what kind of applications are installed on the target system.|
|%ProgramFiles(x86)% | C:\Program Files (x86) | Folder containing all 32-bit applications installed on the system. Useful for seeing what kind of applications are installed on the target system.|

### Working with Directories and Files

- `dir /s <drive:>\<pattern>` to search for files/directories
- `md` or `mkdir` to create a new directory
- `rd` or `rmdir` to delete an empty directory
  - `rd /S` to allow prompt to delete non-empty directory
- `move <src> <dst>` to move directory
- `xcopy <scr> <dst> <opts>` to copy a file, **removes the read-only bit** [deprecated, use `robocopy`]
  - use `/E` options to copy folder and subfolders, including empty folders

#### Robocopy

The heavy-duty rsync-style copying command of windows.

`robocopy C:\source D:\destination`

If given `SeBackupPrivilege` and `SeRestorePrivilege` we can use the `/B` option to copy any file in backup mode and have full rights over them.

Robocopy can also work with system, read-only, and hidden files. As a user, this can be problematic if we do not have the `SeBackupPrivilege` and auditing privilege attributes.  This could stop us from duplicating or moving files and directories. There is a bit of a workaround, however. We can utilize the `/MIR` switch to permit ourselves to copy the files we need temporarily.

When permission are unsufficient, utilizing the `/MIR` switch will complete the task for us. Be aware that it will mark the files as a system backup and hide them from view. We can clear the additional attributes if we add the `/A-:SH` switch to our command. Be careful of the `/MIR` switch, as it will mirror the destination directory to the source (aka delete existing destination files).

### Files

#### Viewing file content

- `more` -> `less` command in linux
  - Go up and down with `enter` or `space bar`
  - `/S` to crunch blank space
  - Pipe output to `more`: eg. `ipconfig /all | more`

- `type` to simple print a file to the screen
  - Doesn't lock file
  - `type example-1.txt >> example-2.txt`, same as linux

#### Creating and modifying files

With `echo`
```cmd
C:\Users\htb\Desktop>echo Check out this text > demo.txt

C:\Users\htb\Desktop>type demo.txt
Check out this text

C:\Users\htb\Desktop>echo More text for our demo file >> demo.txt

C:\Users\htb\Desktop>type demo.txt
Check out this text
More text for our demo file
```

with `fsutil`:
```cmd
C:\Users\htb\Desktop>fsutil file createNew for-sure.txt 222
File C:\Users\htb\Desktop\for-sure.txt is created

C:\Users\htb\Desktop>echo " my super cool text file from fsutil "> for-sure.txt

C:\Users\htb\Desktop>type for-sure.txt
" my super cool text file from fsutil "
```

rename a file with `ren`:
```
ren demo.txt superdemo.txt
```

### Input/Output

We can utilize the <, >, |, and & to send input and output from the console and files to where we need them. With > we can push the output of a command to a file.

Append to a file:
```
C:\Users\htb\Documents> echo a b c d e > test.txt

C:\Users\htb\Documents>type test.txt
a b c d e

C:\Users\htb\Documents>echo f g h i j k see how this works now? >> test.txt

C:\Users\htb\Documents>type test.txt
a b c d e
f g h i j k see how this works now?
```

pass in a file to a command:
```
C:\Users\htb\Documents>find /i "see" < test.txt

f g h i j k see how this works now?
```

pip output between commands:
```
C:\Users\htb\Documents>ipconfig /all | find /i "IPV4"

   IPv4 Address. . . . . . . . . . . : 172.16.146.5(Preferred)
```

Run A then B:
```
C:\Users\htb\Documents>ping 8.8.8.8 & type test.txt

Pinging 8.8.8.8 with 32 bytes of data:
Reply from 8.8.8.8: bytes=32 time=22ms TTL=114
Reply from 8.8.8.8: bytes=32 time=19ms TTL=114
Reply from 8.8.8.8: bytes=32 time=17ms TTL=114
Reply from 8.8.8.8: bytes=32 time=16ms TTL=114

Ping statistics for 8.8.8.8:
    Packets: Sent = 4, Received = 4, Lost = 0 (0% loss),
Approximate round trip times in milli-seconds:
    Minimum = 16ms, Maximum = 22ms, Average = 18ms
a b c d e
f g h i j k see how this works now?
```
Run A then B, only if A succeeds:
```
C:\Users\student\Documents>cd C:\Users\student\Documents\Backup && echo 'did this work' > yes.txt

C:\Users\student\Documents\Backup>type yes.txt
'did this work'
```

#### Deleting files

Use `del` or `erase`:
```
del <file>
erase <file>
```

use `del /A` to delete based on attributes (also works for listing with `dir`):
```
  /A            Selects files to delete based on attributes
  attributes    R  Read-only files            S  System files
                H  Hidden files               A  Files ready for archiving
                I  Not content indexed Files  L  Reparse Points
                O  Offline files              -  Prefix meaning not
```

Use `/F` to force deletion without confirmation prompt.

#### Copying and moving files

- `copy` -> cp in linux
- `move` -> mv in linux

## Gathering System Information

![What to gather](./Windows_InformationTypesChart.webp)

Type 	Description
General System Information 	Contains information about the overall target system. Target system information includes but is not limited to the hostname of the machine, OS-specific details (name, version, configuration, etc.), and installed hotfixes/patches for the system.
Networking Information 	Contains networking and connection information for the target system and system(s) to which the target is connected over the network. Examples of networking information include but are not limited to the following: host IP address, available network interfaces, accessible subnets, DNS server(s), known hosts, and network resources.
Basic Domain Information 	Contains Active Directory information regarding the domain to which the target system is connected.
User Information 	Contains information regarding local users and groups on the target system. This can typically be expanded to contain anything accessible to these accounts, such as environment variables, currently running tasks, scheduled tasks, and known services.