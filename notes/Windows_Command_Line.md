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

## System Navigation

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
  - use `tree /F` to list files recursively.

#### Interesting directories
|Name: | Location: | Description:|
| --- | --- | --- |
|%SYSTEMROOT%\Temp | C:\Windows\Temp | Global directory containing temporary system files accessible to all users on the system. All users, regardless of authority, are provided full read, write, and execute permissions in this directory. Useful for dropping files as a low-privilege user on the system.|
|%TEMP% | C:\Users\<user>\AppData\Local\Temp | Local directory containing a user's temporary files accessible only to the user account that it is attached to. Provides full ownership to the user that owns this folder. Useful when the attacker gains control of a local/domain joined user account.|
|%PUBLIC% | C:\Users\Public | Publicly accessible directory allowing any interactive logon account full access to read, write, modify, execute, etc., files and subfolders within the directory. Alternative to the global Windows Temp Directory as it's less likely to be monitored for suspicious activity.|
|%ProgramFiles% | C:\Program Files | folder containing all 64-bit applications installed on the system. Useful for seeing what kind of applications are installed on the target system.|
|%ProgramFiles(x86)% | C:\Program Files (x86) | Folder containing all 32-bit applications installed on the system. Useful for seeing what kind of applications are installed on the target system.|

## Working with Directories and Files

- `md` or `mkdir` to create a new directory
- `rd` or `rmdir` to delete an empty directory
  - `rd /S` to force prompt to delete a directory
- `move <src> <dst>` to move directory
- `xcopy <scr> <dst> <opts>` to copy a file, removes the read-only bit [deprecated for `robocopy`]
  - use `/E` options to copy folder and subfolders, inclusing empty folders

#### Robocopy