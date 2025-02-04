# FTP (File Transfer Protocol)

FTP is a standard network protocol used to transfer files between a client and a server over a TCP/IP network. In the context of cybersecurity, FTP poses several security risks due to its inherent lack of encryption, making it vulnerable to man-in-the-middle attacks, credential theft, and packet sniffing. Attackers often target FTP servers with brute-force attacks, misconfigured permissions, or anonymous login exploits to gain unauthorized access to sensitive files. Secure alternatives like FTPS (FTP Secure) and SFTP (SSH File Transfer Protocol) are recommended to mitigate these risks by adding encryption and authentication layers.

---

access method (-p for no password prompt, Passive mode):
```
ftp -p 10.129.42.253

Connected to 10.129.42.253.
220 (vsFTPd 3.0.3)
Name (10.129.42.253:user): anonymous
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.

ftp>
```

**Connection & Authentication**
- open `hostname/IP` – Connect to an FTP server.
- user `username` – Log in with a username.
- pass `password` – Provide a password for authentication.
- bye / quit – Close the FTP session.

---

FTP allows a simple shell access:

**Navigation & Directory Management**
 - pwd – Print the current working directory on the remote server.
 - cd `directory` – Change the directory on the remote server.
 - lcd `directory` – Change the local working directory.
 - ls – List files in the current remote directory.
 - dir – List files and directories with detailed information.
 - mkdir `directory` – Create a directory on the remote server.
 - rmdir `directory` – Remove a directory on the remote server.

**File Transfer**
 - get `filename` – Download a file from the remote server.
 - mget `file1` `file2` ... – Download multiple files (wildcards * can be used).
 - put `filename` – Upload a file to the remote server.
 - mput `file1` `file2` ... – Upload multiple files.
 - delete `filename` – Delete a file from the remote server.

**Transfer Mode & Settings**
 - binary – Switch to binary mode for transferring files (used for images, executables, etc.).
 - ascii – Switch to ASCII mode (used for text files).
 - hash – Display # symbols during file transfer to indicate progress.
 - prompt – Toggle interactive mode for multiple file transfers.

**Miscellaneous**
 - status – Display the current FTP session status.
 - help – List available FTP commands.
 - ! – Escape to the local shell (useful for running local commands).
 - close – Disconnect from the FTP server without exiting the FTP shell.
 - passive – Toggle passive mode (useful for firewall/NAT environments).