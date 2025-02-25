# nmap

## Host Discovery

Finding out who's around.

#### Scan Network Range
```bash
$> sudo nmap 10.129.2.0/24 -sn -oA tnet | grep for | cut -d" " -f5

10.129.2.4
10.129.2.10
10.129.2.11
10.129.2.18
10.129.2.19
10.129.2.20
10.129.2.28
```

- `10.129.2.0/24` &rarr; Target network range.
- `-sn` &rarr; Disables port scanning.
- `-oA tnet` &rarr; Stores the results in all formats starting with the name 'tnet'.

note: Gives a file of list of IPs to scan to add to nmap later on (`-iL file`).

#### ip scan format

single: `sudo nmap 10.129.2.18 -sn -oA host `

multiple: `sudo nmap -sn -oA tnet 10.129.2.18 10.129.2.19 10.129.2.20`

mutliple (range): `sudo nmap -sn -oA tnet 10.129.2.18-20`









































example simple output:

```
nmap 10.129.42.253

Starting Nmap 7.80 ( https://nmap.org ) at 2021-02-25 16:07 EST
Nmap scan report for 10.129.42.253
Host is up (0.11s latency).
Not shown: 995 closed ports
PORT    STATE SERVICE
21/tcp  open  ftp
22/tcp  open  ssh
80/tcp  open  http
139/tcp open  netbios-ssn
445/tcp open  microsoft-ds

Nmap done: 1 IP address (1 host up) scanned in 2.19 seconds
```

by default: TCP scan on most common 1000 ports

---

more detailed discovery:

```
nmap -sV -sC -p- 10.129.42.253

Starting Nmap 7.80 ( https://nmap.org ) at 2021-02-25 16:18 EST
Nmap scan report for 10.129.42.253
Host is up (0.11s latency).
Not shown: 65530 closed ports
PORT    STATE SERVICE     VERSION
21/tcp  open  ftp         vsftpd 3.0.3
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_drwxr-xr-x    2 ftp      ftp          4096 Feb 25 19:25 pub
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to ::ffff:10.10.14.2
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 2
|      vsFTPd 3.0.3 - secure, fast, stable
|_End of status
22/tcp  open  ssh         OpenSSH 8.2p1 Ubuntu 4ubuntu0.1 (Ubuntu Linux; protocol 2.0)
80/tcp  open  http        Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: PHP 7.4.3 - phpinfo()
139/tcp open  netbios-ssn Samba smbd 4.6.2
445/tcp open  netbios-ssn Samba smbd 4.6.2
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Host script results:
|_nbstat: NetBIOS name: GS-SVCSCAN, NetBIOS user: <unknown>, NetBIOS MAC: <unknown> (unknown)
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2021-02-25T21:21:51
|_  start_date: N/A

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 233.68 seconds
```

-> -sC : nmap scripts shoudl be used
-> -sV : version scan
-> -p- : scann all 65,535 (TCP by default) ports

---

**nmap scripts:**

Fins the scripts with the command `locate scripts/citrix`.

example output:
```
/usr/share/nmap/scripts/citrix-brute-xml.nse
/usr/share/nmap/scripts/citrix-enum-apps-xml.nse
/usr/share/nmap/scripts/citrix-enum-apps.nse
/usr/share/nmap/scripts/citrix-enum-servers-xml.nse
/usr/share/nmap/scripts/citrix-enum-servers.nse
```

run with ` nmap --script <script name> -p<port> <host>`.

---

**banner grabbing:**

Banner Grabbing is a useful technique to fingerprint a service on a given port quickly. Certain versions of services can be vulnerable.

either `nc -nv ...ip...`

or `nmap -sV --script=banner -p...port... ...ip...`.


the `--script=` option can also do:
 - --script=ftp-anon (for anonymous FTP access checking)
 - --script=http-title (for grabbing HTTP page titles)
 - --script=ssl-cert (for SSL certificate details)