# Threat Intel

## Website information

### crt.sh

Info: detailed DNS information 

query format: `https://crt.sh/?q=<website.com|org|...>`

The website can be quite slow, the script `crt_script.sh` allows you to download most of the data.

### AlienVault

Info: related ip, hostnames, urls, downloadable files, whois historical record

### VirusTotal

Info: Malware details, related ips, threat level, community info

### ViewDNSinfo

Info: Detailed website information, IP, DNS, whois, port scan, lot of random...

### Wayback machine

Info: site screenshots from people, can be used to find no longer existant websites.

# Endpoint Forensic

### volatility

Simple command line tool to get information from Windows memory dump (active program details, filesystem...)

There are many good tutorials but here are a few useful commands:
``` bash
python3 vol.py -f <path to memory image> windows.pslist
python3 vol.py -f <path to memory image> windows.pstree
python3 vol.py -f <path to memory image> windows.malfind
python3 vol.py -f <path to memory image> windows.cmdline
```

### photorec

Very powerful tool that looks for file data in raw memory, ie will find even deleted files if they haven't been zeroed over.
Files names will be lost though and it might not recover large files in full as they might be split up in memory.

Launch it with `photorec` and choose a partition where our data is saved and mounted. Select the vqlid file system and choose where to save the file dumps and let run.

### `Strings` command

Reveals all ascii strings of a file in grep-able format.

# Red Teaming

## Active Directory

### Coercer 

A [python script](https://github.com/p0dalirius/Coercer) to automatically coerce a Windows server to authenticate on an arbitrary machine through 12 methods

# Misc

## Atomic Red Team

[Atomic Red Team](https://github.com/redcanaryco/atomic-red-team/tree/master) is an amazing tool sthat allwos to run exploit based on the [MITRE ATT&CK Framework](https://attack.mitre.org/) to test system response.

## Hack The box Lab walkthroughs

[0xdf](https://0xdf.gitlab.io/tags.html#active-directory) is a very comprehensive walthrough of all if not most hackthebox labs categorized by exploit.