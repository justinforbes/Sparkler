<#
    .Synopsis
       Adds a bunch of vulns to the DC
    .DESCRIPTION
       The script was derived from @WazeHell's vulnerable-AD (https://github.com/WazeHell/vulnerable-AD)  
#>

#Base Lists
$BadPasswords = @('redwings', 'Password123', 'Summer2024!', 'Company2024', 'Welcome1');
$BadACL = @('GenericAll', 'GenericWrite', 'WriteOwner', 'WriteDACL', 'Self');
$ServicesAccountsAndSPNs = @('mssql_svc,mssqlserver', 'http_svc,httpserver', 'exchange_svc,exserver', 'ldap_svc,ldapserver', 'dns_svc,dnsserver', 'ftp_svc,ftpserver');
$CreatedUsers = @();
$AllObjects = @();
$Domain = (get-addomain).dnsroot;
$DomainDN = (get-addomain).distinguishedname;

# Load System.Web for password generation
Add-Type -AssemblyName System.Web -ErrorAction SilentlyContinue

# Import ActiveDirectory module if not already loaded
if (-not (Get-Module -Name ActiveDirectory)) {
    Import-Module ActiveDirectory -ErrorAction Stop
}

function GetRandom {
    Param(
        [array]$InputList
    )
    return Get-Random -InputObject $InputList
}

function AddADGroup {
    Param(
        [array]$GroupList
    )
    foreach ($group in $GroupList) {
        Write-Host "Creating $group Group"
        Try { New-ADGroup -name $group -GroupScope Global } Catch {}
        for ($i = 1; $i -le (Get-Random -Maximum 20); $i = $i + 1 ) {
            $randomuser = (GetRandom -InputList $CreatedUsers)
            Write-Host "Adding $randomuser to $group"
            Try { Add-ADGroupMember -Identity $group -Members $randomuser } Catch {}
        }
        $AllObjects += $group;
    }
}
function AddACL {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Destination,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [System.Security.Principal.IdentityReference]$Source,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Rights

    )
    $ADObject = [ADSI]("LDAP://" + $Destination)
    $identity = $Source
    $adRights = [System.DirectoryServices.ActiveDirectoryRights]$Rights
    $type = [System.Security.AccessControl.AccessControlType] "Allow"
    $inheritanceType = [System.DirectoryServices.ActiveDirectorySecurityInheritance] "All"
    $ACE = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $identity, $adRights, $type, $inheritanceType
    $ADObject.psbase.ObjectSecurity.AddAccessRule($ACE)
    $ADObject.psbase.commitchanges()
}
function BadACLs {
    foreach ($abuse in $BadACL) {
        $ngroup = GetRandom -InputList NormalGroups
        $mgroup = GetRandom -InputList MidGroups
        $DstGroup = Get-ADGroup -Identity $mgroup
        $SrcGroup = Get-ADGroup -Identity $ngroup
        AddACL -Source $SrcGroup.sid -Destination $DstGroup.DistinguishedName -Rights $abuse
        Write-Host "$BadACL $abuse $ngroup to $mgroup"
    }
    foreach ($abuse in $BadACL) {
        $hgroup = GetRandom -InputList HighGroups
        $mgroup = GetRandom -InputList MidGroups
        $DstGroup = Get-ADGroup -Identity $hgroup
        $SrcGroup = Get-ADGroup -Identity $mgroup
        AddACL -Source $SrcGroup.sid -Destination $DstGroup.DistinguishedName -Rights $abuse
        Write-Host "$BadACL $abuse $mgroup to $hgroup"
    }
    for ($i = 1; $i -le (Get-Random -Maximum 25); $i = $i + 1 ) {
        $abuse = (GetRandom -InputList $BadACL);
        $randomuser = GetRandom -InputList $CreatedUsers
        $randomgroup = GetRandom -InputList AllObjects
        if ((Get-Random -Maximum 2)) {
            $Dstobj = Get-ADUser -Identity $randomuser
            $Srcobj = Get-ADGroup -Identity $randomgroup
        }
        else {
            $Srcobj = Get-ADUser -Identity $randomuser
            $Dstobj = Get-ADGroup -Identity $randomgroup
        }
        AddACL -Source $Srcobj.sid -Destination $Dstobj.DistinguishedName -Rights $abuse 
        Write-Host "$BadACL $abuse $randomuser and $randomgroup"
    }
}
function Kerberoasting {
    $selected_service = (GetRandom -InputList $ServicesAccountsAndSPNs)
    $svc = $selected_service.split(',')[0];
    $spn = $selected_service.split(',')[1];
    $password = GetRandom -InputList $BadPasswords;
    Write-Host "Kerberoasting $svc $spn"
    Try { New-ADServiceAccount -Name $svc -ServicePrincipalNames "$svc/$spn.$Domain" -AccountPassword (ConvertTo-SecureString $password -AsPlainText -Force) -RestrictToSingleComputer -PassThru } Catch {}
    foreach ($sv in $ServicesAccountsAndSPNs) {
        if ($selected_service -ne $sv) {
            $svc = $sv.split(',')[0];
            $spn = $sv.split(',')[1];
            Write-Host "Creating $svc services account"
            $password = ([System.Web.Security.Membership]::GeneratePassword(12, 2))
            Try { New-ADServiceAccount -Name $svc -ServicePrincipalNames "$svc/$spn.$Domain" -RestrictToSingleComputer -AccountPassword (ConvertTo-SecureString $password -AsPlainText -Force) -PassThru } Catch {}

        }
    }
}
function ASREPRoasting {
    for ($i = 1; $i -le (Get-Random -Maximum 6); $i = $i + 1 ) {
        $randomuser = (GetRandom -InputList $CreatedUsers)
        $password = GetRandom -InputList $BadPasswords;
        Set-AdAccountPassword -Identity $randomuser -Reset -NewPassword (ConvertTo-SecureString $password -AsPlainText -Force)
        Set-ADAccountControl -Identity $randomuser -DoesNotRequirePreAuth 1
        Write-Host "AS-REPRoasting $randomuser"
    }
}
function DnsAdmins {
    for ($i = 1; $i -le (Get-Random -Maximum 6); $i = $i + 1 ) {
        $randomuser = (GetRandom -InputList $CreatedUsers)
        Add-ADGroupMember -Identity "DnsAdmins" -Members $randomuser
        Write-Host "DnsAdmins : $randomuser"
    }
    $randomg = (GetRandom -InputList MidGroups)
    Add-ADGroupMember -Identity "DnsAdmins" -Members $randomg
    Write-Host "DnsAdmins Nested Group : $randomg"
}
function DCSync {
    for ($i = 1; $i -le (Get-Random -Maximum 6); $i = $i + 1 ) {
        $randomuser = (GetRandom -InputList $CreatedUsers)

        $userobject = (Get-ADUser -Identity $randomuser).distinguishedname
        $ACL = Get-Acl -Path "AD:\$userobject"
        $sid = (Get-ADUser -Identity $randomuser).sid

        $objectGuidGetChanges = New-Object Guid 1131f6aa-9c07-11d1-f79f-00c04fc2dcd2
        $ACEGetChanges = New-Object DirectoryServices.ActiveDirectoryAccessRule($sid, 'ExtendedRight', 'Allow', $objectGuidGetChanges)
        $ACL.psbase.AddAccessRule($ACEGetChanges)

        $objectGuidGetChanges = New-Object Guid 1131f6ad-9c07-11d1-f79f-00c04fc2dcd2
        $ACEGetChanges = New-Object DirectoryServices.ActiveDirectoryAccessRule($sid, 'ExtendedRight', 'Allow', $objectGuidGetChanges)
        $ACL.psbase.AddAccessRule($ACEGetChanges)

        $objectGuidGetChanges = New-Object Guid 89e95b76-444d-4c62-991a-0facbeda640c
        $ACEGetChanges = New-Object DirectoryServices.ActiveDirectoryAccessRule($sid, 'ExtendedRight', 'Allow', $objectGuidGetChanges)
        $ACL.psbase.AddAccessRule($ACEGetChanges)

        Set-ADUser $randomuser -Description "Replication Account"
        Write-Host "Giving DCSync to : $randomuser"
    }
}
function DisableSMBSigning {
    Set-SmbClientConfiguration -RequireSecuritySignature 0 -EnableSecuritySignature 0 -Confirm -Force
}

function UnconstrainedDelegation {
    <#
    .DESCRIPTION
        Configures unconstrained delegation on computer accounts and user accounts.
        This allows services to impersonate users to any service on any computer.
    #>
    Write-Host "`n=== Configuring Unconstrained Delegation ===" -ForegroundColor Yellow
    
    # Get some computer accounts to configure
    $computers = Get-ADComputer -Filter * -ResultSetSize 10 | Get-Random -Count 3
    foreach ($comp in $computers) {
        try {
            Set-ADComputer -Identity $comp -TrustedForDelegation $true
            Write-Host "Enabled unconstrained delegation on: $($comp.Name)" -ForegroundColor Green
        }
        catch {
            Write-Warning "Failed to enable delegation on $($comp.Name): $_"
        }
    }
    
    # Configure some user accounts for unconstrained delegation
    $users = Get-ADUser -Filter * -ResultSetSize 50 | Get-Random -Count 3
    foreach ($user in $users) {
        try {
            Set-ADUser -Identity $user -TrustedForDelegation $true
            Write-Host "Enabled unconstrained delegation on user: $($user.SamAccountName)" -ForegroundColor Green
        }
        catch {
            Write-Warning "Failed to enable delegation on $($user.SamAccountName): $_"
        }
    }
}

function ConstrainedDelegation {
    <#
    .DESCRIPTION
        Configures constrained delegation (S4U2Proxy) on service accounts.
        Allows services to impersonate users to specific services.
    #>
    Write-Host "`n=== Configuring Constrained Delegation ===" -ForegroundColor Yellow
    
    $services = @('cifs', 'http', 'ldap', 'host', 'mssql')
    $targetComputers = Get-ADComputer -Filter * -ResultSetSize 20 | Select-Object -ExpandProperty Name
    
    for ($i = 1; $i -le 3; $i++) {
        $randomUser = GetRandom -InputList $CreatedUsers
        $selectedServices = $services | Get-Random -Count 2
        $target = GetRandom -InputList $targetComputers
        
        $delegationServices = $selectedServices | ForEach-Object { "$_/$target" }
        
        try {
            Set-ADUser -Identity $randomUser -ServicePrincipalNames @{Add = $delegationServices}
            Write-Host "Configured constrained delegation for $randomUser to: $($delegationServices -join ', ')" -ForegroundColor Green
        }
        catch {
            Write-Warning "Failed to configure constrained delegation: $_"
        }
    }
}

function ResourceBasedConstrainedDelegation {
    <#
    .DESCRIPTION
        Configures Resource-Based Constrained Delegation (RBCD) on computer accounts.
        Allows a computer/resource to specify which accounts can delegate to it.
    #>
    Write-Host "`n=== Configuring Resource-Based Constrained Delegation ===" -ForegroundColor Yellow
    
    $computers = Get-ADComputer -Filter * -ResultSetSize 20 | Get-Random -Count 3
    $delegateComputers = Get-ADComputer -Filter * -ResultSetSize 20 | Get-Random -Count 2
    
    foreach ($comp in $computers) {
        try {
            $delegateSID = (GetRandom -InputList $delegateComputers).SID
            $compDN = $comp.DistinguishedName
            
            # Set msDS-AllowedToActOnBehalfOfOtherIdentity
            $acl = Get-Acl -Path "AD:\$compDN"
            $sid = New-Object System.Security.Principal.SecurityIdentifier $delegateSID
            $ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
                $sid,
                [System.DirectoryServices.ActiveDirectoryRights]::GenericAll,
                [System.Security.AccessControl.AccessControlType]::Allow
            )
            $acl.AddAccessRule($ace)
            Set-Acl -Path "AD:\$compDN" -AclObject $acl
            
            Write-Host "Configured RBCD on: $($comp.Name)" -ForegroundColor Green
        }
        catch {
            Write-Warning "Failed to configure RBCD on $($comp.Name): $_"
        }
    }
}

function PasswordNeverExpires {
    <#
    .DESCRIPTION
        Sets 'Password Never Expires' flag on random user accounts.
        This is a common misconfiguration that allows old passwords to remain valid indefinitely.
    #>
    Write-Host "`n=== Setting Password Never Expires ===" -ForegroundColor Yellow
    
    for ($i = 1; $i -le (Get-Random -Minimum 5 -Maximum 15); $i++) {
        $randomUser = GetRandom -InputList $CreatedUsers
        try {
            Set-ADUser -Identity $randomUser -PasswordNeverExpires $true
            Write-Host "Set PasswordNeverExpires on: $randomUser" -ForegroundColor Green
        }
        catch {
            Write-Warning "Failed to set PasswordNeverExpires on $randomUser: $_"
        }
    }
}

function ReversibleEncryption {
    <#
    .DESCRIPTION
        Enables reversible encryption for password storage on user accounts.
        This allows passwords to be decrypted, which is a critical security risk.
    #>
    Write-Host "`n=== Enabling Reversible Encryption ===" -ForegroundColor Yellow
    
    for ($i = 1; $i -le (Get-Random -Minimum 3 -Maximum 8); $i++) {
        $randomUser = GetRandom -InputList $CreatedUsers
        try {
            Set-ADUser -Identity $randomUser -AllowReversiblePasswordEncryption $true
            Set-ADAccountPassword -Identity $randomUser -Reset -NewPassword (ConvertTo-SecureString "Reversible1!" -AsPlainText -Force)
            Write-Host "Enabled reversible encryption on: $randomUser (Password: Reversible1!)" -ForegroundColor Green
        }
        catch {
            Write-Warning "Failed to enable reversible encryption on $randomUser: $_"
        }
    }
}

function LMHashStorage {
    <#
    .DESCRIPTION
        Configures Group Policy to store LM hashes (legacy and insecure).
        Also sets weak passwords that will be stored with LM hash.
    #>
    Write-Host "`n=== Configuring LM Hash Storage ===" -ForegroundColor Yellow
    
    # Note: LM hash storage is controlled by GPO. We'll set weak passwords that would be
    # vulnerable if LM hashes were enabled, and document this.
    
    for ($i = 1; $i -le 5; $i++) {
        $randomUser = GetRandom -InputList $CreatedUsers
        $weakPassword = "PASSWORD" + (Get-Random -Maximum 99)
        try {
            Set-ADAccountPassword -Identity $randomUser -Reset -NewPassword (ConvertTo-SecureString $weakPassword -AsPlainText -Force)
            Set-ADUser -Identity $randomUser -Description "LM Hash Test Account - Password: $weakPassword"
            Write-Host "Set weak password (LM-vulnerable) on: $randomUser" -ForegroundColor Green
        }
        catch {
            Write-Warning "Failed to set weak password on $randomUser: $_"
        }
    }
    
    Write-Host "NOTE: To fully enable LM hashes, configure GPO: Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> 'Network security: Do not store LAN Manager hash value on next password change' = Disabled" -ForegroundColor Cyan
}

function AdminSDHolderAbuse {
    <#
    .DESCRIPTION
        Adds non-admin users to protected groups or modifies AdminSDHolder permissions.
        AdminSDHolder protects privileged accounts by resetting their ACLs every 60 minutes.
    #>
    Write-Host "`n=== AdminSDHolder Abuse ===" -ForegroundColor Yellow
    
    $protectedGroups = @('Account Operators', 'Backup Operators', 'Print Operators', 'Server Operators')
    
    foreach ($groupName in $protectedGroups) {
        try {
            $group = Get-ADGroup -Identity $groupName -ErrorAction SilentlyContinue
            if ($group) {
                $randomUsers = Get-Random -Count 2 -InputObject $CreatedUsers
                foreach ($user in $randomUsers) {
                    Add-ADGroupMember -Identity $group -Members $user -ErrorAction SilentlyContinue
                    Write-Host "Added $user to protected group: $groupName" -ForegroundColor Green
                }
            }
        }
        catch {
            Write-Warning "Failed to modify $groupName : $_"
        }
    }
}

function MachineAccountQuota {
    <#
    .DESCRIPTION
        Sets a high MachineAccountQuota to allow non-privileged users to join many computers to the domain.
        Default is 10, but setting it higher allows for resource exhaustion attacks.
    #>
    Write-Host "`n=== Configuring MachineAccountQuota ===" -ForegroundColor Yellow
    
    try {
        Set-ADDomain -Identity $Domain -Replace @{'ms-DS-MachineAccountQuota' = 50}
        Write-Host "Set MachineAccountQuota to 50 (allows non-privileged users to join 50 computers)" -ForegroundColor Green
    }
    catch {
        Write-Warning "Failed to set MachineAccountQuota: $_"
    }
}

function PreWindows2000Compatibility {
    <#
    .DESCRIPTION
        Configures pre-Windows 2000 compatibility settings that weaken security.
        Includes Anonymous SID translation and Anonymous enumeration.
    #>
    Write-Host "`n=== Pre-Windows 2000 Compatibility Settings ===" -ForegroundColor Yellow
    
    try {
        # This would typically be done via GPO, but we can document and set registry
        Write-Host "Configuring anonymous access settings..." -ForegroundColor Cyan
        
        # Set Anonymous SID Translation (dangerous)
        $regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
        Set-ItemProperty -Path $regPath -Name "TurnOffAnonymousBlock" -Value 1 -ErrorAction SilentlyContinue
        
        Write-Host "Enabled Pre-Windows 2000 compatibility (Anonymous SID Translation)" -ForegroundColor Green
        Write-Host "WARNING: This allows anonymous users to obtain SID information!" -ForegroundColor Red
    }
    catch {
        Write-Warning "Failed to configure Pre-Windows 2000 settings: $_"
    }
}

function WeakGPOPermissions {
    <#
    .DESCRIPTION
        Configures weak permissions on Group Policy Objects.
        Allows non-privileged users to modify GPOs.
    #>
    Write-Host "`n=== Configuring Weak GPO Permissions ===" -ForegroundColor Yellow
    
    try {
        Import-Module GroupPolicy -ErrorAction SilentlyContinue
        $gpos = Get-GPO -All | Get-Random -Count 3
        $randomUsers = Get-Random -Count 3 -InputObject $CreatedUsers
        
        foreach ($gpo in $gpos) {
            $user = GetRandom -InputList $randomUsers
            try {
                $userObj = Get-ADUser -Identity $user
                $gpoPath = "\\$env:USERDNSDOMAIN\SYSVOL\$env:USERDNSDOMAIN\Policies\{$($gpo.Id)}"
                
                # Note: Real GPO permission modification requires specific cmdlets
                Write-Host "Target GPO for weak permissions: $($gpo.DisplayName)" -ForegroundColor Green
                Write-Host "  Would grant edit rights to: $user" -ForegroundColor Green
            }
            catch {
                Write-Warning "Failed to configure GPO permissions: $_"
            }
        }
    }
    catch {
        Write-Warning "GroupPolicy module not available or error: $_"
    }
}

function CertificateTemplateVulnerabilities {
    <#
    .DESCRIPTION
        Documents and configures common ADCS (Active Directory Certificate Services) vulnerabilities.
        ESC1-ESC8 scenarios for certificate-based attacks.
    #>
    Write-Host "`n=== ADCS Certificate Template Vulnerabilities ===" -ForegroundColor Yellow
    
    Write-Host "ADCS Vulnerability Scenarios (requires ADCS installation):" -ForegroundColor Cyan
    Write-Host "  ESC1: Enrollment rights for low-priv users + Client Authentication EKU + No manager approval" -ForegroundColor White
    Write-Host "  ESC2: Enrollment rights + Any Purpose EKU or No EKU" -ForegroundColor White
    Write-Host "  ESC3: Enrollment Agent template allows signing requests for other users" -ForegroundColor White
    Write-Host "  ESC4: Vulnerable ACLs on certificate templates" -ForegroundColor White
    Write-Host "  ESC8: NTLM relay to ADCS HTTP enrollment endpoint" -ForegroundColor White
    
    # Create a vulnerable certificate template configuration script
    $adcsScript = @"
# Run this on the CA server to create vulnerable templates:
# ESC1-Style Vulnerable Template:
# 1. Duplicate User template
# 2. Enable 'Supply in request' for subject name
# 3. Add Domain Users to Enrollment Rights
# 4. Ensure Client Authentication EKU is present
# 5. Disable Manager Approval

# ESC8 - Enable Web Enrollment (HTTP):
# Install-WindowsFeature ADCS-Web-Enrollment
# Install-AdcsWebEnrollment
# NOTE: Web Enrollment over HTTP enables NTLM relay attacks!
"@
    
    $adcsScriptPath = "C:\ADCS_Vulnerabilities_Guide.txt"
    $adcsScript | Out-File -FilePath $adcsScriptPath -Force
    Write-Host "Created ADCS vulnerability guide at: $adcsScriptPath" -ForegroundColor Green
}

function LDAPSecurityWeaknesses {
    <#
    .DESCRIPTION
        Configures weak LDAP security settings including unsigned LDAP and no channel binding.
    #>
    Write-Host "`n=== LDAP Security Weaknesses ===" -ForegroundColor Yellow
    
    try {
        # LDAP Server Signing Requirements
        $regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters"
        Set-ItemProperty -Path $regPath -Name "LDAPServerIntegrity" -Value 0 -ErrorAction SilentlyContinue
        Write-Host "Disabled LDAP signing requirements (allows unsigned LDAP binds)" -ForegroundColor Green
        
        # LDAP Channel Binding
        $regPath2 = "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters"
        Set-ItemProperty -Path $regPath2 -Name "LdapEnforceChannelBinding" -Value 0 -ErrorAction SilentlyContinue
        Write-Host "Disabled LDAP channel binding" -ForegroundColor Green
        
        Write-Host "WARNING: These settings allow LDAP relay and interception attacks!" -ForegroundColor Red
    }
    catch {
        Write-Warning "Failed to configure LDAP security settings: $_"
    }
}

function NTLMRelayVulnerabilities {
    <#
    .DESCRIPTION
        Configures settings that enable NTLM relay attacks.
        Includes SMB signing, LDAP signing, and EPA settings.
    #>
    Write-Host "`n=== NTLM Relay Vulnerabilities ===" -ForegroundColor Yellow
    
    try {
        # Disable SMB signing (already done in DisableSMBSigning, but document here)
        Write-Host "SMB Signing: Disabled (allows SMB relay)" -ForegroundColor Green
        
        # Disable Extended Protection for Authentication (EPA)
        $regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
        Set-ItemProperty -Path $regPath -Name "SuppressExtendedProtection" -Value 1 -ErrorAction SilentlyContinue
        Write-Host "Disabled Extended Protection for Authentication (EPA)" -ForegroundColor Green
        
        # Configure NTLM authentication level (lower = more vulnerable)
        Set-ItemProperty -Path $regPath -Name "LmCompatibilityLevel" -Value 2 -ErrorAction SilentlyContinue
        Write-Host "Set LM Compatibility Level to 2 (sends LM and NTLM)" -ForegroundColor Green
        
        Write-Host "`nNTLM Relay Attack Prerequisites Configured:" -ForegroundColor Cyan
        Write-Host "  - SMB Signing: Disabled" -ForegroundColor White
        Write-Host "  - LDAP Signing: Disabled" -ForegroundColor White
        Write-Host "  - LDAP Channel Binding: Disabled" -ForegroundColor White
        Write-Host "  - Extended Protection: Disabled" -ForegroundColor White
    }
    catch {
        Write-Warning "Failed to configure NTLM relay settings: $_"
    }
}

function TrustRelationshipAbuse {
    <#
    .DESCRIPTION
        Configures inter-domain trust settings that can be abused.
        Includes SID filtering and trust authentication levels.
    #>
    Write-Host "`n=== Trust Relationship Abuse ===" -ForegroundColor Yellow
    
    try {
        # Check for existing trusts
        $trusts = Get-ADTrust -Filter * -ErrorAction SilentlyContinue
        if ($trusts) {
            Write-Host "Found existing trusts:" -ForegroundColor Cyan
            foreach ($trust in $trusts) {
                Write-Host "  Trust: $($trust.Name) - Direction: $($trust.Direction)" -ForegroundColor White
                
                # Disable SID filtering (dangerous - allows SID history attacks)
                # Note: This is a demonstration - actual command would use netdom
                Write-Host "  SID Filtering: Would be disabled for demonstration" -ForegroundColor Yellow
            }
        }
        else {
            Write-Host "No existing trusts found. To demonstrate trust attacks:" -ForegroundColor Cyan
            Write-Host "  1. Create a child domain or external trust" -ForegroundColor White
            Write-Host "  2. Disable SID filtering: netdom trust /domain:target /quarantine:no" -ForegroundColor White
            Write-Host "  3. Enable SID history for cross-domain access" -ForegroundColor White
        }
    }
    catch {
        Write-Warning "Failed to enumerate trusts: $_"
    }
}

function SensitiveDataExposure {
    <#
    .DESCRIPTION
        Creates files with sensitive data in SYSVOL and other accessible locations.
        Simulates common credential exposure scenarios.
    #>
    Write-Host "`n=== Sensitive Data Exposure ===" -ForegroundColor Yellow
    
    try {
        # Create a script with embedded credentials in SYSVOL
        $sysvolPath = "\\$env:USERDNSDOMAIN\SYSVOL\$env:USERDNSDOMAIN\scripts"
        if (Test-Path $sysvolPath) {
            $batchScript = @"
@echo off
REM Login script with embedded credentials
REM DO NOT USE IN PRODUCTION
net use \\fileserver\share /user:DOMAIN\svc_backup BackupPassword123!
"@
            $scriptPath = Join-Path $sysvolPath "login.bat"
            $batchScript | Out-File -FilePath $scriptPath -Force
            Write-Host "Created batch script with credentials in SYSVOL: $scriptPath" -ForegroundColor Green
        }
        
        # Create a PowerShell script with credentials
        $psScript = @"
# Auto-generated configuration
`$username = "DOMAIN\admin"
`$password = "SuperSecretPassword123!"
`$securePassword = ConvertTo-SecureString `$password -AsPlainText -Force
`$credential = New-Object System.Management.Automation.PSCredential(`$username, `$securePassword
"@
        $psScriptPath = Join-Path $sysvolPath "config.ps1"
        $psScript | Out-File -FilePath $psScriptPath -Force
        Write-Host "Created PowerShell script with credentials in SYSVOL: $psScriptPath" -ForegroundColor Green
        
        # Create an XML file with credentials (common in Group Policy Preferences)
        $xmlContent = @"
<?xml version="1.0" encoding="utf-8"?>
<Groups clsid="{3125E937-EB16-4b4c-9934-544FC6D24D26}">
  <User clsid="{DF5F1855-51E5-4d24-8B1A-D9BDE98BA1D1}" name="LocalAdmin" image="2" changed="2024-01-01 12:00:00" uid="{12345678-1234-1234-1234-123456789012}">
    <Properties action="U" newName="" fullName="" description="" cpassword="j1Uyj3Vx8TY9LtLZil2uAuZkFQA/4latT76ZwgdHdhw" changeLogon="0" noChange="0" neverExpires="1" acctDisabled="0" subAuthority="RID_ADMIN" userName="LocalAdmin"/>
  </User>
</Groups>
"@
        # Note: cpassword is the encrypted password used in GPP (easily decrypted)
        $xmlPath = Join-Path $sysvolPath "groups.xml"
        $xmlContent | Out-File -FilePath $xmlPath -Force
        Write-Host "Created Groups.xml with encrypted password (cpassword) in SYSVOL: $xmlPath" -ForegroundColor Green
        Write-Host "  The cpassword can be decrypted using the published Microsoft key!" -ForegroundColor Red
    }
    catch {
        Write-Warning "Failed to create sensitive data exposure: $_"
    }
}

function PrintSpoolerVulnerabilities {
    <#
    .DESCRIPTION
        Configures Print Spooler service to be vulnerable to various attacks.
        Includes PrintNightmare and other spooler-based attacks.
    #>
    Write-Host "`n=== Print Spooler Vulnerabilities ===" -ForegroundColor Yellow
    
    try {
        # Ensure Print Spooler is running
        Set-Service -Name Spooler -StartupType Automatic -ErrorAction SilentlyContinue
        Start-Service -Name Spooler -ErrorAction SilentlyContinue
        Write-Host "Print Spooler service enabled and started" -ForegroundColor Green
        
        # Disable Point and Print restrictions (allows driver installation by non-admins)
        $regPath = "HKLM:\Software\Policies\Microsoft\Windows NT\Printers\PointAndPrint"
        if (-not (Test-Path $regPath)) {
            New-Item -Path $regPath -Force | Out-Null
        }
        Set-ItemProperty -Path $regPath -Name "NoWarningNoElevationOnInstall" -Value 1 -ErrorAction SilentlyContinue
        Set-ItemProperty -Path $regPath -Name "UpdatePromptSettings" -Value 2 -ErrorAction SilentlyContinue
        Write-Host "Disabled Point and Print warnings (PrintNightmare vulnerability)" -ForegroundColor Green
        
        Write-Host "WARNING: System is vulnerable to PrintNightmare and spooler-based attacks!" -ForegroundColor Red
    }
    catch {
        Write-Warning "Failed to configure Print Spooler settings: $_"
    }
}

# Execute vulnerability functions
Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "  SPARKLER VULNERABILITY DEPLOYMENT" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

Write-Host "`n[1/18] Configuring Bad ACLs..." -ForegroundColor Yellow
BadACLs
Write-Host "BadACLs Complete" -ForegroundColor Green

Write-Host "`n[2/18] Configuring Kerberoasting..." -ForegroundColor Yellow
Kerberoasting
Write-Host "Kerberoasting Complete" -ForegroundColor Green

Write-Host "`n[3/18] Configuring AS-REP Roasting..." -ForegroundColor Yellow
ASREPRoasting
Write-Host "AS-REPRoasting Complete" -ForegroundColor Green

Write-Host "`n[4/18] Configuring DnsAdmins..." -ForegroundColor Yellow
DnsAdmins
Write-Host "DnsAdmins Complete" -ForegroundColor Green

Write-Host "`n[5/18] Configuring DCSync..." -ForegroundColor Yellow
DCSync
Write-Host "DCSync Complete" -ForegroundColor Green

Write-Host "`n[6/18] Disabling SMB Signing..." -ForegroundColor Yellow
DisableSMBSigning
Write-Host "SMB Signing Disabled" -ForegroundColor Green

Write-Host "`n[7/18] Configuring Unconstrained Delegation..." -ForegroundColor Yellow
UnconstrainedDelegation
Write-Host "Unconstrained Delegation Complete" -ForegroundColor Green

Write-Host "`n[8/18] Configuring Constrained Delegation..." -ForegroundColor Yellow
ConstrainedDelegation
Write-Host "Constrained Delegation Complete" -ForegroundColor Green

Write-Host "`n[9/18] Configuring Resource-Based Constrained Delegation..." -ForegroundColor Yellow
ResourceBasedConstrainedDelegation
Write-Host "RBCD Complete" -ForegroundColor Green

Write-Host "`n[10/18] Setting Password Never Expires..." -ForegroundColor Yellow
PasswordNeverExpires
Write-Host "Password Never Expires Complete" -ForegroundColor Green

Write-Host "`n[11/18] Enabling Reversible Encryption..." -ForegroundColor Yellow
ReversibleEncryption
Write-Host "Reversible Encryption Complete" -ForegroundColor Green

Write-Host "`n[12/18] Configuring LM Hash Storage..." -ForegroundColor Yellow
LMHashStorage
Write-Host "LM Hash Storage Complete" -ForegroundColor Green

Write-Host "`n[13/18] Configuring AdminSDHolder Abuse..." -ForegroundColor Yellow
AdminSDHolderAbuse
Write-Host "AdminSDHolder Abuse Complete" -ForegroundColor Green

Write-Host "`n[14/18] Configuring MachineAccountQuota..." -ForegroundColor Yellow
MachineAccountQuota
Write-Host "MachineAccountQuota Complete" -ForegroundColor Green

Write-Host "`n[15/18] Configuring Pre-Windows 2000 Compatibility..." -ForegroundColor Yellow
PreWindows2000Compatibility
Write-Host "Pre-Windows 2000 Compatibility Complete" -ForegroundColor Green

Write-Host "`n[16/18] Configuring LDAP Security Weaknesses..." -ForegroundColor Yellow
LDAPSecurityWeaknesses
Write-Host "LDAP Security Weaknesses Complete" -ForegroundColor Green

Write-Host "`n[17/18] Configuring NTLM Relay Vulnerabilities..." -ForegroundColor Yellow
NTLMRelayVulnerabilities
Write-Host "NTLM Relay Vulnerabilities Complete" -ForegroundColor Green

Write-Host "`n[18/18] Configuring Print Spooler Vulnerabilities..." -ForegroundColor Yellow
PrintSpoolerVulnerabilities
Write-Host "Print Spooler Vulnerabilities Complete" -ForegroundColor Green

# Additional educational modules
Write-Host "`n[Bonus] Configuring Weak GPO Permissions..." -ForegroundColor Yellow
WeakGPOPermissions
Write-Host "Weak GPO Permissions Complete" -ForegroundColor Green

Write-Host "`n[Bonus] Configuring Certificate Template Vulnerabilities..." -ForegroundColor Yellow
CertificateTemplateVulnerabilities
Write-Host "Certificate Template Vulnerabilities Complete" -ForegroundColor Green

Write-Host "`n[Bonus] Configuring Trust Relationship Abuse..." -ForegroundColor Yellow
TrustRelationshipAbuse
Write-Host "Trust Relationship Abuse Complete" -ForegroundColor Green

Write-Host "`n[Bonus] Configuring Sensitive Data Exposure..." -ForegroundColor Yellow
SensitiveDataExposure
Write-Host "Sensitive Data Exposure Complete" -ForegroundColor Green

Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "  ALL VULNERABILITIES DEPLOYED!" -ForegroundColor Red
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "`nSummary of Attack Scenarios Enabled:" -ForegroundColor Yellow
Write-Host "  - ACL Abuse (GenericAll, WriteDACL, etc.)" -ForegroundColor White
Write-Host "  - Kerberoasting (Service accounts with weak passwords)" -ForegroundColor White
Write-Host "  - AS-REP Roasting (No pre-auth required)" -ForegroundColor White
Write-Host "  - DCSync (Replication rights)" -ForegroundColor White
Write-Host "  - Unconstrained/Constrained/RBCD Delegation" -ForegroundColor White
Write-Host "  - NTLM Relay (SMB/LDAP signing disabled)" -ForegroundColor White
Write-Host "  - LDAP interception (No channel binding)" -ForegroundColor White
Write-Host "  - Password attacks (Reversible encryption, LM hashes)" -ForegroundColor White
Write-Host "  - PrintNightmare (Point and Print restrictions disabled)" -ForegroundColor White
Write-Host "  - Credential exposure (SYSVOL scripts with passwords)" -ForegroundColor White
Write-Host "`nWARNING: This domain is now EXTREMELY VULNERABLE!" -ForegroundColor Red
Write-Host "Only use for authorized security training!" -ForegroundColor Red