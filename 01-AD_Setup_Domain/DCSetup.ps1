$Configuration = Get-Content -Path 01-AD_Setup_Domain\config.json | ConvertFrom-Json

Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name Shell -Value $Configuration.shell.DefaultShell

Get-WindowsFeature -Name AD-Domain-Services | Install-WindowsFeature -Verbose

Import-Module ADDSDeployment

# Determine domain/forest mode based on OS version
$osVersion = [System.Environment]::OSVersion.Version
if ($osVersion.Build -ge 20348) {
    # Windows Server 2022 or later
    $domainMode = "Win2022"
    $forestMode = "Win2022"
} else {
    # Fallback for older versions
    $domainMode = "WinThreshold"
    $forestMode = "WinThreshold"
}

Install-ADDSForest `
    -CreateDnsDelegation:$false `
    -DatabasePath "C:\Windows\NTDS" `
    -DomainMode $domainMode `
    -DomainName $Configuration.domain.DomainName `
    -DomainNetbiosName $Configuration.domain.DomainNetbiosName `
    -ForestMode $forestMode `
    -InstallDns:$true `
    -LogPath "C:\Windows\NTDS" `
    -NoRebootOnCompletion:$true `
    -SysvolPath "C:\Windows\SYSVOL" `
    -SafeModeAdministratorPassword (ConvertTo-SecureString ($Configuration.domain.SafeModeAdministratorPassword) -AsPlainText -Force) `
    -Force:$true