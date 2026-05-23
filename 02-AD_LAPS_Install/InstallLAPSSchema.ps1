function Get-ScriptDirectory {
    Split-Path -Parent $PSCommandPath
}
$scriptPath = Get-ScriptDirectory

# Check if Windows LAPS (built-in) is available (Windows Server 2022 and later)
$osVersion = [System.Environment]::OSVersion.Version
$isWindowsLAPS = $osVersion.Build -ge 20348

if ($isWindowsLAPS) {
    Write-Host "Detected Windows Server 2022 or later. Using built-in Windows LAPS." -ForegroundColor Green

    # Import the LAPS module (built into Windows Server 2022)
    Import-Module LAPS -ErrorAction SilentlyContinue

    if (Get-Command Update-LapsADSchema -ErrorAction SilentlyContinue) {
        # Update the AD schema for Windows LAPS
        Update-LapsADSchema -Confirm:$false
        Write-Host "Windows LAPS schema updated successfully." -ForegroundColor Green
    } else {
        Write-Warning "Windows LAPS PowerShell module not available. Ensure the LAPS feature is installed."
    }
} else {
    Write-Host "Detected older Windows Server version. Using legacy LAPS." -ForegroundColor Yellow

    # Legacy LAPS installation for older systems
    if (Test-Path ($scriptpath + "\admpwd.ps")) {
        Copy-Item -Path ($scriptpath + "\admpwd.ps") -Destination "C:\Windows\System32\WindowsPowerShell\v1.0\Modules" -Recurse -Force
        Get-ChildItem -Path ($scriptpath + "\admpwd.ps") -Recurse | ForEach-Object {
            Copy-Item -LiteralPath $_.FullName -Destination "C:\Windows\System32\WindowsPowerShell\v1.0\Modules\admpwd.ps" -Force
        }
    }

    if (Test-Path ($scriptpath + "\AdmPwd.admx")) {
        Copy-Item -Path ($scriptpath + "\AdmPwd.admx") -Destination "C:\Windows\PolicyDefinitions" -Force
    }

    if (Test-Path ($scriptpath + "\AdmPwd.adml")) {
        Copy-Item -Path ($scriptpath + "\AdmPwd.adml") -Destination "C:\Windows\PolicyDefinitions\en-US" -Force
    }

    Import-Module ADMPwd.ps -ErrorAction SilentlyContinue

    if (Get-Command Update-AdmPwdADSchema -ErrorAction SilentlyContinue) {
        Update-AdmPwdADSchema
        Set-AdmPwdComputerSelfPermission -OrgUnit (Get-ADDomain).DistinguishedName
    } else {
        Write-Warning "Legacy LAPS module not available. Skipping LAPS schema update."
    }
}