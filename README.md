<p align="center">
  <img src="https://raw.githubusercontent.com/kurobeats/Sparkler/refs/heads/main/logo.png" alt="Sparkler Logo" width="300">
</p>
# Sparkler 💥

**Sparkler Bomb** /ˈspɑːklə bɒm/ *noun*

> A bottle full of sparkler dust that once lit, is highly unpredictable.

---

## Overview

Sparkler is a comprehensive Active Directory (AD) lab deployment and vulnerability injection tool designed for **security professionals, penetration testers, and students** learning Active Directory security. It creates realistic, enterprise-grade AD environments with intentional security weaknesses for hands-on learning.

Forked from [BadBlood](https://github.com/davidprowe/BadBlood) by David Rowe, mashed together with kurobeats' [Active-Directory-User-Script](https://github.com/kurobeats/Active-Directory-User-Script) and WazeHell's [vulnerable-AD](https://github.com/WazeHell/vulnerable-AD).

### Key Features

- 🏢 **Realistic Enterprise Structure** - Multi-tier OU hierarchy with geographic and functional divisions
- 👥 **Randomized Object Generation** - Thousands of users, groups, and computers with realistic naming
- 🔓 **22+ Vulnerability Modules** - Comprehensive attack surface for AD penetration testing practice
- 🔄 **Non-Deterministic Output** - Every deployment creates a unique environment
- 🎓 **Educational Focus** - Designed for training and certification preparation (OSCP, CRTP, CRTE, etc.)
- ✅ **Windows Server 2022 Compatible** - Supports modern AD features and legacy configurations

---

## ⚠️ WARNING

**This tool is for authorized security training and research only.**

- **NEVER** run in production environments
- **NEVER** run on systems without explicit authorization
- Creates intentionally vulnerable Active Directory configurations
- Leaves systems in an insecure state

---

## Table of Contents

- [Installation](#installation)
- [Quick Start](#quick-start)
- [Architecture](#architecture)
- [Vulnerability Modules](#vulnerability-modules)
- [Learning Objectives](#learning-objectives)
- [Windows Server Compatibility](#windows-server-compatibility)
- [Troubleshooting](#troubleshooting)
- [Contributing](#contributing)
- [License](#license)

---

## Installation

### Prerequisites

- Windows Server 2016, 2019, or **2022** (Domain Controller)
- PowerShell 5.1 or later
- Active Directory Domain Services role
- Administrative privileges

### Setup

1. Clone or download the repository to your lab Domain Controller:
```powershell
git clone https://github.com/kurobeats/Sparkler.git
cd Sparkler
```

2. Review and modify `01-AD_Setup_Domain/config.json` for your environment:
```json
{
    "shell": {
        "DefaultShell": "explorer.exe"
    },
    "domain": {
        "DomainName": "sparkler.bmb",
        "DomainNetbiosName": "SPARKLER",
        "SafeModeAdministratorPassword": "Password123!"
    }
}
```

---

## Quick Start

### First Run (Domain Setup)

On a fresh Windows Server installation:

```powershell
.\Invoke-Sparkler.ps1
```

Type `yes` when prompted. The system will:
1. Install AD Domain Services
2. Create the forest/domain
3. **Reboot automatically**

### Second Run (Population & Vulnerabilities)

After reboot, run again:

```powershell
.\Invoke-Sparkler.ps1
```

This will populate the domain with:
- 1,000-5,000 randomized user accounts
- 100-500 security groups
- 50-150 computer accounts
- Complex OU structure
- **22+ vulnerability configurations**

---

## Architecture

### Directory Structure

```
Sparkler/
├── Invoke-Sparkler.ps1              # Main orchestration script
├── 01-AD_Setup_Domain/              # Domain controller setup
│   ├── DCSetup.ps1
│   └── config.json
├── 02-AD_LAPS_Install/              # LAPS installation (Legacy & Windows LAPS)
├── 03-AD_OU_CreateStructure/        # Organizational Unit hierarchy
├── 04-AD_Users_Create/              # User generation with realistic data
├── 05-AD_Groups_Create/             # Security group creation
├── 06-AD_Computers_Create/          # Computer account generation
├── 07-AD_Permissions_Randomiser/    # ACL randomization
├── 08-AD_Random_Groups/             # Group membership randomization
├── 09-AD_Misc_Vulns/                # 🎯 Vulnerability injection
└── AD_OU_SetACL/                    # ACL permission functions
```

### OU Hierarchy Created

```
DC=sparkler,DC=bmb
├── OU=Admin
│   ├── OU=Enterprise (T0-*)
│   ├── OU=Global (T1-*)
│   └── OU=National (T2-*)
├── OU=Global
│   └── [3-Letter Affiliate Codes]
├── OU=National
│   └── [3-Letter Affiliate Codes]
├── OU=Staff
├── OU=SCADA
├── OU=Quarantine
└── [Regional OUs: Russia, Australia, Asia, etc.]
```

Each affiliate code OU contains:
- `ServiceAccounts`
- `Groups`
- `Devices`
- `Test`
- `Managed`

---

## Vulnerability Modules

Sparkler includes **22 comprehensive vulnerability modules** across multiple attack categories:

### 🔐 Credential Attacks

| Module | Description | Attack Technique |
|--------|-------------|------------------|
| **Kerberoasting** | Service accounts with weak passwords & SPNs | T1558.003 |
| **AS-REP Roasting** | Accounts with "Do not require Kerberos preauthentication" | T1558.004 |
| **Password Never Expires** | Long-term credential validity | T1078 |
| **Reversible Encryption** | Store passwords using reversible encryption | T1003 |
| **LM Hash Storage** | Legacy LM hash compatibility | T1003.002 |
| **Sensitive Data Exposure** | Credentials in SYSVOL scripts & GPP | T1552.001 |

### 🎯 Access Control Abuse

| Module | Description | Attack Technique |
|--------|-------------|------------------|
| **Bad ACLs** | Dangerous permissions (GenericAll, WriteDACL, etc.) | T1222 |
| **DCSync** | Replicate directory changes permissions | T1003.006 |
| **AdminSDHolder Abuse** | Protected group membership | T1078 |
| **Weak GPO Permissions** | Non-privileged GPO modification rights | T1552.010 |

### 🔄 Delegation Attacks

| Module | Description | Attack Technique |
|--------|-------------|------------------|
| **Unconstrained Delegation** | TrustedForDelegation enabled | T1558 |
| **Constrained Delegation** | S4U2Proxy configuration | T1558 |
| **Resource-Based Constrained Delegation** | msDS-AllowedToActOnBehalfOfOtherIdentity | T1558 |

### 🌐 Network Protocol Attacks

| Module | Description | Attack Technique |
|--------|-------------|------------------|
| **SMB Signing Disabled** | No SMB message signing | T1557 |
| **LDAP Security Weaknesses** | Unsigned LDAP & no channel binding | T1557 |
| **NTLM Relay Vulnerabilities** | Multi-protocol relay configuration | T1557 |
| **Pre-Windows 2000 Compatibility** | Anonymous SID translation | T1087 |

### 🖨️ Service-Specific Attacks

| Module | Description | Attack Technique |
|--------|-------------|------------------|
| **DnsAdmins** | DNS admin group membership abuse | T1078 |
| **Print Spooler Vulnerabilities** | PrintNightmare configuration | T1569 |
| **Certificate Template Vulnerabilities** | ADCS ESC1-ESC8 scenarios | T1550 |

### 🏢 Domain Configuration

| Module | Description | Attack Technique |
|--------|-------------|------------------|
| **MachineAccountQuota** | High computer join limits | T1133 |
| **Trust Relationship Abuse** | Cross-domain trust attacks | T1550 |

---

## Learning Objectives

### For Penetration Testers

Practice real-world AD attack chains:
1. **Reconnaissance** - LDAP enumeration, user/computer discovery
2. **Initial Access** - AS-REP Roasting, credential exposure
3. **Privilege Escalation** - Kerberoasting, delegation abuse, ACL exploitation
4. **Lateral Movement** - NTLM relay, pass-the-hash, pass-the-ticket
5. **Domain Compromise** - DCSync, Golden/Silver tickets

### For Defenders

Learn to detect and prevent:
- Abnormal LDAP queries
- Kerberos ticket anomalies
- Privileged group modifications
- DCSync detection (Event ID 4662, 5136)
- NTLM authentication patterns

### For Certification Preparation

Relevant certifications supported:
- **OSCP** - AD attack methodology
- **CRTP** (Certified Red Team Professional) - Full AD exploitation
- **CRTE** (Certified Red Team Expert) - Advanced AD attacks
- **OSWE** - Web app + AD integration scenarios

---

## Windows Server Compatibility

| Version | Status | Notes |
|---------|--------|-------|
| Windows Server 2016 | ✅ Supported | Legacy LAPS required |
| Windows Server 2019 | ✅ Supported | Legacy LAPS required |
| Windows Server 2022 | ✅ **Fully Supported** | Native Windows LAPS + Win2022 Domain Mode |

### Windows Server 2022 Features

- **Automatic detection** and configuration of `Win2022` domain/forest functional level
- **Native Windows LAPS** support (built-in, no separate installation)
- **Modern security features** with intentional misconfigurations for testing

---

## Troubleshooting

### Common Issues

**Issue**: Script fails with "AD: drive not found"
```powershell
# Solution: Import module manually
Import-Module ActiveDirectory
.\Invoke-Sparkler.ps1
```

**Issue**: LAPS installation fails on Server 2022
```powershell
# Windows Server 2022 uses built-in LAPS
# The script auto-detects and uses the correct version
```

**Issue**: Computer creation loops indefinitely
```powershell
# Fixed in latest version - safety limits (10,000 iterations) prevent infinite loops
```

### Safety Features

- **Loop iteration limits** on all `do-while` loops
- **Try-catch error handling** throughout
- **Progress indicators** for long-running operations
- **Automatic AD: drive validation**

---

## Contributing

Contributions welcome! Areas for expansion:
- Additional vulnerability modules
- Detection rules for defenders
- Reporting/analytics features
- Cloud (Azure AD) integration

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

---

## Acknowledgments

- **David Rowe** - Original BadBlood creator
- **kurobeats** - Active Directory user generation scripts
- **WazeHell** - Vulnerable-AD concepts
- **Microsoft** - Active Directory and security research

---

## License

This project is provided for educational purposes only. See [LICENSE](LICENSE) for details.

**Remember**: With great power comes great responsibility. Only use this tool in authorized lab environments.

---

## Quick Reference Card

```powershell
# Deploy complete vulnerable AD lab
.\Invoke-Sparkler.ps1  # Run twice (once for setup, once after reboot)

# Individual modules (advanced usage)
.\01-AD_Setup_Domain\DCSetup.ps1
.\04-AD_Users_Create\CreateUsers.ps1
.\09-AD_Misc_Vulns\Add-MiscVulns.ps1
```

**Estimated deployment time**: 30-60 minutes depending on object count

**Recommended VM specs**: 4+ vCPUs, 8GB+ RAM, 100GB+ disk
