# Active Directory Hardening Script

[![PowerShell](https://img.shields.io/badge/PowerShell-5.1+-blue.svg)](https://github.com/PowerShell/PowerShell)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Active Directory](https://img.shields.io/badge/Active%20Directory-2012%20R2+-orange.svg)](https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/active-directory-domain-services)

![alt text](https://www.hackthebox.com/storage/blog/KzKxWFqShgfTkoqZBqloolCwmii4sip2.jpg)

A comprehensive PowerShell script for hardening Active Directory environments based on industry best practices and the MITRE ATT&CK framework. This script implements 12 critical security controls to reduce attack surface and strengthen domain security.

## 🎯 Features

### 12-Point Security Checklist

1. **Account Lockout Policies** - Prevent brute-force attacks
2. **LDAP Access Restrictions** - Secure LDAP communications
3. **Strong Password Policies** - Enforce robust password requirements
4. **Multi-Factor Authentication (MFA)** - Audit and configure MFA requirements
5. **LDAP Signing & Channel Binding** - Protect against relay attacks
6. **Group Managed Service Accounts (gMSA)** - Secure service account management
7. **Privileged Access Management (PAM)** - Implement tiered administration
8. **AD CS Security** - Secure Certificate Services configurations
9. **Least Privilege Principle** - Audit and enforce minimal permissions
10. **AD CS Audit** - Identify PKI misconfigurations (ESC1, ESC2)
11. **Certificate Monitoring** - Track certificate lifecycle and expiration
12. **Security Monitoring & Alerting** - Configure advanced audit policies

### Key Capabilities

- ✅ **Multilingual Support** - Works with English and Russian AD environments using RID-based group detection
- ✅ **Comprehensive Logging** - Detailed execution logs with timestamps
- ✅ **HTML Reporting** - Professional HTML reports with summary statistics
- ✅ **Safety Features** - WhatIf support for testing before implementation
- ✅ **Audit Mode** - Report-only mode for assessment without changes
- ✅ **Vulnerability Detection** - Identifies AD CS vulnerabilities (ESC1, ESC2)
- ✅ **Inactive Account Detection** - Flags dormant privileged accounts
- ✅ **Certificate Expiration Tracking** - Monitors certificate validity

## 📋 Prerequisites

### System Requirements

- Windows Server 2012 R2 or later
- PowerShell 5.1 or higher
- Active Directory PowerShell module
- Domain Administrator privileges

### Required Modules

```powershell
# Check PowerShell version
$PSVersionTable.PSVersion

# Verify ActiveDirectory module
Get-Module -ListAvailable ActiveDirectory

# Import module if needed
Import-Module ActiveDirectory
```

## 🚀 Installation

### Option 1: Clone Repository

```powershell
git clone https://github.com/aacc1on/ad-hardening-script.git
cd ad-hardening-script
```

### Option 2: Download Script

Download `AD-Hardening-Script.ps1` directly to your Domain Controller or management workstation.

### Set Execution Policy

```powershell
# Allow script execution (run as Administrator)
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

## 💻 Usage

### Basic Execution

```powershell
# Run with default settings (requires confirmation)
.\AD-Hardening-Script.ps1

# Run with verbose output
.\AD-Hardening-Script.ps1 -Verbose

# Test mode (no changes will be made)
.\AD-Hardening-Script.ps1 -WhatIf
```

### Advanced Options

```powershell
# Generate audit report only (no changes)
.\AD-Hardening-Script.ps1 -GenerateReportOnly

# Skip account lockout configuration
.\AD-Hardening-Script.ps1 -SkipAccountLockout

# Skip password policy changes
.\AD-Hardening-Script.ps1 -SkipPasswordPolicy

# Custom log path
.\AD-Hardening-Script.ps1 -LogPath "D:\ADSecurity\Logs"

# Combine multiple parameters
.\AD-Hardening-Script.ps1 -GenerateReportOnly -Verbose -LogPath "C:\Reports"
```

### Parameters

| Parameter | Type | Description | Default |
|-----------|------|-------------|---------|
| `-SkipAccountLockout` | Switch | Skip account lockout policy configuration | `$false` |
| `-SkipPasswordPolicy` | Switch | Skip password policy configuration | `$false` |
| `-GenerateReportOnly` | Switch | Audit-only mode without making changes | `$false` |
| `-LogPath` | String | Custom path for logs and reports | `C:\ADHardening_Logs` |
| `-WhatIf` | Switch | Preview changes without executing | `$false` |
| `-Verbose` | Switch | Display detailed execution information | `$false` |

## 📊 Output

The script generates two types of output:

### 1. Log File

**Location:** `C:\ADHardening_Logs\ADHardening_YYYYMMDD_HHMMSS.log`

**Format:** Text file with timestamped entries

```
[2025-01-30 14:32:15] [Info] Starting AD Hardening Process...
[2025-01-30 14:32:16] [Success] ActiveDirectory module imported successfully
[2025-01-30 14:32:18] [Warning] User john.doe hasn't logged in for 120 days
[2025-01-30 14:32:20] [Success] Account Lockout Policy configured
```

### 2. HTML Report

**Location:** `C:\ADHardening_Logs\ADHardening_Report_YYYYMMDD_HHMMSS.html`

**Contents:**
- Executive summary with success/warning/error counts
- 12-point checklist status
- Key recommendations
- Detailed findings
- Resource links

**Sample Report Preview:**

```
🔒 Active Directory Hardening Report
Domain: contoso.com
Report Date: 2025-01-30 14:35:22
Executed By: Administrator

Summary:
✅ 25 Successful operations
⚠️ 8 Warnings
❌ 0 Errors
```

## 🔒 Security Controls Implemented

### 1. Account Lockout Policy

**Default Settings:**
- Lockout threshold: 5 failed attempts
- Lockout duration: 30 minutes
- Observation window: 30 minutes

**Purpose:** Prevent brute-force password attacks

### 2. Password Policy

**Default Requirements:**
- Minimum length: 14 characters
- Maximum age: 60 days
- Minimum age: 1 day
- Password history: 24 passwords
- Complexity: Enabled

**Purpose:** Enforce strong password standards across the domain

### 3. LDAP Security

**Configurations:**
- LDAP signing required
- LDAP channel binding enabled
- Firewall rules for ports 389 and 636

**Purpose:** Protect against LDAP relay attacks and man-in-the-middle

### 4. Privileged Account Auditing

**Checks:**
- Domain Admins membership
- Enterprise Admins membership
- Schema Admins membership
- Built-in Administrators group
- Inactive privileged accounts
- Accounts without MFA/Smart Card requirement

**Purpose:** Implement least privilege and identify security gaps

### 5. AD CS Vulnerability Scanning

**Detections:**
- **ESC1:** Templates allowing subject name specification
- **ESC2:** Templates with "Any Purpose" EKU
- Overly permissive CA ACLs
- Vulnerable certificate template permissions

**Purpose:** Prevent certificate-based privilege escalation

### 6. gMSA Infrastructure

**Actions:**
- Create KDS Root Key if missing
- Identify service accounts that should be converted to gMSAs
- Flag accounts with old passwords

**Purpose:** Eliminate static service account passwords

### 7. Advanced Audit Policies

**Enabled Categories:**
- Credential Validation
- Kerberos Authentication Service
- User Account Management
- Security Group Management

**Purpose:** Enable comprehensive security event logging

## ⚠️ Important Warnings

### Before Production Use

1. **Test in Non-Production Environment First**
   - Always run in a test domain before production
   - Use `-WhatIf` parameter to preview changes
   - Review all warnings and errors carefully

2. **Backup Required**
   - Take a full system state backup of all Domain Controllers
   - Document current Group Policy settings
   - Export current security configurations

3. **Domain Controller Restart Required**
   - LDAP signing and channel binding require DC restart
   - Schedule maintenance window for production changes
   - Ensure all DCs are restarted for consistency

4. **Potential Breaking Changes**
   - Strong password policies may affect user accounts
   - LDAP signing can break legacy applications
   - Account lockout may impact automated systems

### Recommended Testing Procedure

```powershell
# Step 1: Generate audit report
.\AD-Hardening-Script.ps1 -GenerateReportOnly -Verbose

# Step 2: Review HTML report and log file
# Check for warnings and potential issues

# Step 3: Test mode execution
.\AD-Hardening-Script.ps1 -WhatIf -Verbose

# Step 4: Gradual implementation
.\AD-Hardening-Script.ps1 -SkipPasswordPolicy -SkipAccountLockout

# Step 5: Full implementation (after testing)
.\AD-Hardening-Script.ps1 -Verbose
```

## 🛠️ Troubleshooting

### Common Issues

#### Issue: "Module ActiveDirectory not found"

**Solution:**
```powershell
# Install RSAT tools on Windows 10/11
Add-WindowsCapability -Name Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0 -Online

# On Windows Server
Install-WindowsFeature -Name RSAT-AD-PowerShell
```

#### Issue: "Access Denied" errors

**Solution:**
- Ensure running as Domain Administrator
- Check UAC elevation (Run as Administrator)
- Verify Domain Admin group membership

```powershell
# Check current privileges
whoami /groups | Select-String "Domain Admins"
```

#### Issue: Script execution policy blocked

**Solution:**
```powershell
# Check current policy
Get-ExecutionPolicy

# Set appropriate policy
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser

# Or bypass for single execution
PowerShell.exe -ExecutionPolicy Bypass -File .\AD-Hardening-Script.ps1
```

#### Issue: Remote DC configuration fails

**Solution:**
- Enable PowerShell Remoting on all DCs
- Configure WinRM and firewall rules

```powershell
# On each DC
Enable-PSRemoting -Force
Set-Item WSMan:\localhost\Client\TrustedHosts * -Force
```

### Log Analysis

**Check for errors:**
```powershell
Select-String -Path "C:\ADHardening_Logs\*.log" -Pattern "\[Error\]"
```

**View warnings:**
```powershell
Select-String -Path "C:\ADHardening_Logs\*.log" -Pattern "\[Warning\]"
```

**Count successes:**
```powershell
(Select-String -Path "C:\ADHardening_Logs\*.log" -Pattern "\[Success\]").Count
```

## 📈 Post-Implementation Steps

### 1. Verify Changes

```powershell
# Check password policy
Get-ADDefaultDomainPasswordPolicy

# Verify account lockout settings
net accounts

# Check LDAP signing
Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters" -Name LDAPServerIntegrity
```

### 2. Monitor Impact

- Review Security event logs for authentication failures
- Check helpdesk tickets for password-related issues
- Monitor application logs for LDAP connectivity problems

### 3. Continuous Monitoring

**Create scheduled task for regular audits:**

```powershell
$action = New-ScheduledTaskAction -Execute "PowerShell.exe" `
    -Argument "-File C:\Scripts\AD-Hardening-Script.ps1 -GenerateReportOnly"

$trigger = New-ScheduledTaskTrigger -Weekly -DaysOfWeek Monday -At 3AM

Register-ScheduledTask -TaskName "AD Security Audit" `
    -Action $action -Trigger $trigger -User "SYSTEM" `
    -RunLevel Highest
```

### 4. Additional Hardening

- Implement Microsoft LAPS for local admin passwords
- Deploy Microsoft Defender for Identity
- Configure Azure AD Connect security features
- Implement Privileged Access Workstations (PAWs)
- Deploy AD tiered administration model

## 🔍 Compliance Mapping

This script helps meet requirements from:

- **NIST 800-53:** AC-2, AC-7, IA-2, IA-5, SC-13
- **CIS Controls:** 4.1, 4.3, 5.2, 6.2, 6.5
- **MITRE ATT&CK:** T1078, T1110, T1557, T1649
- **PCI DSS:** 8.1, 8.2, 8.5, 10.2
- **HIPAA:** §164.308(a)(4), §164.312(a)(1)

## 📚 Additional Resources

### Microsoft Documentation

- [Active Directory Security Best Practices](https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/best-practices-for-securing-active-directory)
- [Implementing Least-Privilege Administrative Models](https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/implementing-least-privilege-administrative-models)
- [Group Managed Service Accounts Overview](https://docs.microsoft.com/en-us/windows-server/security/group-managed-service-accounts/group-managed-service-accounts-overview)

### Security Tools

- [BloodHound](https://github.com/BloodHoundAD/BloodHound) - AD attack path analysis
- [Purple Knight](https://www.purple-knight.com/) - AD security assessment
- [PingCastle](https://www.pingcastle.com/) - AD security audit tool
- [ADRecon](https://github.com/adrecon/ADRecon) - AD reconnaissance tool

### Learning Resources

- [ADSecurity.org](https://adsecurity.org/) - Sean Metcalf's AD security blog
- [MITRE ATT&CK Framework](https://attack.mitre.org/) - Adversary tactics and techniques
- [SpecterOps Blog](https://posts.specterops.io/) - Advanced AD security research

## 🤝 Contributing

Contributions are welcome! Please follow these guidelines:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/improvement`)
3. Test thoroughly in lab environment
4. Commit changes (`git commit -am 'Add new security check'`)
5. Push to branch (`git push origin feature/improvement`)
6. Create Pull Request

### Development Guidelines

- Follow PowerShell best practices
- Include comment-based help
- Add error handling
- Update documentation
- Test with both English and non-English AD environments

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## ⚖️ Disclaimer

**USE AT YOUR OWN RISK**

This script makes significant changes to Active Directory security settings. While designed with best practices in mind:

- Always test in non-production environment first
- Review all changes before applying
- Maintain proper backups
- Understand the impact of each security control
- The authors are not responsible for any damage or issues

This tool is provided "as-is" without warranty of any kind.

## 👥 Authors

- **Original Author** - Initial work and 12-point security framework



## 📅 Changelog

### Version 1.0.0 (2025-01-30)

**Initial Release:**
- 12-point security hardening framework
- Multilingual support (English/Russian)
- HTML reporting
- Comprehensive logging
- AD CS vulnerability detection
- gMSA infrastructure setup
- Advanced audit policy configuration

---

**Last Updated:** January 30, 2025

**Recommended Review Frequency:** Quarterly or after major AD changes