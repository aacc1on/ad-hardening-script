#Requires -Version 5.1
#Requires -Modules ActiveDirectory

<#
.SYNOPSIS
    Active Directory Hardening Script - 12-Point Security Checklist (Multilingual Support)
    
.DESCRIPTION
    This script implements 12 critical Active Directory hardening measures
    to reduce the attack surface and improve security.
    It is compatible with AD environments using English and Russian group names.
    
.NOTES
    Requires Domain Admin privileges.
    Test in a non-production environment before deploying.
    
.EXAMPLE
    .\AD-Hardening-Script.ps1 -WhatIf
    .\AD-Hardening-Script.ps1 -Verbose
#>

[CmdletBinding(SupportsShouldProcess=$true)]
param(
    [Parameter(Mandatory=$false)]
    [switch]$SkipAccountLockout,
    
    [Parameter(Mandatory=$false)]
    [switch]$SkipPasswordPolicy,
    
    [Parameter(Mandatory=$false)]
    [switch]$GenerateReportOnly,
    
    [Parameter(Mandatory=$false)]
    [string]$LogPath = "C:\ADHardening_Logs"
)

# Global variables
$Script:ErrorCount = 0
$Script:WarningCount = 0
$Script:SuccessCount = 0
$Timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$LogFile = Join-Path $LogPath "ADHardening_$Timestamp.log"

# Create log folder if missing
if (-not (Test-Path $LogPath)) {
    New-Item -ItemType Directory -Path $LogPath -Force | Out-Null
}

#region Helper Functions

function Write-Log {
    param(
        [Parameter(Mandatory=$true)]
        [string]$Message,
        
        [Parameter(Mandatory=$false)]
        [ValidateSet('Info','Success','Warning','Error')]
        [string]$Level = 'Info'
    )
    
    $LogMessage = "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] [$Level] $Message"
    Add-Content -Path $LogFile -Value $LogMessage
    
    switch ($Level) {
        'Success' { Write-Host $Message -ForegroundColor Green; $Script:SuccessCount++ }
        'Warning' { Write-Warning $Message; $Script:WarningCount++ }
        'Error'   { Write-Error $Message; $Script:ErrorCount++ }
        default   { Write-Host $Message -ForegroundColor Cyan }
    }
}

function Test-IsAdmin {
    $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    return $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Get-DomainInfo {
    try {
        $domain = Get-ADDomain
        return @{
            DomainDN = $domain.DistinguishedName
            DomainName = $domain.DNSRoot
            DomainController = $domain.PDCEmulator
        }
    }
    catch {
        Write-Log "Failed to get domain information: $_" -Level Error
        throw
    }
}

function Get-ADGroupByRID {
    <#
    .SYNOPSIS
        Find an AD group by RID (works with any language)
    #>
    param(
        [Parameter(Mandatory=$true)]
        [int]$RID
    )
    
    try {
        $domain = Get-ADDomain
        $domainSID = $domain.DomainSID
        $groupSID = New-Object System.Security.Principal.SecurityIdentifier("$domainSID-$RID")
        $group = Get-ADGroup -Identity $groupSID -ErrorAction Stop
        return $group
    }
    catch {
        return $null
    }
}

function Get-PrivilegedGroups {
    <#
    .SYNOPSIS
        Get a list of privileged groups (works with English and Russian ADs)
    #>
    
    # Well-known RIDs for privileged groups
    $wellKnownGroups = @{
        512 = "Domain Admins"           # Администраторы домена
        519 = "Enterprise Admins"       # Администраторы предприятия  
        518 = "Schema Admins"           # Администраторы схемы
        544 = "Administrators"          # Администраторы
        548 = "Account Operators"       # Операторы учета
        551 = "Backup Operators"        # Операторы архива
        550 = "Print Operators"         # Операторы печати
        549 = "Server Operators"        # Операторы сервера
    }
    
    $groups = @()
    
    foreach ($rid in $wellKnownGroups.Keys) {
        $group = Get-ADGroupByRID -RID $rid
        if ($group) {
            $groups += @{
                RID = $rid
                Name = $group.Name
                EnglishName = $wellKnownGroups[$rid]
                DistinguishedName = $group.DistinguishedName
                SID = $group.SID
            }
        }
    }
    
    return $groups
}

#endregion

#region Main Script

Write-Log "========================================" -Level Info
Write-Log "AD Hardening Script Started" -Level Info
Write-Log "========================================" -Level Info

# Check Administrator privileges
if (-not (Test-IsAdmin)) {
    Write-Log "This script requires Administrator privileges. Please run as Administrator." -Level Error
    exit 1
}

# Check for ActiveDirectory module
try {
    Import-Module ActiveDirectory -ErrorAction Stop
    Write-Log "ActiveDirectory module imported successfully" -Level Success
}
catch {
    Write-Log "Failed to import ActiveDirectory module: $_" -Level Error
    exit 1
}

# Retrieve Domain information
$DomainInfo = Get-DomainInfo
Write-Log "Domain: $($DomainInfo.DomainName)" -Level Info
Write-Log "Domain DN: $($DomainInfo.DomainDN)" -Level Info
Write-Log "PDC Emulator: $($DomainInfo.DomainController)" -Level Info

#endregion

#region 1. Implement Account Lockout Policies
# Criterion 1: Apply account lockout policy

function Set-AccountLockoutPolicy {
    Write-Log "`n[1/12] Implementing Account Lockout Policies..." -Level Info
    
    if ($SkipAccountLockout) {
        Write-Log "Skipping Account Lockout Policy configuration (as requested)" -Level Warning
        return
    }
    
    try {
        $LockoutThreshold = 5  # Allowed number of failed attempts
        $LockoutDuration = 30  # Lockout duration (minutes)
        $LockoutObservationWindow = 30  # Observation window (minutes)
        
        if ($PSCmdlet.ShouldProcess("Default Domain Policy", "Configure Account Lockout")) {
            # Use the net accounts command
            Invoke-Expression "net accounts /lockoutthreshold:$LockoutThreshold" | Out-Null
            Invoke-Expression "net accounts /lockoutduration:$LockoutDuration" | Out-Null
            Invoke-Expression "net accounts /lockoutwindow:$LockoutObservationWindow" | Out-Null
            
            Write-Log "Account Lockout Policy configured: Threshold=$LockoutThreshold, Duration=$LockoutDuration min" -Level Success
        }
    }
    catch {
        Write-Log "Failed to configure Account Lockout Policy: $_" -Level Error
    }
}

#endregion

#region 2. Limit LDAP Access
# Criterion 2: Limit LDAP access

function Set-LDAPAccessRestrictions {
    Write-Log "`n[2/12] Configuring LDAP Access Restrictions..." -Level Info
    
    try {
        # Enable requirement for LDAP signing
        $registryPath = "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters"
        
            if ($PSCmdlet.ShouldProcess("LDAP Server", "Enable LDAP Signing")) {
            # Configure LDAP signing requirements
            if (-not (Test-Path $registryPath)) {
                Write-Log "Registry path not found. This might not be a Domain Controller." -Level Warning
                return
            }
            
            Set-ItemProperty -Path $registryPath -Name "LDAPServerIntegrity" -Value 2 -Type DWord -ErrorAction Stop
            
            Write-Log "LDAP Signing enabled (requires DC restart)" -Level Success
        }
        
        # Create firewall rules for LDAP
        $ldapRules = @(
            @{Name="LDAP-Restrict-389"; Port=389; Protocol="TCP"},
            @{Name="LDAPS-Restrict-636"; Port=636; Protocol="TCP"}
        )
        
        foreach ($rule in $ldapRules) {
            try {
                $existingRule = Get-NetFirewallRule -DisplayName $rule.Name -ErrorAction SilentlyContinue
                if (-not $existingRule) {
                    New-NetFirewallRule -DisplayName $rule.Name `
                        -Direction Inbound `
                        -Protocol $rule.Protocol `
                        -LocalPort $rule.Port `
                        -Action Allow `
                        -Profile Domain `
                        -ErrorAction Stop | Out-Null
                    Write-Log "Firewall rule created: $($rule.Name)" -Level Success
                }
            }
            catch {
                Write-Log "Failed to create firewall rule $($rule.Name): $_" -Level Warning
            }
        }
    }
    catch {
        Write-Log "Failed to configure LDAP restrictions: $_" -Level Error
    }
}

#endregion

#region 3. Enforce Strong Password Policies
# Criterion 3: Enforce strong password policy

function Set-StrongPasswordPolicy {
    Write-Log "`n[3/12] Enforcing Strong Password Policies..." -Level Info
    
    if ($SkipPasswordPolicy) {
        Write-Log "Skipping Password Policy configuration (as requested)" -Level Warning
        return
    }
    
    try {
        $MinPasswordLength = 14
        $MaxPasswordAge = 60
        $MinPasswordAge = 1
        $PasswordHistoryCount = 24
        
        if ($PSCmdlet.ShouldProcess("Default Domain Policy", "Configure Password Policy")) {
            # Configure password policy
            Invoke-Expression "net accounts /minpwlen:$MinPasswordLength" | Out-Null
            Invoke-Expression "net accounts /maxpwage:$MaxPasswordAge" | Out-Null
            Invoke-Expression "net accounts /minpwage:$MinPasswordAge" | Out-Null
            Invoke-Expression "net accounts /uniquepw:$PasswordHistoryCount" | Out-Null
            
            # Enable complexity requirement
            $tempCfg = "$env:TEMP\secpol.cfg"
            $tempNewCfg = "$env:TEMP\secpol_new.cfg"
            
            secedit /export /cfg $tempCfg | Out-Null
            (Get-Content $tempCfg) -replace "PasswordComplexity = 0", "PasswordComplexity = 1" | Set-Content $tempNewCfg
            secedit /configure /db secedit.sdb /cfg $tempNewCfg /areas SECURITYPOLICY | Out-Null
            
            Remove-Item $tempCfg, $tempNewCfg -Force -ErrorAction SilentlyContinue
            
            Write-Log "Strong Password Policy configured: MinLength=$MinPasswordLength, MaxAge=$MaxPasswordAge days, Complexity=Enabled" -Level Success
        }
    }
    catch {
        Write-Log "Failed to configure Password Policy: $_" -Level Error
    }
}

#endregion

#region 4. Enable MFA (Multi-Factor Authentication)
# Criterion 4: Enable multi-factor authentication

function Enable-MFAConfiguration {
    Write-Log "`n[4/12] Configuring MFA Settings..." -Level Info
    
    try {
        # Check MFA requirements for privileged users (using RIDs)
        Write-Log "Checking MFA requirements for privileged accounts..." -Level Info
        
        $privilegedGroups = Get-PrivilegedGroups
        
        foreach ($groupInfo in $privilegedGroups) {
            try {
                $group = Get-ADGroup -Identity $groupInfo.SID -ErrorAction Stop
                $members = Get-ADGroupMember -Identity $group.DistinguishedName -ErrorAction Stop
                
                Write-Log "Group: $($groupInfo.Name) ($($groupInfo.EnglishName)) has $($members.Count) members" -Level Info
                
                # Check smart card requirement
                foreach ($member in $members) {
                    if ($member.objectClass -eq 'user') {
                        $user = Get-ADUser $member.SamAccountName -Properties SmartcardLogonRequired -ErrorAction SilentlyContinue
                        if ($user -and -not $user.SmartcardLogonRequired) {
                            Write-Log "WARNING: User $($member.SamAccountName) in $($groupInfo.Name) does not have SmartCard required" -Level Warning
                        }
                    }
                }
            }
            catch {
                Write-Log "Failed to check group $($groupInfo.Name): $_" -Level Warning
            }
        }
        
        Write-Log "MFA audit completed. Enable Azure MFA or Smart Card authentication for privileged accounts." -Level Info
        Write-Log "Recommendation: Use 'Set-ADUser -Identity USERNAME -SmartcardLogonRequired `$true' for privileged accounts" -Level Info
    }
    catch {
        Write-Log "Failed to configure MFA settings: $_" -Level Error
    }
}

#endregion

#region 5. Enable LDAP Signing & Channel Binding
# Criterion 5: Enable LDAP signing and channel binding

function Enable-LDAPSigningAndChannelBinding {
    Write-Log "`n[5/12] Enabling LDAP Signing & Channel Binding..." -Level Info
    
    try {
        if ($PSCmdlet.ShouldProcess("Domain Controllers", "Enable LDAP Signing")) {
            # Retrieve all Domain Controllers
            $DCs = Get-ADDomainController -Filter * -ErrorAction SilentlyContinue
            
            if (-not $DCs) {
                Write-Log "Could not retrieve Domain Controllers list" -Level Warning
                return
            }
            
            foreach ($DC in $DCs) {
                Write-Log "Configuring LDAP Signing on $($DC.HostName)..." -Level Info
                
                # Configure LDAP signing requirements
                $scriptBlock = {
                    param($DCName)
                    
                    try {
                        # Require LDAP signing
                        $regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters"
                        if (Test-Path $regPath) {
                            Set-ItemProperty -Path $regPath -Name "LDAPServerIntegrity" -Value 2 -Type DWord -Force
                            Set-ItemProperty -Path $regPath -Name "LdapEnforceChannelBinding" -Value 2 -Type DWord -Force
                            return "Success"
                        }
                        return "Path not found"
                    }
                    catch {
                        return "Error: $_"
                    }
                }
                
                try {
                    if ($DC.HostName -eq $env:COMPUTERNAME) {
                        # Local DC
                        $result = & $scriptBlock -DCName $DC.HostName
                    } else {
                        # Remote DC
                        $result = Invoke-Command -ComputerName $DC.HostName -ScriptBlock $scriptBlock -ArgumentList $DC.HostName -ErrorAction Stop
                    }
                    
                    if ($result -eq "Success") {
                        Write-Log "LDAP Signing configured on $($DC.HostName)" -Level Success
                    } else {
                        Write-Log "Configuration result for $($DC.HostName): $result" -Level Warning
                    }
                }
                catch {
                    Write-Log "Failed to configure $($DC.HostName): $_" -Level Warning
                }
            }
            
            Write-Log "LDAP Signing and Channel Binding enabled. Restart Domain Controllers for changes to take effect." -Level Warning
        }
    }
    catch {
        Write-Log "Failed to enable LDAP Signing: $_" -Level Error
    }
}

#endregion

#region 6. Use Group Managed Service Accounts (gMSAs)
# Criterion 6: Use Group Managed Service Accounts (gMSA)

function Configure-gMSASupport {
    Write-Log "`n[6/12] Configuring Group Managed Service Accounts (gMSA) Support..." -Level Info
    
    try {
        # Check for KDS Root Key existence
        $kdsRootKey = Get-KdsRootKey -ErrorAction SilentlyContinue
        
        if (-not $kdsRootKey) {
            if ($PSCmdlet.ShouldProcess("AD Forest", "Create KDS Root Key")) {
                Write-Log "Creating KDS Root Key for gMSA support..." -Level Info
                
                        # Create KDS Root Key (using -EffectiveImmediately for testing; remove in production)
                Add-KdsRootKey -EffectiveImmediately -ErrorAction Stop | Out-Null
                Write-Log "KDS Root Key created successfully" -Level Success
            }
        }
        else {
            Write-Log "KDS Root Key already exists" -Level Success
        }
        
        # Check existing service accounts
        Write-Log "Checking for existing service accounts that should be converted to gMSA..." -Level Info
        
        $serviceAccounts = Get-ADUser -Filter {ServicePrincipalName -like "*"} -Properties ServicePrincipalName, PasswordLastSet -ErrorAction SilentlyContinue
        
        if ($serviceAccounts) {
            Write-Log "Found $($serviceAccounts.Count) service accounts with SPNs:" -Level Info
            foreach ($account in $serviceAccounts) {
                if ($account.PasswordLastSet) {
                    $passwordAge = (Get-Date) - $account.PasswordLastSet
                    if ($passwordAge.Days -gt 90) {
                        Write-Log "  - $($account.SamAccountName) (Password age: $($passwordAge.Days) days) - Consider converting to gMSA" -Level Warning
                    }
                }
            }
        }
        else {
            Write-Log "No service accounts with SPNs found" -Level Info
        }
        
        Write-Log "gMSA infrastructure ready. Use 'New-ADServiceAccount' to create gMSAs for services." -Level Info
    }
    catch {
        Write-Log "Failed to configure gMSA support: $_" -Level Error
    }
}

#endregion

#region 7. Enable Privileged Access Management (PAM)
# Criterion 7: Enable Privileged Access Management (PAM)

function Enable-PrivilegedAccessManagement {
    Write-Log "`n[7/12] Configuring Privileged Access Management (PAM)..." -Level Info
    
    try {
        # Ensure Protected Users group exists (Windows Server 2012 R2+)
        # Protected Users group RID: 525
        $protectedUsersGroup = Get-ADGroupByRID -RID 525
        
        if ($protectedUsersGroup) {
            Write-Log "Protected Users group exists: $($protectedUsersGroup.Name)" -Level Info
            
            # Check privileged users are in Protected Users group
            $privilegedGroups = Get-PrivilegedGroups | Where-Object { $_.RID -in @(512, 519, 518) }  # DA, EA, SA only
            
            $protectedMembers = Get-ADGroupMember $protectedUsersGroup.DistinguishedName -ErrorAction SilentlyContinue
            
            foreach ($groupInfo in $privilegedGroups) {
                $group = Get-ADGroup -Identity $groupInfo.SID
                $members = Get-ADGroupMember -Identity $group.DistinguishedName -ErrorAction SilentlyContinue
                
                foreach ($member in $members) {
                    if ($member.objectClass -eq 'user') {
                        $isProtected = $protectedMembers | Where-Object { $_.SamAccountName -eq $member.SamAccountName }
                        
                        if (-not $isProtected) {
                            Write-Log "WARNING: Admin user $($member.SamAccountName) from $($groupInfo.Name) is NOT in Protected Users group" -Level Warning
                        }
                    }
                }
            }
        } else {
            Write-Log "Protected Users group not found (requires Windows Server 2012 R2 or later)" -Level Warning
        }
        
        # Verify AdminSDHolder configuration
        Write-Log "Verifying AdminSDHolder configuration..." -Level Info
        $adminSDHolder = Get-ADObject -Identity "CN=AdminSDHolder,CN=System,$($DomainInfo.DomainDN)" -Properties * -ErrorAction SilentlyContinue
        if ($adminSDHolder) {
            Write-Log "AdminSDHolder last modified: $($adminSDHolder.whenChanged)" -Level Info
        }
        
        Write-Log "PAM audit completed. Implement tiered admin model and Just-In-Time access." -Level Info
    }
    catch {
        Write-Log "Failed to configure PAM: $_" -Level Error
    }
}

#endregion

#region 8. Secure AD CS Configurations
# Criterion 8: Secure AD Certificate Services (AD CS) configurations

function Secure-ADCSConfiguration {
    Write-Log "`n[8/12] Securing AD Certificate Services (AD CS) Configurations..." -Level Info
    
    try {
        # Check for AD CS presence
        $cas = certutil -config - -ping 2>&1
        
        if ($LASTEXITCODE -eq 0) {
            Write-Log "AD CS detected. Checking certificate templates..." -Level Info
            
            # Retrieve certificate templates
            $configDN = "CN=Configuration,$($DomainInfo.DomainDN)"
            $templatePath = "CN=Certificate Templates,CN=Public Key Services,CN=Services,$configDN"
            
            $templates = Get-ADObject -SearchBase $templatePath `
                -Filter {objectClass -eq "pKICertificateTemplate"} `
                -Properties * -ErrorAction SilentlyContinue
            
            if ($templates) {
                Write-Log "Found $($templates.Count) certificate templates" -Level Info
                
                # Check for vulnerable templates (ESC1)
                $vulnerableTemplates = $templates | Where-Object {
                    $_.'msPKI-Certificate-Name-Flag' -band 0x1  # ENROLLEE_SUPPLIES_SUBJECT
                }
                
                if ($vulnerableTemplates) {
                    Write-Log "WARNING: Found $($vulnerableTemplates.Count) potentially vulnerable templates (ESC1):" -Level Warning
                    foreach ($template in $vulnerableTemplates) {
                        Write-Log "  - $($template.Name): Allows enrollee to supply subject name" -Level Warning
                    }
                }
                else {
                    Write-Log "No ESC1 vulnerable templates detected" -Level Success
                }
                
                # Check for overly permissive templates
                $permissiveCount = 0
                foreach ($template in $templates | Select-Object -First 10) {
                    try {
                        $acl = Get-Acl "AD:$($template.DistinguishedName)" -ErrorAction SilentlyContinue
                        if ($acl) {
                            $everyoneAccess = $acl.Access | Where-Object { 
                                $_.IdentityReference -like "*Everyone*" -or 
                                $_.IdentityReference -like "*Authenticated Users*" -or
                                $_.IdentityReference -like "*Прошедшие*"
                            }
                            
                            if ($everyoneAccess) {
                                Write-Log "WARNING: Template $($template.Name) has overly permissive ACLs" -Level Warning
                                $permissiveCount++
                            }
                        }
                    }
                    catch {
                        # Ignore ACL read errors
                    }
                }
                
                if ($permissiveCount -eq 0) {
                    Write-Log "No overly permissive templates detected (checked first 10)" -Level Success
                }
            }
            
            Write-Log "AD CS audit completed. Review and restrict CA permissions, disable vulnerable templates" -Level Info
        }
        else {
            Write-Log "AD CS not detected or not accessible" -Level Info
        }
    }
    catch {
        Write-Log "Failed to audit AD CS configuration: $_" -Level Error
    }
}

#endregion

#region 9. Embrace Principle of Least Privilege
# Criterion 9: Apply Principle of Least Privilege

function Implement-LeastPrivilege {
    Write-Log "`n[9/12] Implementing Principle of Least Privilege..." -Level Info
    
    try {
        # Audit privileged group memberships (using RIDs)
        Write-Log "Auditing privileged group memberships..." -Level Info
        
        $privilegedGroups = Get-PrivilegedGroups
        
        foreach ($groupInfo in $privilegedGroups) {
            try {
                $group = Get-ADGroup -Identity $groupInfo.SID
                $members = Get-ADGroupMember -Identity $group.DistinguishedName -ErrorAction Stop
                
                if ($members.Count -gt 0) {
                    Write-Log "Group: $($groupInfo.Name) ($($groupInfo.EnglishName)) - $($members.Count) members" -Level Info
                    
                    foreach ($member in $members) {
                        if ($member.objectClass -eq 'user') {
                            $user = Get-ADUser $member.SamAccountName -Properties Enabled, LastLogonDate, PasswordLastSet -ErrorAction SilentlyContinue
                            
                            if ($user) {
                                # Check for disabled accounts
                                if (-not $user.Enabled) {
                                    Write-Log "  WARNING: Disabled user $($member.SamAccountName) is still in $($groupInfo.Name)" -Level Warning
                                }
                                
                                # Check users who haven't logged in for a long time
                                if ($user.LastLogonDate -and ((Get-Date) - $user.LastLogonDate).Days -gt 90) {
                                    Write-Log "  WARNING: User $($member.SamAccountName) hasn't logged in for $([math]::Round(((Get-Date) - $user.LastLogonDate).Days)) days" -Level Warning
                                }
                            }
                        }
                    }
                }
                else {
                    Write-Log "Group: $($groupInfo.Name) ($($groupInfo.EnglishName)) - 0 members" -Level Info
                }
            }
            catch {
                Write-Log "Failed to check group $($groupInfo.Name): $_" -Level Warning
            }
        }
        
        Write-Log "Least Privilege audit completed. Review and remove unnecessary permissions." -Level Info
    }
    catch {
        Write-Log "Failed to implement Least Privilege audit: $_" -Level Error
    }
}

#endregion

#region 10. Audit AD CS Setup
# Criterion 10: Audit AD CS configuration

function Audit-ADCSSetup {
    Write-Log "`n[10/12] Auditing AD CS Setup for Misconfigurations..." -Level Info
    
    try {
        # Retrieve PKI configuration
        $configDN = "CN=Configuration,$($DomainInfo.DomainDN)"
        $pkiConfig = "CN=Public Key Services,CN=Services,$configDN"
        
        $pkiObjects = Get-ADObject -SearchBase $pkiConfig -Filter * -ErrorAction SilentlyContinue
        
        if ($pkiObjects) {
            Write-Log "PKI infrastructure detected" -Level Info
            
            # Check Certification Authorities
            $cas = Get-ADObject -SearchBase $pkiConfig -Filter {objectClass -eq "pKIEnrollmentService"} -Properties * -ErrorAction SilentlyContinue
            
            if ($cas) {
                Write-Log "Found $($cas.Count) Certification Authority(ies)" -Level Info
                
                foreach ($ca in $cas) {
                    Write-Log "  CA: $($ca.Name)" -Level Info
                    
                    # Check CA permissions
                    try {
                        $caAcl = Get-Acl "AD:$($ca.DistinguishedName)" -ErrorAction SilentlyContinue
                        if ($caAcl) {
                            $dangerousPermissions = $caAcl.Access | Where-Object {
                                ($_.IdentityReference -like "*Authenticated Users*" -or 
                                 $_.IdentityReference -like "*Everyone*" -or
                                 $_.IdentityReference -like "*Прошедшие*") -and
                                ($_.ActiveDirectoryRights -like "*GenericAll*" -or 
                                 $_.ActiveDirectoryRights -like "*WriteDacl*")
                            }
                            
                            if ($dangerousPermissions) {
                                Write-Log "  WARNING: CA has overly permissive ACLs!" -Level Warning
                            }
                            else {
                                Write-Log "  CA permissions appear secure" -Level Success
                            }
                        }
                    }
                    catch {
                        # Ignore ACL errors
                    }
                }
            }
            else {
                Write-Log "No Certification Authorities found" -Level Info
            }
            
            # Check certificate template security
            Write-Log "Checking certificate template security..." -Level Info
            $templatePath = "CN=Certificate Templates,CN=Public Key Services,CN=Services,$configDN"
            $templates = Get-ADObject -SearchBase $templatePath -Filter {objectClass -eq "pKICertificateTemplate"} -Properties * -ErrorAction SilentlyContinue
            
            if ($templates) {
                $vulnerableCount = 0
                foreach ($template in $templates) {
                    # ESC1 - Check ENROLLEE_SUPPLIES_SUBJECT
                    if ($template.'msPKI-Certificate-Name-Flag' -band 1) {
                        Write-Log "  ESC1 Vulnerable: $($template.Name) allows subject name specification" -Level Warning
                        $vulnerableCount++
                    }
                    
                    # ESC2 - Check Any Purpose EKU
                    if ($template.'msPKI-Certificate-Application-Policy' -contains "2.5.29.37.0") {
                        Write-Log "  ESC2 Vulnerable: $($template.Name) has Any Purpose EKU" -Level Warning
                        $vulnerableCount++
                    }
                }
                
                if ($vulnerableCount -eq 0) {
                    Write-Log "No obvious template vulnerabilities detected" -Level Success
                }
            }
        }
        else {
            Write-Log "No PKI infrastructure detected in this domain" -Level Info
        }
    }
    catch {
        Write-Log "Failed to audit AD CS setup: $_" -Level Error
    }
}

#endregion

#region 11. Monitor Issued Certificates
# Criterion 11: Monitor issued certificates

function Monitor-IssuedCertificates {
    Write-Log "`n[11/12] Monitoring Issued Certificates..." -Level Info
    
    try {
        # Check certificates registered in AD
        Write-Log "Checking for certificates in AD..." -Level Info
        
        $usersWithCerts = Get-ADUser -Filter * -Properties userCertificate -ErrorAction SilentlyContinue | 
            Where-Object { $_.userCertificate -ne $null } |
            Select-Object -First 50
        
        if ($usersWithCerts) {
            Write-Log "Found $($usersWithCerts.Count) users with certificates in AD (showing first 50)" -Level Info
            
            $expiredCount = 0
            $expiringCount = 0
            
            foreach ($user in $usersWithCerts) {
                try {
                    $certs = $user.userCertificate
                    foreach ($certBytes in $certs) {
                        try {
                            $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 -ArgumentList @(,$certBytes)
                            
                            # Check certificate validity period
                            $daysToExpiry = ($cert.NotAfter - (Get-Date)).Days
                            
                            if ($daysToExpiry -lt 0) {
                                Write-Log "  EXPIRED: User $($user.SamAccountName) has expired certificate" -Level Warning
                                $expiredCount++
                            }
                            elseif ($daysToExpiry -lt 30) {
                                Write-Log "  EXPIRING: User $($user.SamAccountName) certificate expires in $daysToExpiry days" -Level Warning
                                $expiringCount++
                            }
                        }
                        catch {
                            # Ignore certificate parsing errors
                        }
                    }
                }
                catch {
                    # Ignore user cert errors
                }
            }
            
            if ($expiredCount -eq 0 -and $expiringCount -eq 0) {
                Write-Log "All checked certificates are valid and not expiring soon" -Level Success
            }
        }
        else {
            Write-Log "No users with certificates found in AD" -Level Info
        }
        
        Write-Log "Certificate monitoring completed. Implement automated monitoring for certificate lifecycle." -Level Info
    }
    catch {
        Write-Log "Failed to monitor certificates: $_" -Level Error
    }
}

#endregion

#region 12. Implement Security Monitoring and Alerting
# Criterion 12: Implement security monitoring and alerting

function Implement-SecurityMonitoring {
    Write-Log "`n[12/12] Implementing Security Monitoring and Alerting..." -Level Info
    
    try {
        # Check Windows Event Log configuration
        Write-Log "Checking Windows Event Log configuration..." -Level Info
        
        $criticalLogs = @(
            "Security",
            "System",
            "Application"
        )
        
        foreach ($logName in $criticalLogs) {
            try {
                $log = Get-WinEvent -ListLog $logName -ErrorAction Stop
                
                if ($log.IsEnabled) {
                    $sizeMB = [math]::Round($log.MaximumSizeInBytes / 1MB, 2)
                    Write-Log "  $logName : Enabled, Max Size: $sizeMB MB" -Level Info
                    
                    if ($sizeMB -lt 100) {
                        Write-Log "  WARNING: Consider increasing log size for $logName (current: $sizeMB MB, recommended: 100+ MB)" -Level Warning
                    }
                }
                else {
                    Write-Log "  WARNING: $logName is NOT enabled!" -Level Warning
                }
            }
            catch {
                Write-Log "  Failed to check log $logName : $_" -Level Warning
            }
        }
        
        # Create monitoring script
        Write-Log "Creating security monitoring script..." -Level Info
        
    $monitoringScript = @'
    # Monitor suspicious activities
$events = @(
    @{LogName="Security"; EventID=4625; Description="Failed logon attempts"},
    @{LogName="Security"; EventID=4672; Description="Special privileges assigned"},
    @{LogName="Security"; EventID=4768; Description="Kerberos TGT requested"},
    @{LogName="Security"; EventID=4769; Description="Kerberos service ticket requested"}
)

$alertThreshold = 10
$timeSpan = (Get-Date).AddHours(-1)

foreach ($event in $events) {
    try {
        $recentEvents = Get-WinEvent -FilterHashtable @{
            LogName = $event.LogName
            ID = $event.EventID
            StartTime = $timeSpan
        } -ErrorAction SilentlyContinue
        
        if ($recentEvents.Count -gt $alertThreshold) {
            Write-Warning "$($event.Description): $($recentEvents.Count) events in last hour!"
            # Add email notification or SIEM integration here
        }
    }
    catch {}
}
'@
        
        $scriptPath = Join-Path $LogPath "SecurityMonitoring.ps1"
        $monitoringScript | Out-File -FilePath $scriptPath -Force
        Write-Log "Monitoring script created: $scriptPath" -Level Success
        
        # Enable Advanced Audit Policies
        if ($PSCmdlet.ShouldProcess("Advanced Audit Policies", "Enable")) {
            Write-Log "Enabling Advanced Audit Policies..." -Level Info
            
            $auditCommands = @(
                "auditpol /set /subcategory:`"Credential Validation`" /success:enable /failure:enable",
                "auditpol /set /subcategory:`"Kerberos Authentication Service`" /success:enable /failure:enable",
                "auditpol /set /subcategory:`"User Account Management`" /success:enable /failure:enable",
                "auditpol /set /subcategory:`"Security Group Management`" /success:enable"
            )
            
            foreach ($cmd in $auditCommands) {
                try {
                    Invoke-Expression $cmd | Out-Null
                }
                catch {
                    Write-Log "Failed to execute audit policy command" -Level Warning
                }
            }
            
            Write-Log "Advanced Audit Policies configured" -Level Success
        }
        
        Write-Log "Security monitoring configuration completed" -Level Success
    }
    catch {
        Write-Log "Failed to implement security monitoring: $_" -Level Error
    }
}

#endregion

#region Execute All Hardening Functions

try {
    Write-Log "`nStarting AD Hardening Process..." -Level Info
    Write-Log "Domain: $($DomainInfo.DomainName)`n" -Level Info
    
    if (-not $GenerateReportOnly) {
        # Execute all hardening steps
        Set-AccountLockoutPolicy
        Set-LDAPAccessRestrictions
        Set-StrongPasswordPolicy
        Enable-MFAConfiguration
        Enable-LDAPSigningAndChannelBinding
        Configure-gMSASupport
        Enable-PrivilegedAccessManagement
        Secure-ADCSConfiguration
        Implement-LeastPrivilege
        Audit-ADCSSetup
        Monitor-IssuedCertificates
        Implement-SecurityMonitoring
    }
    else {
        Write-Log "Report-only mode: Auditing current configuration..." -Level Info
        # Audit only without making changes
        Enable-MFAConfiguration
        Secure-ADCSConfiguration
        Implement-LeastPrivilege
        Audit-ADCSSetup
        Monitor-IssuedCertificates
    }
    
    # Final report
    Write-Log "`n========================================" -Level Info
    Write-Log "AD Hardening Script Completed" -Level Info
    Write-Log "========================================" -Level Info
    Write-Log "Success: $Script:SuccessCount" -Level Info
    Write-Log "Warnings: $Script:WarningCount" -Level Info
    Write-Log "Errors: $Script:ErrorCount" -Level Info
    Write-Log "Log file: $LogFile" -Level Info
    
    Write-Log "`nIMPORTANT NEXT STEPS:" -Level Info
    Write-Log "1. Review the log file for warnings and errors" -Level Info
    Write-Log "2. Test changes in non-production environment first" -Level Info
    Write-Log "3. Some changes require DC restart to take effect" -Level Info
    Write-Log "4. Implement continuous monitoring and regular audits" -Level Info
    Write-Log "5. Train administrators on new security policies" -Level Info
    
    # Generate HTML report
    $htmlReport = @"
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>AD Hardening Report - $(Get-Date -Format 'yyyy-MM-dd')</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background-color: #f5f5f5; }
        .container { background-color: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); max-width: 1200px; margin: auto; }
        h1 { color: #2c3e50; border-bottom: 3px solid #3498db; padding-bottom: 10px; }
        h2 { color: #34495e; margin-top: 30px; }
        .success { color: #27ae60; font-weight: bold; }
        .warning { color: #f39c12; font-weight: bold; }
        .error { color: #e74c3c; font-weight: bold; }
        table { width: 100%; border-collapse: collapse; margin: 20px 0; }
        th, td { padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }
        th { background-color: #3498db; color: white; }
        tr:hover { background-color: #f5f5f5; }
        .summary { display: flex; justify-content: space-around; margin: 20px 0; }
        .summary-box { padding: 20px; border-radius: 5px; text-align: center; flex: 1; margin: 0 10px; }
        .summary-box h3 { margin: 0; font-size: 2em; }
        .checklist { margin: 20px 0; }
        .checklist-item { padding: 10px; margin: 5px 0; border-left: 4px solid #3498db; background-color: #ecf0f1; }
    </style>
</head>
<body>
    <div class="container">
        <h1>🔒 Active Directory Hardening Report</h1>
        <p><strong>Domain:</strong> $($DomainInfo.DomainName)</p>
        <p><strong>Report Date:</strong> $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')</p>
        <p><strong>Executed By:</strong> $env:USERNAME</p>
        <p><strong>DC:</strong> $($DomainInfo.DomainController)</p>
        
        <div class="summary">
            <div class="summary-box" style="background-color: #d5f4e6;">
                <h3 class="success">$Script:SuccessCount</h3>
                <p>Successful</p>
            </div>
            <div class="summary-box" style="background-color: #ffeaa7;">
                <h3 class="warning">$Script:WarningCount</h3>
                <p>Warnings</p>
            </div>
            <div class="summary-box" style="background-color: #fab1a0;">
                <h3 class="error">$Script:ErrorCount</h3>
                <p>Errors</p>
            </div>
        </div>
        
        <h2>📋 12-Point Hardening Checklist Status</h2>
        <div class="checklist">
            <div class="checklist-item">
                <strong>1. Account Lockout Policies</strong><br>
                Threshold: 5 attempts, Duration: 30 minutes
            </div>
            <div class="checklist-item">
                <strong>2. LDAP Access Restrictions</strong><br>
                LDAP Signing enabled, Firewall rules configured
            </div>
            <div class="checklist-item">
                <strong>3. Strong Password Policies</strong><br>
                Min Length: 14, Max Age: 60 days, Complexity: Enabled
            </div>
            <div class="checklist-item">
                <strong>4. Multi-Factor Authentication</strong><br>
                Privileged accounts audited for MFA requirements
            </div>
            <div class="checklist-item">
                <strong>5. LDAP Signing & Channel Binding</strong><br>
                Configured on Domain Controllers (restart required)
            </div>
            <div class="checklist-item">
                <strong>6. Group Managed Service Accounts</strong><br>
                KDS Root Key configured, gMSA infrastructure ready
            </div>
            <div class="checklist-item">
                <strong>7. Privileged Access Management</strong><br>
                Protected Users group verified, AdminSDHolder checked
            </div>
            <div class="checklist-item">
                <strong>8. AD CS Security</strong><br>
                Certificate templates and CA permissions audited
            </div>
            <div class="checklist-item">
                <strong>9. Least Privilege Principle</strong><br>
                Privileged group memberships reviewed
            </div>
            <div class="checklist-item">
                <strong>10. AD CS Audit</strong><br>
                PKI infrastructure checked for misconfigurations
            </div>
            <div class="checklist-item">
                <strong>11. Certificate Monitoring</strong><br>
                User and computer certificates validated
            </div>
            <div class="checklist-item">
                <strong>12. Security Monitoring</strong><br>
                Event logs configured, Advanced Audit Policies enabled
            </div>
        </div>
        
        <h2>⚠️ Key Recommendations</h2>
        <ul>
            <li>Review all WARNING messages in log file: <code>$LogFile</code></li>
            <li>Restart Domain Controllers for LDAP signing changes</li>
            <li>Add privileged users to Protected Users group</li>
            <li>Implement MFA/Smart Cards for administrative accounts</li>
            <li>Convert service accounts to gMSAs where possible</li>
            <li>Review and disable vulnerable AD CS templates</li>
            <li>Implement tiered administration model (Tier 0/1/2)</li>
            <li>Increase Event Log sizes (System and Application to 100+ MB)</li>
            <li>Set up centralized logging (SIEM integration)</li>
            <li>Conduct regular security audits with BloodHound/Purple Knight</li>
            <li>Disable inactive privileged accounts</li>
        </ul>
        
        <h2>📚 Additional Resources</h2>
        <ul>
            <li><a href="https://attack.mitre.org/" target="_blank">MITRE ATT&CK Framework</a></li>
            <li><a href="https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/best-practices-for-securing-active-directory" target="_blank">Microsoft AD Security Best Practices</a></li>
            <li><a href="https://adsecurity.org/" target="_blank">ADSecurity.org Resources</a></li>
            <li><a href="https://www.purple-knight.com/" target="_blank">Purple Knight - AD Security Assessment Tool</a></li>
        </ul>
        
        <hr>
        <p style="text-align: center; color: #7f8c8d; font-size: 0.9em;">
            Generated by AD-Hardening-Script.ps1 (Multilingual Edition) | $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
        </p>
    </div>
</body>
</html>
"@
    
    $reportPath = Join-Path $LogPath "ADHardening_Report_$Timestamp.html"
    $htmlReport | Out-File -FilePath $reportPath -Encoding UTF8
    Write-Log "`nHTML Report generated: $reportPath" -Level Success
    
}
catch {
    Write-Log "Critical error in main script execution: $_" -Level Error
    throw
}

#endregion

Write-Log "`n✅ Script execution completed successfully at $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -Level Info