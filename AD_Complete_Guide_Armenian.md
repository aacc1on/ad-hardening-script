# Active Directory և AD Hardening Script - Ամբողջական Ուղեցույց

## 📚 Բովանդակություն

1. [Active Directory - Ընդհանուր Նկարագրություն](#active-directory-ընդհանուր-նկարագրություն)
2. [AD Պրոտոկոլներ և Մեխանիզմներ](#ad-պրոտոկոլներ-և-մեխանիզմներ)
3. [Hardening Script - 12 Կետերի Մանրամասն Բացատրություն](#hardening-script-12-կետերի-մանրամասն-բացատրություն)
4. [Հարձակումների Տեսակներ և Պաշտպանություն](#հարձակումների-տեսակներ-և-պաշտպանություն)

---

## Active Directory - Ընդհանուր Նկարագրություն

### Ի՞նչ է Active Directory-ն

**Active Directory (AD)** - Microsoft-ի կողմից մշակված directory service, որը թույլ է տալիս կառավարել և կազմակերպել ցանցային ռեսուրսները։

### Հիմնական Բաղադրիչներ

```
┌─────────────────────────────────────────┐
│         Active Directory Forest         │
│                                         │
│  ┌───────────────────────────────────┐  │
│  │         Domain Tree               │  │
│  │                                   │  │
│  │  ┌──────────────────────────┐    │  │
│  │  │   Domain (contoso.com)   │    │  │
│  │  │                          │    │  │
│  │  │  • Domain Controllers    │    │  │
│  │  │  • Users                 │    │  │
│  │  │  • Computers             │    │  │
│  │  │  • Groups                │    │  │
│  │  │  • Organizational Units  │    │  │
│  │  │  • Group Policies        │    │  │
│  │  └──────────────────────────┘    │  │
│  └───────────────────────────────────┘  │
└─────────────────────────────────────────┘
```

### AD Կառուցվածքային Տարրեր

1. **Forest (Անտառ)**
   - Ամենաբարձր մակարդակի container
   - Ունի մեկ schema և configuration
   - Կարող է պարունակել մի քանի domain-ներ

2. **Domain (Դոմեն)**
   - Կազմակերպական միավոր
   - Ունի իր security boundary-ն
   - Օրինակ՝ contoso.com, techcorp.local

3. **Domain Controller (DC)**
   - Server, որը պահում է AD database-ը
   - Իրականացնում է authentication և authorization
   - Replicate է անում տվյալները մյուս DC-ների հետ

4. **Organizational Unit (OU)**
   - Լոգիկական container օբյեկտների համար
   - Թույլ է տալիս կիրառել Group Policy
   - Կազմակերպական ստրուկտուրա

5. **Objects (Օբյեկտներ)**
   - **Users** - Օգտատերեր
   - **Computers** - Համակարգիչներ
   - **Groups** - Խմբեր
   - **Service Accounts** - Ծառայությունների հաշիվներ

### AD Database

```
C:\Windows\NTDS\
├── ntds.dit          # AD Database (բոլոր օբյեկտները)
├── edb.log           # Transaction log
├── edb.chk           # Checkpoint file
└── temp.edb          # Temporary database
```

**ntds.dit** պարունակում է՝
- Օգտատերերի credentials (password hashes)
- Խմբերի անդամություն
- Security descriptors (ACLs)
- Schema տեղեկություն
- Configuration տվյալներ

---

## AD Պրոտոկոլներ և Մեխանիզմներ

### 1. LDAP (Lightweight Directory Access Protocol)

**Նպատակ:** AD database-ի հետ աշխատելու համար պրոտոկոլ

**Ինչպես է աշխատում:**

```
┌──────────┐                    ┌──────────────┐
│  Client  │─────LDAP Query────▶│    Domain    │
│          │                    │  Controller  │
│          │◀────LDAP Result────│              │
└──────────┘                    └──────────────┘

Port 389  - LDAP (չզանցագրված)
Port 636  - LDAPS (SSL/TLS-ով)
Port 3268 - Global Catalog
Port 3269 - Global Catalog SSL
```

**LDAP Query Օրինակ:**

```ldap
# Գտնել բոլոր IT բաժնի օգտատերերին
(&(objectClass=user)(department=IT))

# Distinguished Name (DN)
CN=John Smith,OU=Users,OU=IT,DC=contoso,DC=com

# Attributes
cn: John Smith
sAMAccountName: jsmith
mail: john.smith@contoso.com
memberOf: CN=Domain Admins,CN=Users,DC=contoso,DC=com
```

**LDAP Signing:**
- Ապահովում է LDAP request-ների ամբողջականությունը
- Կանխում է man-in-the-middle հարձակումները
- Պահանջում է digital signature

**LDAP Channel Binding:**
- Կապում է TLS channel-ը LDAP session-ին
- Կանխում է relay attacks
- Windows Server 2019+ լիակատար աջակցություն

### 2. Kerberos Authentication

**Նպատակ:** Network authentication պրոտոկոլ (Port 88)

**Աշխատանքի Սխեմա:**

```
1. AS-REQ (Authentication Service Request)
   User ────▶ KDC: "Ես եմ John, ուզում եմ TGT"

2. AS-REP (Authentication Service Response)
   KDC ────▶ User: "Ահա TGT (Ticket Granting Ticket)"
   
3. TGS-REQ (Ticket Granting Service Request)
   User ────▶ KDC: "Ինձ SPN=HTTP/webserver պետք է"
   
4. TGS-REP (Ticket Granting Service Response)
   KDC ────▶ User: "Ահա Service Ticket"
   
5. AP-REQ (Application Request)
   User ────▶ Server: "Ահա իմ ticket-ը"
   
6. AP-REP (Application Response)
   Server ────▶ User: "OK, authenticated"
```

**Kerberos Tickets:**

```
┌─────────────────────────────────────┐
│   TGT (Ticket Granting Ticket)      │
├─────────────────────────────────────┤
│ • Encrypted with krbtgt hash        │
│ • Valid for 10 hours (default)      │
│ • Used to request service tickets   │
│ • Stored in memory (lsass.exe)      │
└─────────────────────────────────────┘

┌─────────────────────────────────────┐
│   Service Ticket                    │
├─────────────────────────────────────┤
│ • Encrypted with service hash       │
│ • Valid for specific service (SPN)  │
│ • Contains user authorization data  │
└─────────────────────────────────────┘
```

**Service Principal Name (SPN):**

```powershell
# Format
ServiceClass/HostName:Port/ServiceName

# Օրինակներ
HTTP/webserver.contoso.com
MSSQLSvc/sqlserver.contoso.com:1433
HOST/fileserver.contoso.com
```

### 3. NTLM (NT LAN Manager)

**Նպատակ:** Challenge-response authentication

**Աշխատանքի Սխեմա:**

```
1. Negotiate
   Client ────▶ Server: "Ես ուզում եմ authenticate լինել"

2. Challenge
   Server ────▶ Client: "Ահա 8-byte random challenge"

3. Response
   Client ────▶ Server: "Ահա hash(password + challenge)"

4. Verification
   Server ────▶ DC: "Ստուգիր այս response-ը"
   DC ────▶ Server: "OK" կամ "Failed"
```

**NTLM-ի Խնդիրներ:**
- Հնացած (legacy protocol)
- Vulnerability to relay attacks
- Pass-the-hash attacks
- Չունի mutual authentication

**NTLMv1 vs NTLMv2:**

```
NTLMv1:
- Թույլ encryption (DES)
- Հեշտությամբ crack-վում է
- ԿԱՏ չի օգտագործվում

NTLMv2:
- Ավելի ուժեղ encryption (HMAC-MD5)
- Timestamp ավելացված
- Ավելի դժվար է crack անել
```

### 4. SMB (Server Message Block)

**Նպատակ:** File sharing պրոտոկոլ

```
Ports:
- 445 (SMB over TCP)
- 139 (SMB over NetBIOS)

Versions:
- SMBv1: Հին, անապահով, պետք է անջատել
- SMBv2: Windows Vista+
- SMBv3: Windows 8/Server 2012+, encryption
```

**SMB Signing:**
- Ապահովում է packet-ների ամբողջականությունը
- Կանխում է man-in-the-middle attacks
- Կարող է performance-ի վրա ազդել

### 5. DNS (Domain Name System)

**AD DNS:**

```
┌─────────────────────────────────────┐
│   AD-Integrated DNS Zones           │
├─────────────────────────────────────┤
│ • Stored in AD database             │
│ • Replicated with AD replication    │
│ • Secure Dynamic Updates            │
│ • SRV records for DC location       │
└─────────────────────────────────────┘

Կարևոր SRV Records:
_ldap._tcp.dc._msdcs.contoso.com      # LDAP
_kerberos._tcp.dc._msdcs.contoso.com  # Kerberos
_gc._tcp.contoso.com                   # Global Catalog
```

### 6. Replication

**Նպատակ:** Տվյալների սինխրոնացում DC-ների միջև

```
┌──────────┐                ┌──────────┐
│   DC1    │◄──Replicate───▶│   DC2    │
└────┬─────┘                └─────┬────┘
     │                            │
     └──────────Replicate─────────┘
                   │
             ┌─────▼─────┐
             │    DC3    │
             └───────────┘

Replication Protocols:
• RPC (Remote Procedure Call) - Intra-site
• SMTP - Inter-site (read-only)
```

**Replication Conflicts:**
- Last Write Wins
- Version numbers
- USN (Update Sequence Number)

---

## Hardening Script - 12 Կետերի Մանրամասն Բացատրություն

### Կետ 1️⃣: Account Lockout Policies (Հաշվի Արգելափակման Քաղաքականություն)

**Ի՞նչ է անում:**

```powershell
net accounts /lockoutthreshold:5      # 5 սխալ փորձ
net accounts /lockoutduration:30      # 30 րոպե արգելափակում
net accounts /lockoutwindow:30        # 30 րոպե հետևման պատուհան
```

**Ինչու է կարևոր:**
- Կանխում է brute-force հարձակումները
- Եթե հարձակվողը փորձի 1000 գաղտնաբառ, հաշիվը կարգելափակվի 5-րդ սխալ փորձից հետո

**Աշխատանքի Սխեմա:**

```
Փորձ 1: john/password123    ❌ Սխալ
Փորձ 2: john/password456    ❌ Սխալ
Փորձ 3: john/qwerty         ❌ Սխալ
Փորձ 4: john/letmein        ❌ Սխալ
Փորձ 5: john/admin          ❌ Սխալ
────────────────────────────────────
🔒 ՀԱՇԻՎԸ ԱՐԳԵԼԱՓԱԿՎԱԾ Է 30 ՐՈՊԵՈՎ
```

**Պահվում է:**
```
Event ID 4740 - Account Lockout
Event ID 4625 - Failed Logon
Event ID 4776 - Credential Validation
```

**Խնդիրներ:**
- Կարող է DoS լինել (հարձակվողը մտադիր արգելափակի օգտատերերին)
- Պետք է balance անել security vs usability

---

### Կետ 2️⃣: LDAP Access Restrictions

**Ի՞նչ է անում:**

```powershell
# Registry-ում
HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters
LDAPServerIntegrity = 2    # Require Signing

# Firewall Rules
Port 389  - LDAP
Port 636  - LDAPS (SSL)
```

**LDAP Signing Levels:**

```
0 = None          - Ամենավտանգավորը
1 = Negotiate     - Եթե client-ը ուզում է
2 = Require       - Պարտադիր (Ապահով)
```

**Առանց Signing-ի Հարձակում:**

```
┌─────────┐                  ┌──────────┐
│  Client │─────LDAP────────▶│    DC    │
└─────────┘                  └──────────┘
     ▲                             │
     │      ┌──────────────┐       │
     └──────│  Attacker    │◀──────┘
            │ (Man-in-the- │
            │   Middle)    │
            └──────────────┘
            
Attacker-ը կարող է:
• Կարդալ credentials
• Փոխել queries
• Inject data
```

**Signing-ով:**

```
┌─────────┐    Signed LDAP      ┌──────────┐
│  Client │────────────────────▶│    DC    │
└─────────┘                     └──────────┘
     ▲
     │      ┌──────────────┐
     └──────│  Attacker    │
            │   ❌ Cannot  │
            │   Modify     │
            └──────────────┘
```

**Channel Binding:**

```
LDAP over TLS:
1. TLS handshake ─────▶ Secure channel
2. LDAP auth    ─────▶ Bound to TLS session
3. If attacker intercepts ─────▶ Signature mismatch ❌
```

---

### Կետ 3️⃣: Strong Password Policies

**Ի՞նչ է անում:**

```powershell
MinPasswordLength = 14        # Նվազագույն երկարություն
MaxPasswordAge = 60          # Առավելագույն տարիք (օր)
MinPasswordAge = 1           # Նվազագույն տարիք
PasswordHistoryCount = 24    # Պատմություն
PasswordComplexity = 1       # Բարդություն միացված
```

**Password Complexity Պահանջները:**

```
Պետք է պարունակի 3+ հետևյալներից:
✓ Մեծատառեր (A-Z)
✓ Փոքրատառեր (a-z)
✓ Թվեր (0-9)
✓ Հատուկ նիշեր (!@#$%^&*)

Չպետք է պարունակի:
❌ Username-ը
❌ Display Name-ը

Օրինակներ:
✅ MyP@ssw0rd2025!    (14+ chars, complex)
✅ C0mpl3x!tyR0cks    (14+ chars, complex)
❌ password           (too short, simple)
❌ Password123        (< 14 chars)
```

**Password Storage:**

```
AD-ում Password-ները պահվում են որպես hashes:

┌────────────────────────────────────┐
│   Password: MyP@ssw0rd123          │
├────────────────────────────────────┤
│   LM Hash: Disabled (թույլ)        │
│   NT Hash: 8846f7eaee8fb117ad...   │
│   Kerberos Keys: AES256, AES128... │
└────────────────────────────────────┘

Hash-երը պահվում են:
• ntds.dit database
• Memory (lsass.exe)
• Cached credentials (registry)
```

**Password Cracking:**

```
Weak Password (8 chars):
Password: password1
Cracking time: < 1 second (GPU)

Strong Password (14+ chars):
Password: MyC0mpl3x!P@ss
Cracking time: ~10 years (GPU)
```

---

### Կետ 4️⃣: Multi-Factor Authentication (MFA)

**Ի՞նչ է անում:**

```powershell
# Ստուգում է smart card requirement
Get-ADUser -Properties SmartcardLogonRequired
Set-ADUser -Identity admin -SmartcardLogonRequired $true
```

**Authentication Factors:**

```
Something you KNOW      Something you HAVE      Something you ARE
─────────────────      ──────────────────      ─────────────────
Password               Smart Card              Fingerprint
PIN                    Security Token          Face Recognition
Security Question      Mobile Phone            Iris Scan
```

**Smart Card Authentication:**

```
1. User inserts smart card
   │
2. System requests PIN
   │
3. Smart card unlocks private key
   │
4. Client sends certificate to DC
   │
5. DC validates certificate (PKI)
   │
6. DC issues Kerberos TGT
   │
7. User authenticated ✓
```

**Azure MFA Flow:**

```
1. User enters username/password
   │
2. Azure AD prompts for MFA
   │
3. Options:
   ├─ Mobile app notification
   ├─ Mobile app verification code
   ├─ Phone call
   └─ Text message (SMS)
   │
4. User confirms
   │
5. Authentication successful ✓
```

**Privileged Account Protection:**

```
Domain Admins ───────▶ ՊԵՏՔ Է MFA
Enterprise Admins ───▶ ՊԵՏՔ Է MFA
Schema Admins ───────▶ ՊԵՏՔ Է MFA
Administrators ──────▶ ՊԵՏՔ Է MFA

Regular Users ───────▶ Խորհուրդ է տրվում
```

---

### Կետ 5️⃣: LDAP Signing & Channel Binding

**Ի՞նչ է անում:**

```powershell
# Բոլոր DC-ների վրա
LDAPServerIntegrity = 2          # Require Signing
LdapEnforceChannelBinding = 2    # Always require
```

**LDAP Relay Attack (առանց signing-ի):**

```
1. Attacker sets up rogue LDAP server
   │
2. Victim connects: ldap://attacker-server
   │
3. Attacker relays to real DC
   │
4. Attacker can:
   ├─ Add users
   ├─ Modify groups
   ├─ Change passwords
   └─ Escalate privileges
```

**Channel Binding Protection:**

```
┌──────────────────────────────────────┐
│   Client                             │
│   ├─ Establishes TLS connection      │
│   ├─ Gets channel binding token (CBT)│
│   ├─ Includes CBT in LDAP auth       │
│   └─ Signs with session key          │
└──────────────────────────────────────┘
         │
         ▼
┌──────────────────────────────────────┐
│   Attacker (relay attempt)           │
│   ├─ Receives TLS connection         │
│   ├─ But CBT is for different session│
│   ├─ DC rejects (CBT mismatch)       │
│   └─ Attack fails ❌                 │
└──────────────────────────────────────┘
```

**Registry Settings մանրամասն:**

```
LDAPServerIntegrity Values:
├─ 0: None (Ամենավտանգավորը)
├─ 1: Negotiate signing (Եթե client-ը ուզում է)
└─ 2: Require signing (Պարտադիր - Ապահով)

LdapEnforceChannelBinding:
├─ 0: Never (Անջատված)
├─ 1: When supported (Եթե հնարավոր է)
└─ 2: Always (Միշտ - Ապահով)
```

---

### Կետ 6️⃣: Group Managed Service Accounts (gMSA)

**Ի՞նչ է անում:**

```powershell
# Ստեղծում է KDS Root Key
Add-KdsRootKey -EffectiveImmediately

# Ստեղծում է gMSA
New-ADServiceAccount -Name "gMSA-SQL" `
    -DNSHostName "sqlserver.contoso.com" `
    -PrincipalsAllowedToRetrieveManagedPassword "SQL-Servers"
```

**Ավանդական Service Account vs gMSA:**

```
┌─────────────────────────────────────────────┐
│   Traditional Service Account              │
├─────────────────────────────────────────────┤
│ • Manual password management               │
│ • Password never expires (սովորաբար)      │
│ • Same password on multiple servers       │
│ • SPN conflicts possible                  │
│ • Security risk if compromised            │
└─────────────────────────────────────────────┘
            ❌ Խնդիրներ

┌─────────────────────────────────────────────┐
│   Group Managed Service Account (gMSA)     │
├─────────────────────────────────────────────┤
│ • Automatic password management            │
│ • Password changes every 30 days          │
│ • 240-character complex password           │
│ • Managed by DC                           │
│ • No manual intervention needed           │
│ • Cannot be used for interactive logon    │
└─────────────────────────────────────────────┘
            ✅ Ապահով
```

**gMSA Password Management:**

```
┌────────────────────────────────────────┐
│          KDS Root Key                  │
│   (Key Distribution Service)           │
└────────────┬───────────────────────────┘
             │
    ┌────────▼───────────┐
    │  Derives Password  │
    │  Every 30 Days     │
    └────────┬───────────┘
             │
    ┌────────▼──────────────────────────┐
    │  Password = PBKDF2(               │
    │    KDS Root Key +                 │
    │    gMSA SID +                     │
    │    Password Interval              │
    │  )                                │
    └───────────────────────────────────┘
```

**gMSA Օգտագործման Օրինակ:**

```powershell
# 1. Ստեղծել gMSA
New-ADServiceAccount -Name gMSA-IIS `
    -DNSHostName web01.contoso.com `
    -PrincipalsAllowedToRetrieveManagedPassword "WebServers"

# 2. Install-ել server-ի վրա
Install-ADServiceAccount -Identity gMSA-IIS

# 3. Կարգավորել service
Set-Service -Name "W3SVC" `
    -StartupType Automatic `
    -Credential "CONTOSO\gMSA-IIS$"  # Ուշադրություն $-ին

# 4. Password-ը ավտոմատ փոխվում է
# Ոչինչ անելու կարիք չկա! 🎉
```

**Kerberoasting Protection:**

```
Regular Service Account:
├─ Has SPN
├─ Password set by admin (often weak)
├─ Can be Kerberoasted
└─ Password can be cracked offline ❌

gMSA:
├─ Has SPN
├─ 240-character random password
├─ Changes every 30 days
└─ Practically impossible to crack ✅
```

---

### Կետ 7️⃣: Privileged Access Management (PAM)

**Ի՞նչ է անում:**

```powershell
# Ստուգում է Protected Users խումբը
$protectedUsers = Get-ADGroupByRID -RID 525

# Ստուգում է admin users-ին
Get-ADGroupMember "Domain Admins" | ForEach-Object {
    # Պետք է լինեն Protected Users խմբում
}
```

**Protected Users Group:**

```
RID: 525 (Windows Server 2012 R2+)

Պաշտպանություններ:
├─ Cannot use NTLM authentication
├─ Cannot use DES or RC4 in Kerberos
├─ Credentials not cached
├─ Cannot be delegated
├─ TGT lifetime limited to 4 hours
└─ Must use Kerberos AES256

Հետևանքներ:
✅ Protection from Pass-the-Hash
✅ Protection from credential theft
✅ Stronger encryption
❌ Incompatible with older systems
❌ Cannot use if NTLM needed
```

**Tiered Administration Model:**

```
┌──────────────────────────────────────┐
│   Tier 0 (Domain Level)              │
│   ├─ Domain Controllers              │
│   ├─ Domain Admins                   │
│   ├─ Enterprise Admins               │
│   └─ Schema Admins                   │
│   🔒 Highest Security                │
└──────────────────────────────────────┘
            │
┌──────────────────────────────────────┐
│   Tier 1 (Server Level)              │
│   ├─ Application Servers             │
│   ├─ Database Servers                │
│   ├─ Server Admins                   │
│   └─ Limited delegation              │
│   🔒 Medium Security                 │
└──────────────────────────────────────┘
            │
┌──────────────────────────────────────┐
│   Tier 2 (Workstation Level)         │
│   ├─ User Workstations               │
│   ├─ Help Desk                       │
│   ├─ End Users                       │
│   └─ No server access                │
│   🔒 Standard Security               │
└──────────────────────────────────────┘

Կանոն: Tier N admin-ները ՉԵՆ կարող login լինել Tier N-1-ում
```

**AdminSDHolder:**

```
Purpose:
- Պաշտպանում է privileged groups-ի ACL-ները
- Ամեն 60 րոպեն մեկ ստուգում է
- Վերականգնում է ACL-ները եթե փոխվել են

Process:
1. SDProp process runs hourly
   │
2. Checks all protected objects
   │
3. Compares ACLs with AdminSDHolder template
   │
4. Resets any modifications
   │
5. Sets adminCount = 1

Protected Groups (RIDs):
├─ 512: Domain Admins
├─ 518: Schema Admins
├─ 519: Enterprise Admins
├─ 544: Administrators
└─ ... և այլն
```

**Just-In-Time (JIT) Access:**

```
Traditional:
User ────▶ Permanent admin rights ────▶ Always privileged ❌

JIT:
User ────▶ Request temporary rights ────▶ Auto-expire ✅
         │
         ├─ Request approved
         ├─ Rights granted for 4 hours
         ├─ Activities logged
         └─ Rights auto-removed
```

---

### Կետ 8️⃣: Secure AD CS Configurations

**Ի՞նչ է անում:**

```powershell
# Գտնում է certificate templates
Get-ADObject -Filter {objectClass -eq "pKICertificateTemplate"}

# Ստուգում է ESC1 vulnerability
$template.'msPKI-Certificate-Name-Flag' -band 0x1
```

**AD Certificate Services (AD CS):**

```
Components:
┌──────────────────────────────────────┐
│   Certification Authority (CA)       │
│   ├─ Issues certificates             │
│   ├─ Manages PKI infrastructure      │
│   └─ Validates requests              │
└──────────────────────────────────────┘
            │
┌──────────────────────────────────────┐
│   Certificate Templates              │
│   ├─ User certificates               │
│   ├─ Computer certificates           │
│   ├─ Smart card logon               │
│   └─ Code signing                    │
└──────────────────────────────────────┘
```

**ESC1 Vulnerability (ENROLLEE_SUPPLIES_SUBJECT):**

```
Vulnerable Template:
├─ CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT = 1
├─ User can specify Subject Alternative Name (SAN)
├─ Certificate allows authentication
└─ Permissions allow enrollment

Հարձակում:
1. Attacker enrolls for certificate
   │
2. Specifies SAN = Domain Admin
   │
3. CA issues certificate
   │
4. Attacker authenticates as Domain Admin
   │
5. Domain Takeover ❌

Fix:
└─ Remove ENROLLEE_SUPPLIES_SUBJECT flag
└─ Restrict enrollment permissions
└─ Require Manager Approval
```

**ESC2 Vulnerability (Any Purpose EKU):**

```
Extended Key Usage (EKU):
├─ Client Authentication
├─ Smart Card Logon
├─ Code Signing
└─ ANY PURPOSE (2.5.29.37.0) ❌ Վտանգավոր

Խնդիր:
Certificate with "Any Purpose" EKU can be used for anything:
├─ Authentication
├─ Encryption
├─ Digital Signature
└─ Privilege Escalation
```

**Certificate Template Security:**

```powershell
# Լավ Template
Template: SecureWebServer
├─ Purpose: Server Authentication only
├─ Enrollment: Requires approval
├─ SAN: Auto-generated from AD
├─ Validity: 1 year
└─ Permissions: Restricted ✅

# Վատ Template  
Template: VulnerableUser
├─ Purpose: Any Purpose ❌
├─ Enrollment: Auto-enroll ❌
├─ SAN: User-supplied ❌
├─ Validity: 10 years ❌
└─ Permissions: Authenticated Users ❌
```

---

### Կետ 9️⃣: Principle of Least Privilege

**Ի՞նչ է անում:**

```powershell
# Ստուգում է privileged groups-ը
Get-PrivilegedGroups | ForEach-Object {
    Get-ADGroupMember -Identity $_.SID
    # Ստուգում է disabled users-ին
    # Ստուգում է անակտիվ users-ին (90+ days)
}
```

**Least Privilege սկզբունք:**

```
❌ ՍԽԱԼ:
Բոլոր IT աշխատակիցներին տալ Domain Admin

✅ ՃԻՇՏ:
├─ Help Desk ────▶ Password Reset Delegation only
├─ Server Admin ─▶ Server Operators (Tier 1)
├─ Network Admin ▶ DHCP/DNS Admins only
└─ Backup Admin ─▶ Backup Operators only
```

**Privileged Groups Audit:**

```
Domain Admins (RID 512):
├─ Member: administrator ✅ (Active, logged in today)
├─ Member: old.admin ❌ (Disabled, should be removed!)
├─ Member: contractor ❌ (Not logged in for 180 days)
└─ Member: temp.admin ❌ (Created 2 years ago, never used)

Enterprise Admins (RID 519):
├─ Should be EMPTY except during forest operations
└─ Remove immediately after use

Schema Admins (RID 518):
├─ Should be EMPTY except during schema changes
└─ Remove immediately after use
```

**Inactive Account Detection:**

```powershell
# Գտնում է անակտիվ admin accounts
$privilegedUsers = Get-ADGroupMember "Domain Admins"

foreach ($user in $privilegedUsers) {
    $adUser = Get-ADUser $user -Properties LastLogonDate
    
    $daysSinceLogon = (Get-Date) - $adUser.LastLogonDate
    
    if ($daysSinceLogon.Days -gt 90) {
        Write-Warning "User $($user.Name) inactive for $($daysSinceLogon.Days) days"
        # ՊԵՏՔ Է ՀԵՌԱՑՆԵԼ
    }
}
```

**Permission Delegation օրինակ:**

```powershell
# ՍԽԱԼ: Domain Admin իրավունքներ
Add-ADGroupMember -Identity "Domain Admins" -Members "helpdesk"

# ՃԻՇՏ: Specific delegation
$ou = "OU=Users,DC=contoso,DC=com"

# Delegate password reset only
dsacls $ou /G "CONTOSO\HelpDesk:CA;Reset Password;user"

# Delegate user creation only
dsacls $ou /G "CONTOSO\UserAdmins:CC;user"
```

---

### Կետ 🔟: Audit AD CS Setup

**Ի՞նչ է անում:**

```powershell
# Գտնում է PKI infrastructure
$pkiConfig = "CN=Public Key Services,CN=Services,CN=Configuration,..."

# Ստուգում է CA permissions
Get-Acl "AD:$($ca.DistinguishedName)"

# Ստուգում է template vulnerabilities
```

**PKI Hierarchy:**

```
┌─────────────────────────────────────┐
│   Root CA (Offline)                 │
│   ├─ Self-signed certificate        │
│   ├─ Validity: 20+ years            │
│   ├─ Stored offline/disconnected    │
│   └─ Only for issuing subordinate   │
└─────────────┬───────────────────────┘
              │
    ┌─────────▼──────────────────────┐
    │   Subordinate/Issuing CA       │
    │   ├─ Online                    │
    │   ├─ Issues end-entity certs   │
    │   ├─ Validity: 5 years         │
    │   └─ Integrated with AD        │
    └────────────────────────────────┘
```

**CA Permissions Audit:**

```
Secure CA ACL:
├─ Domain Admins: Full Control ✅
├─ Enterprise Admins: Full Control ✅
├─ Cert Publishers: Read ✅
└─ Authenticated Users: Read ✅

Vulnerable CA ACL:
├─ Everyone: Enroll ❌ ՎՏԱՆԳԱՎՈՐ
├─ Authenticated Users: Full Control ❌ ՎՏԱՆԳԱՎՈՐ
└─ Domain Users: Manage CA ❌ ՎՏԱՆԳԱՎՈՐ

Հարձակում:
User ──▶ Full Control on CA ──▶ Issue arbitrary certificates
     └──▶ Escalate to Domain Admin
```

**Certificate Enrollment Process:**

```
1. User/Computer requests certificate
   │
2. Request sent to CA
   │
3. CA validates:
   ├─ Does requestor have permission?
   ├─ Is template enabled?
   ├─ Are requirements met?
   └─ Manager approval needed?
   │
4. CA issues certificate
   │
5. Certificate published to AD
   │
6. User/Computer retrieves certificate
```

**ESC Vulnerabilities Summary:**

```
ESC1: User can specify Subject (SAN)
ESC2: Any Purpose EKU
ESC3: Enrollment Agent abuse
ESC4: Vulnerable template ACL
ESC5: Vulnerable PKI object ACL
ESC6: EDITF_ATTRIBUTESUBJECTALTNAME2 flag
ESC7: Vulnerable CA ACL
ESC8: NTLM Relay to HTTP enrollment
```

---

### Կետ 1️⃣1️⃣: Monitor Issued Certificates

**Ի՞նչ է անում:**

```powershell
# Ստուգում է users-ին սերտիֆիկատներով
Get-ADUser -Filter * -Properties userCertificate

# Ստուգում է expiration
$cert.NotAfter
$daysToExpiry = ($cert.NotAfter - (Get-Date)).Days
```

**Certificate Lifecycle:**

```
┌──────────────────────────────────────┐
│   1. Certificate Request             │
│      User/Computer requests cert     │
└────────────┬─────────────────────────┘
             │
┌────────────▼─────────────────────────┐
│   2. Certificate Issuance            │
│      CA validates and issues         │
└────────────┬─────────────────────────┘
             │
┌────────────▼─────────────────────────┐
│   3. Certificate Installation        │
│      Stored in certificate store     │
└────────────┬─────────────────────────┘
             │
┌────────────▼─────────────────────────┐
│   4. Certificate Usage               │
│      Authentication, encryption      │
└────────────┬─────────────────────────┘
             │
┌────────────▼─────────────────────────┐
│   5. Certificate Renewal/Expiration  │
│      Auto-renew or expires           │
└────────────┬─────────────────────────┘
             │
┌────────────▼─────────────────────────┐
│   6. Certificate Revocation (if bad) │
│      Published to CRL                │
└──────────────────────────────────────┘
```

**Certificate Store Locations:**

```
Windows Certificate Stores:
├─ Current User
│  ├─ Personal (My certs)
│  ├─ Trusted Root CA
│  └─ Intermediate CA
│
└─ Local Machine
   ├─ Personal (Computer certs)
   ├─ Trusted Root CA
   └─ Intermediate CA

AD Attributes:
├─ userCertificate (User certs)
├─ userSMIMECertificate (Email certs)
└─ msPKI-Enrollment-Servers
```

**Certificate Expiration Monitoring:**

```powershell
# Ստուգել սերտիֆիկատներ
$users = Get-ADUser -Filter * -Properties userCertificate

foreach ($user in $users) {
    foreach ($certBytes in $user.userCertificate) {
        $cert = [X509Certificate2]::new($certBytes)
        
        $daysLeft = ($cert.NotAfter - (Get-Date)).Days
        
        if ($daysLeft -lt 0) {
            Write-Warning "$($user.Name): EXPIRED cert"
        }
        elseif ($daysLeft -lt 30) {
            Write-Warning "$($user.Name): Expires in $daysLeft days"
        }
    }
}
```

**Certificate Revocation List (CRL):**

```
Purpose: Ցանկ չեղարկված սերտիֆիկատների

CRL Distribution Point (CDP):
http://pki.contoso.com/CertEnroll/CA.crl

CRL պարունակում է:
├─ Serial number of revoked cert
├─ Revocation date
├─ Reason code
└─ Next update time

Revocation Reasons:
├─ 0: Unspecified
├─ 1: Key Compromise ❌
├─ 2: CA Compromise ❌❌
├─ 3: Affiliation Changed
├─ 4: Superseded
└─ 5: Cessation of Operation
```

---

### Կետ 1️⃣2️⃣: Security Monitoring and Alerting

**Ի՞նչ է անում:**

```powershell
# Ստուգում է Event Log-երի չափը
Get-WinEvent -ListLog Security
Get-WinEvent -ListLog System

# Միացնում է Advanced Audit Policies
auditpol /set /subcategory:"Credential Validation" /success:enable /failure:enable

# Ստեղծում է monitoring script
```

**Critical Security Events:**

```
Authentication Events:
├─ 4624: Successful logon ✅
├─ 4625: Failed logon ❌
├─ 4634: Logoff
├─ 4647: User-initiated logoff
└─ 4648: Logon using explicit credentials

Account Management:
├─ 4720: User account created
├─ 4722: User account enabled
├─ 4723: Password change attempted
├─ 4724: Password reset attempted
├─ 4725: User account disabled
├─ 4726: User account deleted
└─ 4740: Account lockout ⚠️

Privileged Actions:
├─ 4672: Special privileges assigned 👑
├─ 4673: Privileged service called
├─ 4674: Privileged operation attempted
└─ 4697: Service installed ⚠️

Kerberos Events:
├─ 4768: TGT requested
├─ 4769: Service ticket requested
├─ 4770: Service ticket renewed
├─ 4771: Pre-auth failed ❌
└─ 4772: Ticket request failed ❌

AD Changes:
├─ 4728: Member added to security group
├─ 4729: Member removed from security group
├─ 4732: Member added to local group
├─ 4756: Member added to universal group
└─ 5136: Directory service object modified

Process Creation:
└─ 4688: New process created (with command line)
```

**Advanced Audit Policy Categories:**

```powershell
Account Logon:
├─ Credential Validation ✅
├─ Kerberos Authentication Service ✅
└─ Kerberos Service Ticket Operations ✅

Account Management:
├─ User Account Management ✅
├─ Security Group Management ✅
├─ Computer Account Management
└─ Distribution Group Management

Logon/Logoff:
├─ Logon ✅
├─ Logoff
├─ Account Lockout ✅
└─ Special Logon ✅

Object Access:
├─ File System
├─ Registry
├─ SAM (Security Accounts Manager)
└─ Handle Manipulation

Policy Change:
├─ Audit Policy Change ✅
├─ Authentication Policy Change ✅
└─ Authorization Policy Change

Privilege Use:
├─ Sensitive Privilege Use ✅
└─ Non-Sensitive Privilege Use

System:
├─ Security State Change ✅
└─ Security System Extension ✅
```

**Event Log Size Recommendations:**

```
Default Sizes (Too Small):
├─ Security: 20 MB ❌
├─ Application: 20 MB ❌
└─ System: 20 MB ❌

Recommended Sizes:
├─ Security: 512 MB - 4 GB ✅
├─ Application: 100-512 MB ✅
└─ System: 100-512 MB ✅

High-Security Environments:
├─ Security: 4+ GB ✅
└─ Forward to SIEM immediately ✅
```

**Security Monitoring Script Օրինակ:**

```powershell
# Հետևել failed logon attempts
$events = Get-WinEvent -FilterHashtable @{
    LogName = 'Security'
    ID = 4625  # Failed logon
    StartTime = (Get-Date).AddHours(-1)
}

if ($events.Count -gt 10) {
    # Հնարավոր brute-force attack
    Send-MailMessage -To "security@contoso.com" `
        -Subject "ALERT: Multiple Failed Logons" `
        -Body "$($events.Count) failed logons in last hour"
}

# Հետևել privileged group changes
$events = Get-WinEvent -FilterHashtable @{
    LogName = 'Security'
    ID = 4728  # Member added to security group
    StartTime = (Get-Date).AddHours(-1)
}

foreach ($event in $events) {
    if ($event.Message -match "Domain Admins") {
        # Ինչ-որ մեկը ավելացվել է Domain Admins
        Send-Alert "User added to Domain Admins!"
    }
}
```

**SIEM Integration:**

```
Windows Event Forwarding (WEF):
┌──────────┐                ┌──────────────┐
│   DC1    │───Events──────▶│   Collector  │
│   DC2    │───Events──────▶│   Server     │
│   DC3    │───Events──────▶│              │
└──────────┘                └──────┬───────┘
                                   │
                            ┌──────▼───────┐
                            │     SIEM     │
                            │  (Splunk,    │
                            │   Sentinel,  │
                            │   QRadar)    │
                            └──────────────┘
```

---

## Հարձակումների Տեսակներ և Պաշտպանություն

### 1. Pass-the-Hash (PtH)

**Ինչպես է աշխատում:**

```
1. Attacker compromises workstation
   │
2. Dumps NTLM hashes from memory (Mimikatz)
   │
3. Uses hash (without cracking) to authenticate
   │
4. Gains access to other systems
```

**Պաշտպանություն:**

```
✅ Protected Users group
✅ Disable NTLM, use only Kerberos
✅ Local Admin Password Solution (LAPS)
✅ Credential Guard
✅ Remote Credential Guard
```

### 2. Kerberoasting

**Ինչպես է աշխատում:**

```
1. Attacker requests service tickets (TGS)
   │
2. Service tickets encrypted with service account password
   │
3. Attacker extracts tickets from memory
   │
4. Cracks password offline (no detection)
```

**Պաշտպանություն:**

```
✅ Use gMSA (240-char passwords)
✅ Strong service account passwords (25+ chars)
✅ Monitor for TGS requests (Event 4769)
✅ Limit service account permissions
```

### 3. Golden Ticket

**Ինչպես է աշխատում:**

```
1. Attacker gets krbtgt account hash
   │
2. Creates forged TGT (Golden Ticket)
   │
3. TGT valid for any user, any duration
   │
4. Complete domain persistence
```

**Պաշտպանություն:**

```
✅ Protect krbtgt password (reset regularly)
✅ Monitor for TGT anomalies
✅ Detect impossible logons
✅ Use honeypot accounts
```

### 4. DCSync Attack

**Ինչպես է աշխատում:**

```
1. Attacker gets Replicating Directory Changes permission
   │
2. Pretends to be a DC
   │
3. Requests password hashes via replication
   │
4. Dumps entire domain database
```

**Պաշտպանություն:**

```
✅ Audit replication permissions
✅ Monitor Event 4662 (Directory Service Access)
✅ Limit who can replicate
✅ Use Protected Users group
```

---

## Վերջնական Խորհուրդներ

### Priority 1 (Անհրաժեշտ):

```
1. ✅ Enable LDAP Signing
2. ✅ Disable NTLM (եթե հնարավոր է)
3. ✅ Use strong passwords (14+ chars)
4. ✅ Enable account lockout
5. ✅ Monitor privileged groups
```

### Priority 2 (Խորհուրդ է տրվում):

```
6. ✅ Implement MFA for admins
7. ✅ Use gMSA for services
8. ✅ Protected Users group
9. ✅ Secure AD CS templates
10. ✅ Advanced audit policies
```

### Priority 3 (Best Practice):

```
11. ✅ Tiered administration
12. ✅ PAW (Privileged Access Workstations)
13. ✅ Regular security audits (BloodHound)
14. ✅ SIEM integration
15. ✅ Incident response plan
```

---

## Օգտակար Հրամաններ

```powershell
# Ստուգել domain functional level
Get-ADDomain | Select-Object DomainMode

# Գտնել բոլոր Domain Admins
Get-ADGroupMember "Domain Admins" -Recursive

# Գտնել service accounts with SPNs
Get-ADUser -Filter {ServicePrincipalName -ne "$null"} -Properties ServicePrincipalName

# Ստուգել password policy
Get-ADDefaultDomainPasswordPolicy

# Գտնել անակտիվ users
Search-ADAccount -AccountInactive -TimeSpan 90 -UsersOnly

# Ստուգել privileged users առանց MFA
Get-ADGroupMember "Domain Admins" | ForEach-Object {
    Get-ADUser $_ -Properties SmartcardLogonRequired | 
    Where-Object {-not $_.SmartcardLogonRequired}
}

# Մոնիտորինգ failed logons
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4625} -MaxEvents 100

# Գտնել disabled accounts in admin groups
Get-ADGroupMember "Domain Admins" | ForEach-Object {
    Get-ADUser $_ | Where-Object {-not $_.Enabled}
}
```

---

**Ամփոփում:**

AD Hardening Script-ը իրականացնում է 12 կրիտիկական անվտանգության միջոցներ, որոնք պաշտպանում են Active Directory-ն ամենատարածված հարձակումներից։ Յուրաքանչյուր քայլ ուղղված է կոնկրետ vulnerability-ի կամ attack vector-ի դեմ պայքարին։

Հիմնական նպատակը՝ **Defense in Depth** - բազմաշերտ պաշտպանություն, որտեղ յուրաքանչյուր շերտ ավելացնում է անվտանգության մակարդակ։
