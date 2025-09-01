# Conditional Access Exclusion Analyzer

A PowerShell tool for analyzing Microsoft Entra ID (Azure AD) Conditional Access policy exclusions. Discover which users are excluded from your security policies and understand exactly why.

## 🎯 Purpose

Ever wondered why certain users aren't being prompted for MFA? Or which legacy groups are creating security gaps in your Conditional Access policies? This script provides complete visibility into policy exclusions, helping you identify and remediate security risks.

## ✨ Features

- **Comprehensive Exclusion Detection**
  - Direct user exclusions
  - Group membership exclusions (including nested groups)
  - Directory role-based exclusions
  - Guest/External user type exclusions

- **Intelligent Analysis**
  - Recursive nested group traversal with circular reference protection
  - Shows exact group membership paths (direct vs nested)
  - Identifies which specific groups cause each exclusion

- **Flexible Usage**
  - Interactive mode with prompts
  - Command-line parameters for automation
  - CSV export for reporting and audits

- **Performance Optimized**
  - Progress tracking for large environments
  - Group caching to minimize API calls
  - Efficient handling of complex group structures

## 📋 Prerequisites

### Required PowerShell Modules
```powershell
Install-Module Microsoft.Graph.Authentication -Scope CurrentUser
Install-Module Microsoft.Graph.Identity.SignIns -Scope CurrentUser
Install-Module Microsoft.Graph.Users -Scope CurrentUser
Install-Module Microsoft.Graph.Groups -Scope CurrentUser
Install-Module Microsoft.Graph.Identity.DirectoryManagement -Scope CurrentUser
```

### Required Permissions
- `Policy.Read.All` - Read Conditional Access policies
- `User.Read.All` - Read user information
- `Group.Read.All` - Read group memberships
- `RoleManagement.Read.Directory` - Read directory role assignments

## 🚀 Quick Start

### Interactive Mode
```powershell
.\Get-ConditionalAccessUserExclusions.ps1
```

### By User Principal Name
```powershell
.\Get-ConditionalAccessUserExclusions.ps1 -UserPrincipalName "user@domain.com"
```

### By Object ID
```powershell
.\Get-ConditionalAccessUserExclusions.ps1 -ObjectId "12345678-1234-1234-1234-123456789012"
```

### With CSV Export
```powershell
.\Get-ConditionalAccessUserExclusions.ps1 -UserPrincipalName "user@domain.com" -OutputPath "C:\Reports\Exclusions.csv"
```

## 📊 Sample Output

```
CONDITIONAL ACCESS EXCLUSION ANALYSIS RESULTS
================================================================================
User: John Doe (john.doe@contoso.com)
User Type: Member
Total Policies: 52
Policies with Exclusions: 14
================================================================================

Policy: Require MFA for All Users
State: enabled
Exclusions:
  - Type: Group Membership | Group: Emergency Access Accounts
    Member of excluded group (Direct)
  - Type: Group Membership | Group: Service Accounts
    Member of excluded group (Nested via IT_Systems)

SUMMARY BY EXCLUSION TYPE:
------------------------------
Direct User: 2 exclusion(s)
Group Membership: 12 exclusion(s)

GROUPS CAUSING EXCLUSIONS:
------------------------------
  - Emergency Access Accounts (8 policies) - Member of excluded group (Direct)
  - Service Accounts (4 policies) - Member of excluded group (Nested via IT_Systems)

Total unique groups causing exclusions: 2
```

## 🛠️ Use Cases

1. **Security Audits** - Identify users with excessive exclusions
2. **Compliance Reporting** - Document policy exceptions for auditors
3. **Troubleshooting** - Understand why policies aren't applying
4. **Cleanup Projects** - Find and remove legacy exclusion groups
5. **Zero Trust Implementation** - Reduce exclusions systematically

## 📝 CSV Export Format

The exported CSV includes:
- PolicyName
- PolicyState
- ExclusionType
- ExclusionName
- ExclusionDetail
- PolicyId
- ExclusionId

## 🐛 Troubleshooting

### "Insufficient privileges" error
Ensure your account has the required Microsoft Graph permissions listed above.

### "Module not found" error
Install the required PowerShell modules using the commands in the Prerequisites section.

### Script runs slowly
- Large numbers of nested groups can impact performance
- Consider analyzing specific high-risk users rather than all users
- The script includes progress bars to track status

## 🤝 Contributing

Contributions are welcome! Please feel free to submit issues or pull requests.

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🔗 Related Resources

- [Microsoft Conditional Access Documentation](https://docs.microsoft.com/en-us/azure/active-directory/conditional-access/)
- [Microsoft Graph PowerShell SDK](https://docs.microsoft.com/en-us/powershell/microsoftgraph/)
- [Blog: "Help, I'm Trapped in a Conditional Access Policy Factory!"](#)

## ⚠️ Disclaimer

This tool is provided as-is for analysis purposes. Always test in a non-production environment first and ensure you understand the implications of any changes to your Conditional Access policies.
