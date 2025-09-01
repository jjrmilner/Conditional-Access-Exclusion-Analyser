# Conditional Access Exclusion Analyzer - README Update

Based on your license requirements, here's the updated README.md with the appropriate license section:

```markdown
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

Licensed under the Apache License, Version 2.0 (the "Apache License") with Commons Clause Restriction.

You may not use this file except in compliance with the Apache License. You may obtain a copy of the Apache License at: http://www.apache.org/licenses/LICENSE-2.0

This Software is provided under the Apache License with the following Commons Clause Restriction:

"The license granted herein does not include, and the Apache License does not grant to you, the right to Sell the Software. For purposes of this restriction, "Sell" means practicing any or all of the rights granted to you under the Apache License to provide to third parties, for a fee or other consideration (including without limitation fees for hosting, consulting, implementation, or support services related to the Software), a product or service whose value derives, entirely or substantially, from the functionality of the Software. Any license notice or attribution required by the Apache License must also include this Commons Clause Restriction."

For paid/professional use cases prohibited above, obtain a commercial license from Global Micro Solutions (Pty) Ltd: licensing@globalmicro.co.za

## ⚠️ Warranty Disclaimer

Distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the Apache License for the specific language governing permissions and limitations under the License.

## 🔗 Related Resources

- [Microsoft Conditional Access Documentation](https://docs.microsoft.com/en-us/azure/active-directory/conditional-access/)
- [Microsoft Graph PowerShell SDK](https://docs.microsoft.com/en-us/powershell/microsoftgraph/)
- [Blog: "Help, I'm Trapped in a Conditional Access Policy Factory!"](#)

## 👨‍💻 Author

Developed by Global Micro Solutions (Pty) Ltd

---

**Note**: This tool is provided for analysis purposes. Always test in a non-production environment first and ensure you understand the implications of any changes to your Conditional Access policies.
```

This updated README includes your specific Apache License 2.0 with Commons Clause restriction and the warranty disclaimer, while maintaining all the technical documentation and usage information.
