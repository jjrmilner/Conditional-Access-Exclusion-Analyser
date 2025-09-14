# Conditional Access Exclusion Analyser

Based on your license requirements, here's the updated README.md with the appropriate license section:

```markdown
# Conditional Access Exclusion Analyser

A PowerShell tool for analysing Microsoft Entra ID (Azure AD) Conditional Access policy exclusions. Identify which users are excluded from your security policies and understand the specific reasons for their exclusion.

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
  - Group caching to minimise API calls
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
- Consider analysing specific high-risk users rather than all users
- The script includes progress bars to track status

## 🤝 Contributing

Contributions are welcome! Please feel free to submit issues or pull requests.

## 🔗 Related Resources

- [Microsoft Conditional Access Documentation](https://docs.microsoft.com/en-us/azure/active-directory/conditional-access/)
- [Microsoft Graph PowerShell SDK](https://docs.microsoft.com/en-us/powershell/microsoftgraph/)
- [Blog: "Help, I'm Trapped in a Conditional Access Policy Factory!"](#)

---

## 📄 **License:** Apache 2.0 (see LICENSE)  
**Additional restriction:** Commons Clause (see COMMONS-CLAUSE.txt)

**SPDX headers**
- Each source file includes:  
  `SPDX-License-Identifier: Apache-2.0 WITH Commons-Clause`

---

### FAQ: MSP and Consulting Use

**Q: Can an MSP or consultant use this tool in a paid engagement?**  
**A:** It depends on how the tool is used:  
- **Allowed:** If the tool is used internally by the end customer (e.g., installed in their tenant) and the consultant is simply assisting, this is generally acceptable.  
- **Not allowed without a commercial licence:** If the MSP or consultant provides a managed service where the tool runs in their own environment (e.g., their tenant or infrastructure) or if the value of the service substantially derives from the tool’s functionality, this falls under the definition of “Sell” in the Commons Clause and requires a commercial licence.

**Q: Why is this restricted?**  
The Commons Clause removes the right to “Sell,” which includes providing a service for a fee where the value derives from the software. This ensures fair use and prevents competitors from monetising the tool without contributing back.

**Q: How do I get a commercial licence?**  
Contact Global Micro Solutions (Pty) Ltd at:  
📧 licensing@globalmicro.co.za

## ⚠️ Warranty Disclaimer

Distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. Please review the Apache-2.0 WITH Commons-Clause License for the specific language governing permissions and limitations under the License.
