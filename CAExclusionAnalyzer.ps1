<# SPDX-License-Identifier: Apache-2.0 WITH Commons-Clause
# Copyright (c) 2025 Global Micro Solutions (Pty) Ltd
# All rights reserved

.WARRANTY
    Distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
    either express or implied. See the Apache-2.0 WITH Commons-Clause License for the specific language
    governing permissions and limitations under the License.

.SYNOPSIS
    Analyzes Microsoft Entra ID (Azure AD) Conditional Access policies to identify user exclusions and their reasons.

.DESCRIPTION
    This PowerShell script provides a comprehensive analysis of Conditional Access policy exclusions for a specific user
    in Microsoft Entra ID. It helps administrators understand why certain users might be excluded from security policies,
    which is crucial for security auditing and compliance.

    The script identifies four types of exclusions:
    1. Direct user exclusions - User is explicitly excluded
    2. Group-based exclusions - User is excluded via group membership (including nested groups)
    3. Directory role exclusions - User is excluded based on assigned administrative roles
    4. Guest/External user exclusions - User is excluded based on their user type

    Key Features:
    - Comprehensive exclusion analysis across all Conditional Access policies
    - Nested group membership detection with circular reference protection
    - Interactive mode for ease of use
    - Detailed reporting showing which groups cause exclusions
    - CSV export capability for documentation and auditing
    - Progress tracking for large environments
    - Robust error handling and logging

.PARAMETER UserPrincipalName
    The User Principal Name (UPN) of the user to analyse. This is typically the user's email address
    in Microsoft Entra ID. Example: john.doe@contoso.com

.PARAMETER ObjectId
    The Object ID (GUID) of the user to analyse. This is the unique identifier for the user
    in Microsoft Entra ID. Example: 12345678-1234-1234-1234-123456789012

.PARAMETER OutputPath
    Optional path to export the results to a CSV file. If not specified, results are only displayed
    in the console. The directory must exist, and the file will be created or overwritten.
    Example: C:\Reports\CA_Exclusions.csv

.EXAMPLE
    # Run in interactive mode (prompts for all parameters)
    .\Get-ConditionalAccessUserExclusions.ps1

    This launches the script in interactive mode, prompting you to choose how to identify the user
    and whether to export results to CSV.

.EXAMPLE
    # Analyse user by UPN
    .\Get-ConditionalAccessUserExclusions.ps1 -UserPrincipalName "john.doe@contoso.com"
    
    Analyses all Conditional Access policies to find exclusions for john.doe@contoso.com and
    displays results in the console.

.EXAMPLE
    # Analyse user by Object ID with CSV export
    .\Get-ConditionalAccessUserExclusions.ps1 -ObjectId "12345678-1234-1234-1234-123456789012" -OutputPath "C:\Reports\JohnDoe_Exclusions.csv"
    
    Analyses exclusions using the user's Object ID and exports detailed results to a CSV file
    for documentation or further analysis.

.EXAMPLE
    # Analyse admin user with many group memberships
    .\Get-ConditionalAccessUserExclusions.ps1 -UserPrincipalName "admin@contoso.com" -OutputPath "C:\Audit\AdminExclusions.csv"
    
    Particularly useful for analysing administrative accounts that may have numerous group
    memberships and role assignments causing policy exclusions.

.NOTES
    GitHub: https://github.com/jjrmilner/ConditionalAccessTools
    Blog: https://jjrmilner.substack.com/analyzing-conditional-access-exclusions
    
    Prerequisites:
    - PowerShell 5.1 or higher
    - Microsoft Graph PowerShell SDK modules (see REQUIREMENTS section)
    - Appropriate permissions in Microsoft Entra ID (see REQUIREMENTS section)
    
    REQUIREMENTS:
    
    Required PowerShell Modules:
    - Microsoft.Graph.Authentication
    - Microsoft.Graph.Identity.SignIns
    - Microsoft.Graph.Users
    - Microsoft.Graph.Groups
    - Microsoft.Graph.Identity.DirectoryManagement
    
    To install all required modules:
    Install-Module Microsoft.Graph.Authentication, Microsoft.Graph.Identity.SignIns, Microsoft.Graph.Users, Microsoft.Graph.Groups, Microsoft.Graph.Identity.DirectoryManagement -Scope CurrentUser
    
    Required Microsoft Graph API Permissions:
    - Policy.Read.All - Read all Conditional Access policies
    - User.Read.All - Read user information
    - Group.Read.All - Read group information and memberships
    - RoleManagement.Read.Directory - Read directory role assignments
    
    The account running the script must have appropriate permissions to read these resources
    in your Microsoft Entra ID tenant.

    LIMITATIONS:
    - Maximum of 999 Conditional Access policies per tenant (Microsoft limit)
    - Large environments with many nested groups may take several minutes to analyze
    - Some exclusion types (like terms of use) may not be detected

    TROUBLESHOOTING:
    - If you receive "Insufficient privileges" errors, ensure your account has the required permissions
    - For "Module not found" errors, install the required modules using the command above
    - For timeout issues in large environments, consider analyzing specific user groups separately

.LINK
    https://docs.microsoft.com/en-us/powershell/microsoftgraph/

.LINK
    https://docs.microsoft.com/en-us/azure/active-directory/conditional-access/

.LINK
    https://github.com/microsoftgraph/msgraph-sdk-powershell
#>

# Script parameters with validation
[CmdletBinding(DefaultParameterSetName = "Interactive")]
param(
    [Parameter(Mandatory = $true, ParameterSetName = "UPN", HelpMessage = "Enter the user's email address")]
    [ValidatePattern('^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$')]
    [string]$UserPrincipalName,
    
    [Parameter(Mandatory = $true, ParameterSetName = "ObjectId", HelpMessage = "Enter the user's Object ID (GUID)")]
    [ValidatePattern('^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$')]
    [string]$ObjectId,
    
    [Parameter(Mandatory = $false, HelpMessage = "Enter the path for CSV export")]
    [ValidateScript({
        if ($_ -eq "") { return $true }
        $parentDir = Split-Path -Path $_ -Parent
        if (-not (Test-Path -Path $parentDir -PathType Container)) {
            throw "The directory '$parentDir' does not exist. Please create it first or specify a different path."
        }
        return $true
    })]
    [string]$OutputPath
)

#region Helper Functions
# These functions provide core functionality for the script

<#
.SYNOPSIS
    Writes formatted log messages to the console with timestamps and color coding.

.DESCRIPTION
    This function standardizes output formatting throughout the script, making it easier
    to follow the script's progress and identify warnings or errors.
#>
function Write-LogMessage {
    param(
        [Parameter(Mandatory = $false)]
        [AllowEmptyString()]
        [string]$Message = "",
        
        [Parameter(Mandatory = $false)]
        [ValidateSet("Info", "Warning", "Error", "Success")]
        [string]$Type = "Info"
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $color = switch ($Type) {
        "Info" { "White" }
        "Warning" { "Yellow" }
        "Error" { "Red" }
        "Success" { "Green" }
    }
    
    if ($Message -eq "") {
        Write-Host ""
    }
    else {
        Write-Host "[$timestamp] $Message" -ForegroundColor $color
    }
}

<#
.SYNOPSIS
    Tests the current Microsoft Graph connection.

.DESCRIPTION
    Verifies that we have an active Microsoft Graph session by attempting
    to retrieve organization information.
#>
function Test-GraphConnection {
    try {
        $context = Get-MgContext
        if ($null -eq $context) {
            return $false
        }
        
        # Test if we can make a basic Graph call
        $null = Get-MgOrganization -ErrorAction Stop
        return $true
    }
    catch {
        return $false
    }
}

<#
.SYNOPSIS
    Establishes or validates Microsoft Graph connection with required permissions.

.DESCRIPTION
    This function ensures we have an active Microsoft Graph connection with all
    necessary permissions to read Conditional Access policies, users, groups, and roles.
    If permissions are missing, it will reconnect with the required scopes.
#>
function Connect-ToGraph {
    param(
        [string[]]$RequiredScopes = @(
            "Policy.Read.All",              # Read Conditional Access policies
            "User.Read.All",                # Read user information
            "Group.Read.All",               # Read group memberships
            "RoleManagement.Read.Directory" # Read role assignments
        )
    )
    
    Write-LogMessage "Checking Microsoft Graph connection..." -Type "Info"
    
    if (-not (Test-GraphConnection)) {
        Write-LogMessage "Connecting to Microsoft Graph with required scopes..." -Type "Info"
        Write-LogMessage "You may be prompted to authenticate and consent to permissions." -Type "Warning"
        try {
            Connect-MgGraph -Scopes $RequiredScopes -NoWelcome -ErrorAction Stop
            Write-LogMessage "Successfully connected to Microsoft Graph" -Type "Success"
        }
        catch {
            Write-LogMessage "Failed to connect to Microsoft Graph: $($_.Exception.Message)" -Type "Error"
            Write-LogMessage "Please ensure you have the required permissions and try again." -Type "Error"
            throw $_
        }
    }
    else {
        Write-LogMessage "Already connected to Microsoft Graph" -Type "Success"
    }
    
    # Verify we have all required scopes
    $context = Get-MgContext
    $currentScopes = $context.Scopes
    $missingScopes = $RequiredScopes | Where-Object { $_ -notin $currentScopes }
    
    if ($missingScopes.Count -gt 0) {
        Write-LogMessage "Missing required scopes: $($missingScopes -join ', ')" -Type "Warning"
        Write-LogMessage "Reconnecting with additional scopes..." -Type "Info"
        try {
            Disconnect-MgGraph -ErrorAction SilentlyContinue
            Connect-MgGraph -Scopes $RequiredScopes -NoWelcome -ErrorAction Stop
            Write-LogMessage "Successfully reconnected with required scopes" -Type "Success"
        }
        catch {
            Write-LogMessage "Failed to reconnect with required scopes: $($_.Exception.Message)" -Type "Error"
            throw $_
        }
    }
}

<#
.SYNOPSIS
    Retrieves user details from Microsoft Entra ID.

.DESCRIPTION
    Fetches user information using either UPN or Object ID, including properties
    needed for exclusion analysis like UserType (Member vs Guest).
#>
function Get-UserDetails {
    param(
        [string]$UserPrincipalName,
        [string]$ObjectId
    )
    
    try {
        if ($UserPrincipalName) {
            Write-LogMessage "Retrieving user details for UPN: $UserPrincipalName" -Type "Info"
            $filter = "userPrincipalName eq '$UserPrincipalName'"
            $user = Get-MgUser -Filter $filter -Property Id,DisplayName,UserPrincipalName,UserType -ErrorAction Stop
        }
        else {
            Write-LogMessage "Retrieving user details for Object ID: $ObjectId" -Type "Info"
            $user = Get-MgUser -UserId $ObjectId -Property Id,DisplayName,UserPrincipalName,UserType -ErrorAction Stop
        }
        
        if ($null -eq $user) {
            throw "User not found in Microsoft Entra ID"
        }
        
        Write-LogMessage "Found user: $($user.DisplayName) ($($user.UserPrincipalName))" -Type "Success"
        Write-LogMessage "User type: $($user.UserType)" -Type "Info"
        return $user
    }
    catch {
        Write-LogMessage "Failed to retrieve user details: $($_.Exception.Message)" -Type "Error"
        throw $_
    }
}

<#
.SYNOPSIS
    Retrieves all group memberships for a user, including nested groups.

.DESCRIPTION
    This function performs a recursive search to find all groups a user belongs to,
    both directly and through nested group memberships. It includes protection against
    circular group references and provides progress tracking for large group structures.

.NOTES
    The function uses a HashSet to track processed groups and prevent infinite loops
    in case of circular group memberships. It also caches group information to minimize
    API calls for better performance.
#>
function Get-UserGroupMemberships {
    param(
        [Parameter(Mandatory = $true)]
        [string]$UserId,
        
        [Parameter(Mandatory = $false)]
        [hashtable]$GroupCache = @{},
        
        [Parameter(Mandatory = $false)]
        [System.Collections.Generic.HashSet[string]]$ProcessedGroups = [System.Collections.Generic.HashSet[string]]::new(),
        
        [Parameter(Mandatory = $false)]
        [bool]$IsNestedCall = $false,
        
        [Parameter(Mandatory = $false)]
        [int]$TotalGroupsProcessed = 0
    )
    
    $allMemberships = @()
    
    try {
        # Get direct group memberships
        # For nested calls, we are checking a group's memberships, not a user's memberships
        if ($IsNestedCall) {
            # Get groups that this group is a member of (for nested group detection)
            $directMemberships = Get-MgGroupMemberOf -GroupId $UserId -All -ErrorAction Stop | 
                Where-Object { $_.AdditionalProperties.'@odata.type' -eq '#microsoft.graph.group' }
        }
        else {
            # Get groups that the user is a member of
            $directMemberships = Get-MgUserMemberOf -UserId $UserId -All -ErrorAction Stop | 
                Where-Object { $_.AdditionalProperties.'@odata.type' -eq '#microsoft.graph.group' }
        }
        
        $membershipCount = 0
        $totalMemberships = $directMemberships.Count
        
        foreach ($membership in $directMemberships) {
            $membershipCount++
            $groupId = $membership.Id
            
            # Update progress for group processing (only for initial user call)
            if (-not $IsNestedCall -and $totalMemberships -gt 0) {
                Write-Progress -Activity "Processing Group Memberships" `
                    -Status "Processing group $membershipCount of $totalMemberships" `
                    -PercentComplete (($membershipCount / $totalMemberships) * 100) `
                    -Id 2
            }
            
            # Skip if we've already processed this group (prevents circular references)
            if ($ProcessedGroups.Contains($groupId)) {
                continue
            }
            $ProcessedGroups.Add($groupId) | Out-Null
            $TotalGroupsProcessed++
            
            # Get group details (use cache if available for performance)
            if (-not $GroupCache.ContainsKey($groupId)) {
                try {
                    $GroupCache[$groupId] = Get-MgGroup -GroupId $groupId `
                        -Property Id,DisplayName,GroupTypes -ErrorAction Stop
                }
                catch {
                    Write-LogMessage "Warning: Could not retrieve details for group $groupId" -Type "Warning"
                    continue
                }
            }
            
            $group = $GroupCache[$groupId]
            $allMemberships += [PSCustomObject]@{
                GroupId = $groupId
                GroupName = $group.DisplayName
                MembershipType = "Direct"
                GroupTypes = $group.GroupTypes -join ","
            }
            
            # Recursively get nested group memberships
            try {
                $nestedMemberships = Get-UserGroupMemberships -UserId $groupId `
                    -GroupCache $GroupCache `
                    -ProcessedGroups $ProcessedGroups `
                    -IsNestedCall $true `
                    -TotalGroupsProcessed $TotalGroupsProcessed
                    
                foreach ($nested in $nestedMemberships) {
                    # Update membership type to show the path through nested groups
                    $nested.MembershipType = "Nested (via $($group.DisplayName))"
                    $allMemberships += $nested
                }
            }
            catch {
                # This is expected when the group has no nested memberships
                # Only log if it's not a "not found" error
                if ($_.Exception.Message -notlike "*does not exist*") {
                    Write-LogMessage "Warning: Could not retrieve nested memberships for group $($group.DisplayName): $($_.Exception.Message)" -Type "Warning"
                }
            }
        }
        
        if (-not $IsNestedCall) {
            Write-Progress -Activity "Processing Group Memberships" -Completed -Id 2
        }
    }
    catch {
        # Only show warning for the initial user call, not for nested group checks
        if (-not $IsNestedCall) {
            Write-LogMessage "Warning: Could not retrieve group memberships for user $UserId : $($_.Exception.Message)" -Type "Warning"
        }
    }
    
    return $allMemberships
}

<#
.SYNOPSIS
    Retrieves directory role assignments for a user.

.DESCRIPTION
    Gets all Microsoft Entra ID directory roles assigned to the user. These roles
    might cause exclusions from Conditional Access policies targeting administrative accounts.
#>
function Get-UserRoleAssignments {
    param(
        [Parameter(Mandatory = $true)]
        [string]$UserId
    )
    
    # Initialize empty array to ensure we never return null
    $userRoles = @()
    
    try {
        Write-LogMessage "Retrieving directory role assignments for user..." -Type "Info"
        
        # Get all role assignments for the user
        $filter = "principalId eq '$UserId'"
        $roleAssignments = Get-MgRoleManagementDirectoryRoleAssignment -Filter $filter -All -ErrorAction Stop
        
        foreach ($assignment in $roleAssignments) {
            try {
                $roleDefinition = Get-MgRoleManagementDirectoryRoleDefinition `
                    -UnifiedRoleDefinitionId $assignment.RoleDefinitionId -ErrorAction Stop
                    
                $userRoles += [PSCustomObject]@{
                    RoleId = $assignment.RoleDefinitionId
                    RoleName = $roleDefinition.DisplayName
                    RoleTemplateId = $roleDefinition.TemplateId
                    AssignmentType = "Direct"
                }
            }
            catch {
                Write-LogMessage "Warning: Could not retrieve role definition for ID $($assignment.RoleDefinitionId)" -Type "Warning"
            }
        }
        
        Write-LogMessage "Found $($userRoles.Count) direct role assignments" -Type "Info"
    }
    catch {
        Write-LogMessage "Warning: Could not retrieve role assignments: $($_.Exception.Message)" -Type "Warning"
    }
    
    # Always return an array, even if empty
    return ,$userRoles
}

<#
.SYNOPSIS
    Tests if a user is excluded from a specific Conditional Access policy.

.DESCRIPTION
    This function analyzes a Conditional Access policy to determine if and why a user
    is excluded. It checks for:
    - Direct user exclusions
    - Group-based exclusions (including nested groups)
    - Directory role-based exclusions
    - Guest/External user type exclusions

.NOTES
    Returns an array of exclusion objects, each containing details about why the user
    is excluded from the policy.
#>
function Test-UserInCAExclusion {
    param(
        [Parameter(Mandatory = $true)]
        [object]$Policy,
        
        [Parameter(Mandatory = $true)]
        [object]$User,
        
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [array]$UserGroupMemberships,
        
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [array]$UserRoleAssignments,
        
        [Parameter(Mandatory = $false)]
        [hashtable]$GroupCache = @{}
    )
    
    $exclusions = @()
    $conditions = $Policy.Conditions.Users
    
    # Check 1: Direct user exclusion
    # The user's Object ID is explicitly listed in the policy's excluded users
    if ($conditions.ExcludeUsers -contains $User.Id) {
        $exclusions += [PSCustomObject]@{
            PolicyId = $Policy.Id
            PolicyName = $Policy.DisplayName
            PolicyState = $Policy.State
            ExclusionType = "Direct User"
            ExclusionDetail = "User directly excluded by Object ID"
            ExclusionId = $User.Id
            ExclusionName = $User.DisplayName
        }
    }
    
    # Check 2: Group-based exclusions
    # The user is excluded because they're a member of an excluded group
    if ($conditions.ExcludeGroups -and $conditions.ExcludeGroups.Count -gt 0) {
        foreach ($excludedGroupId in $conditions.ExcludeGroups) {
            $membershipMatch = $UserGroupMemberships | Where-Object { $_.GroupId -eq $excludedGroupId }
            if ($membershipMatch) {
                foreach ($membership in $membershipMatch) {
                    $exclusions += [PSCustomObject]@{
                        PolicyId = $Policy.Id
                        PolicyName = $Policy.DisplayName
                        PolicyState = $Policy.State
                        ExclusionType = "Group Membership"
                        ExclusionDetail = "Member of excluded group ($($membership.MembershipType))"
                        ExclusionId = $excludedGroupId
                        ExclusionName = $membership.GroupName
                    }
                }
            }
        }
    }
    
    # Check 3: Role-based exclusions
    # The user is excluded because they have an excluded directory role
    if ($conditions.ExcludeRoles -and $conditions.ExcludeRoles.Count -gt 0) {
        foreach ($excludedRoleId in $conditions.ExcludeRoles) {
            $roleMatch = $UserRoleAssignments | Where-Object { 
                $_.RoleTemplateId -eq $excludedRoleId -or $_.RoleId -eq $excludedRoleId 
            }
            if ($roleMatch) {
                foreach ($role in $roleMatch) {
                    $exclusions += [PSCustomObject]@{
                        PolicyId = $Policy.Id
                        PolicyName = $Policy.DisplayName
                        PolicyState = $Policy.State
                        ExclusionType = "Directory Role"
                        ExclusionDetail = "Has excluded directory role"
                        ExclusionId = $excludedRoleId
                        ExclusionName = $role.RoleName
                    }
                }
            }
        }
    }
    
    # Check 4: Guest/External user exclusions
    # The user is excluded because of their user type (Guest vs Member)
    if ($conditions.ExcludeGuestsOrExternalUsers -and $User.UserType -eq "Guest") {
        $guestExclusions = $conditions.ExcludeGuestsOrExternalUsers
        $excludedGuestTypes = @(
            "internalGuest",
            "b2bCollaborationGuest",
            "b2bDirectConnectUser",
            "otherExternalUser",
            "serviceProvider"
        )
        
        $matchingTypes = $guestExclusions.GuestOrExternalUserTypes | Where-Object { $_ -in $excludedGuestTypes }
        if ($matchingTypes) {
            $exclusions += [PSCustomObject]@{
                PolicyId = $Policy.Id
                PolicyName = $Policy.DisplayName
                PolicyState = $Policy.State
                ExclusionType = "Guest/External User"
                ExclusionDetail = "Excluded as guest/external user type: $($matchingTypes -join ', ')"
                ExclusionId = $User.Id
                ExclusionName = $User.DisplayName
            }
        }
    }
    
    return $exclusions
}

#endregion Helper Functions

#region Main Script Logic

<#
.SYNOPSIS
    Main execution function that orchestrates the exclusion analysis.

.DESCRIPTION
    This function coordinates all the steps of the analysis:
    1. Handles interactive mode if no parameters provided
    2. Connects to Microsoft Graph
    3. Retrieves user information
    4. Gets group memberships and role assignments
    5. Analyzes all Conditional Access policies
    6. Formats and displays results
    7. Exports to CSV if requested
#>
function Main {
    try {
        Write-LogMessage "Starting Conditional Access User Exclusion Analysis" -Type "Info"
        Write-LogMessage "Script Version: 1.0.0 | Microsoft Graph PowerShell SDK" -Type "Info"
        Write-LogMessage "For updates and documentation, visit: https://github.com/yourusername/ConditionalAccessTools" -Type "Info"
        
        # Interactive mode - prompt for parameters if not provided
        if ($PSCmdlet.ParameterSetName -eq "Interactive") {
            Write-Host "`n==== Conditional Access User Exclusion Analysis ====" -ForegroundColor Cyan
            Write-Host "This script will analyze which Conditional Access policies exclude a specific user." -ForegroundColor White
            Write-Host "It helps identify security policy gaps and understand why users might bypass certain controls.`n" -ForegroundColor White
            
            # Ask user to choose input method
            Write-Host "How would you like to identify the user?" -ForegroundColor Yellow
            Write-Host "1. User Principal Name (email address)" -ForegroundColor White
            Write-Host "2. Object ID (GUID)" -ForegroundColor White
            Write-Host "3. Exit" -ForegroundColor White
            
            do {
                $choice = Read-Host "`nEnter your choice (1-3)"
                $validChoice = $choice -match '^[1-3]$'
                if (-not $validChoice) {
                    Write-Host "Invalid choice. Please enter 1, 2, or 3." -ForegroundColor Red
                }
            } while (-not $validChoice)
            
            switch ($choice) {
                "1" {
                    do {
                        $UserPrincipalName = Read-Host "`nEnter the User Principal Name (email address)"
                        if ($UserPrincipalName -notmatch '^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$') {
                            Write-Host "Invalid email format. Please enter a valid email address." -ForegroundColor Red
                            $UserPrincipalName = $null
                        }
                    } while (-not $UserPrincipalName)
                    $inputMethod = "UPN"
                }
                "2" {
                    do {
                        $ObjectId = Read-Host "`nEnter the Object ID (GUID)"
                        if ($ObjectId -notmatch '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$') {
                            Write-Host "Invalid GUID format. Please enter a valid Object ID." -ForegroundColor Red
                            Write-Host "Example: 12345678-1234-1234-1234-123456789012" -ForegroundColor Gray
                            $ObjectId = $null
                        }
                    } while (-not $ObjectId)
                    $inputMethod = "ObjectId"
                }
                "3" {
                    Write-Host "`nExiting script..." -ForegroundColor Yellow
                    exit 0
                }
            }
            
            # Ask about CSV export
            $exportChoice = Read-Host "`nDo you want to export results to CSV? (Y/N)"
            if ($exportChoice -eq 'Y' -or $exportChoice -eq 'y') {
                do {
                    $OutputPath = Read-Host "Enter the full path for the CSV file (e.g., C:\Reports\CA_Exclusions.csv)"
                    if ($OutputPath) {
                        $parentDir = Split-Path -Path $OutputPath -Parent
                        if (-not (Test-Path -Path $parentDir -PathType Container)) {
                            Write-Host "The directory '$parentDir' does not exist. Please enter a valid path." -ForegroundColor Red
                            $OutputPath = $null
                        }
                        elseif (-not $OutputPath.EndsWith('.csv')) {
                            $OutputPath = "$OutputPath.csv"
                            Write-Host "Added .csv extension: $OutputPath" -ForegroundColor Yellow
                        }
                    }
                } while ($OutputPath -and -not (Test-Path -Path (Split-Path -Path $OutputPath -Parent) -PathType Container))
            }
            
            Write-Host "`nStarting analysis..." -ForegroundColor Green
            Write-Host ("-"*50) -ForegroundColor Gray
        }
        else {
            $inputMethod = $PSCmdlet.ParameterSetName
        }
        
        # Step 1: Connect to Microsoft Graph
        Write-Progress -Activity "Initializing" -Status "Connecting to Microsoft Graph..." -PercentComplete 0
        Connect-ToGraph
        
        # Step 2: Get user details
        Write-Progress -Activity "Analyzing User" -Status "Retrieving user details..." -PercentComplete 10
        if ($inputMethod -eq "UPN" -or $UserPrincipalName) {
            $targetUser = Get-UserDetails -UserPrincipalName $UserPrincipalName
        }
        else {
            $targetUser = Get-UserDetails -ObjectId $ObjectId
        }
        
        # Step 3: Get user's group memberships (including nested)
        Write-LogMessage "Analyzing user's group memberships (including nested groups)..." -Type "Info"
        Write-Progress -Activity "Analyzing User" -Status "Retrieving group memberships..." -PercentComplete 20
        $groupCache = @{}
        $userGroupMemberships = @(Get-UserGroupMemberships -UserId $targetUser.Id -GroupCache $groupCache)
        if ($null -eq $userGroupMemberships) { $userGroupMemberships = @() }
        Write-LogMessage "Found $($userGroupMemberships.Count) total group memberships" -Type "Info"
        
        # Step 4: Get user's role assignments
        Write-Progress -Activity "Analyzing User" -Status "Retrieving role assignments..." -PercentComplete 40
        $userRoleAssignments = @(Get-UserRoleAssignments -UserId $targetUser.Id)
        if ($null -eq $userRoleAssignments) { $userRoleAssignments = @() }
        
        # Step 5: Get all Conditional Access policies
        Write-LogMessage "Retrieving all Conditional Access policies..." -Type "Info"
        Write-Progress -Activity "Analyzing User" -Status "Retrieving Conditional Access policies..." -PercentComplete 60
        $policies = Get-MgIdentityConditionalAccessPolicy -All -ErrorAction Stop
        Write-LogMessage "Found $($policies.Count) Conditional Access policies" -Type "Info"
        
        # Step 6: Analyze each policy for exclusions
        Write-LogMessage "Analyzing policies for user exclusions..." -Type "Info"
        $allExclusions = @()
        $policyCount = 0
        
        foreach ($policy in $policies) {
            $policyCount++
            Write-Progress -Activity "Analyzing Conditional Access Policies" `
                -Status "Policy $policyCount of $($policies.Count): $($policy.DisplayName)" `
                -PercentComplete (60 + (($policyCount / $policies.Count) * 35))
            
            $exclusions = Test-UserInCAExclusion -Policy $policy `
                -User $targetUser `
                -UserGroupMemberships $userGroupMemberships `
                -UserRoleAssignments $userRoleAssignments `
                -GroupCache $groupCache
                
            $allExclusions += $exclusions
        }
        
        Write-Progress -Activity "Analyzing Conditional Access Policies" -Completed
        Write-Progress -Activity "Analyzing User" -Completed
        
        # Step 7: Display results
        $separator = "="*80
        Write-LogMessage
        Write-LogMessage $separator -Type "Info"
        Write-LogMessage "CONDITIONAL ACCESS EXCLUSION ANALYSIS RESULTS" -Type "Success"
        Write-LogMessage $separator -Type "Info"
        Write-LogMessage "User: $($targetUser.DisplayName) ($($targetUser.UserPrincipalName))" -Type "Info"
        Write-LogMessage "User Type: $($targetUser.UserType)" -Type "Info"
        Write-LogMessage "Total Policies: $($policies.Count)" -Type "Info"
        Write-LogMessage "Total Exclusions Found: $($allExclusions.Count)" -Type "Info"
        Write-LogMessage $separator -Type "Info"
        Write-LogMessage
        
        if ($allExclusions.Count -eq 0) {
            Write-LogMessage "No Conditional Access policy exclusions found for this user." -Type "Warning"
            Write-LogMessage "This user is subject to all Conditional Access policies without exceptions." -Type "Info"
        }
        else {
            Write-LogMessage "EXCLUSION DETAILS:" -Type "Success"
            $detailSeparator = "-"*50
            Write-LogMessage $detailSeparator -Type "Info"
            
            # Group exclusions by policy for better readability
            $exclusionsByPolicy = $allExclusions | Group-Object PolicyName
            
            foreach ($policyGroup in $exclusionsByPolicy | Sort-Object Name) {
                Write-Host "`nPolicy: " -NoNewline -ForegroundColor Cyan
                Write-Host $policyGroup.Name -ForegroundColor White
                Write-Host "State: " -NoNewline -ForegroundColor Gray
                Write-Host $policyGroup.Group[0].PolicyState -ForegroundColor Yellow
                Write-Host "Exclusions:" -ForegroundColor Gray
                
                foreach ($exclusion in $policyGroup.Group | Sort-Object ExclusionType, ExclusionName) {
                    Write-Host "  - Type: " -NoNewline -ForegroundColor Gray
                    Write-Host $exclusion.ExclusionType -NoNewline -ForegroundColor Green
                    
                    if ($exclusion.ExclusionType -eq "Group Membership") {
                        Write-Host " | Group: " -NoNewline -ForegroundColor Gray
                        Write-Host $exclusion.ExclusionName -ForegroundColor Yellow
                        Write-Host "    $($exclusion.ExclusionDetail)" -ForegroundColor DarkGray
                    }
                    elseif ($exclusion.ExclusionType -eq "Direct User") {
                        Write-Host " | " -NoNewline -ForegroundColor Gray
                        Write-Host $exclusion.ExclusionDetail -ForegroundColor Yellow
                    }
                    elseif ($exclusion.ExclusionType -eq "Directory Role") {
                        Write-Host " | Role: " -NoNewline -ForegroundColor Gray
                        Write-Host $exclusion.ExclusionName -ForegroundColor Yellow
                    }
                    else {
                        Write-Host " | " -NoNewline -ForegroundColor Gray
                        Write-Host $exclusion.ExclusionName -ForegroundColor Yellow
                        Write-Host "    $($exclusion.ExclusionDetail)" -ForegroundColor DarkGray
                    }
                }
            }
            
            Write-Host "`n$detailSeparator" -ForegroundColor White
        }
        
        # Step 8: Export to CSV if requested
        if ($OutputPath) {
            try {
                Write-Progress -Activity "Finalizing Results" -Status "Exporting to CSV..." -PercentComplete 95
                $exportData = $allExclusions | Select-Object @(
                    'PolicyName',
                    'PolicyState',
                    'ExclusionType',
                    'ExclusionName',
                    'ExclusionDetail',
                    'PolicyId',
                    'ExclusionId'
                )
                $exportData | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8
                Write-LogMessage "Results exported to: $OutputPath" -Type "Success"
            }
            catch {
                Write-LogMessage "Failed to export results: $($_.Exception.Message)" -Type "Error"
            }
        }
        
        # Step 9: Provide summary analysis
        if ($allExclusions.Count -gt 0) {
            Write-LogMessage
            Write-LogMessage "SUMMARY BY EXCLUSION TYPE:" -Type "Info"
            $summarySeparator = "-"*30
            Write-LogMessage $summarySeparator -Type "Info"
            $summary = $allExclusions | Group-Object ExclusionType | Sort-Object Name
            foreach ($group in $summary) {
                Write-LogMessage "$($group.Name): $($group.Count) exclusion(s)" -Type "Info"
            }
            
            # Show which groups are causing the most exclusions
            Write-LogMessage
            Write-LogMessage "GROUPS CAUSING EXCLUSIONS:" -Type "Info"
            Write-LogMessage $summarySeparator -Type "Info"
            
            $groupExclusions = $allExclusions | Where-Object { $_.ExclusionType -eq "Group Membership" }
            if ($groupExclusions) {
                $uniqueGroups = $groupExclusions | Group-Object ExclusionName | Sort-Object Count -Descending
                
                foreach ($group in $uniqueGroups) {
                    $membershipType = ($group.Group | Select-Object -First 1).ExclusionDetail
                    Write-Host "  - " -NoNewline -ForegroundColor Gray
                    Write-Host $group.Name -NoNewline -ForegroundColor Yellow
                    Write-Host " (" -NoNewline -ForegroundColor Gray
                    Write-Host "$($group.Count) policies" -NoNewline -ForegroundColor Cyan
                    Write-Host ") - $membershipType" -ForegroundColor Gray
                }
                
                Write-LogMessage
                Write-LogMessage "Total unique groups causing exclusions: $($uniqueGroups.Count)" -Type "Info"
            }
            
            # Show which roles are causing exclusions
            $roleExclusions = $allExclusions | Where-Object { $_.ExclusionType -eq "Directory Role" }
            if ($roleExclusions) {
                Write-LogMessage
                Write-LogMessage "ROLES CAUSING EXCLUSIONS:" -Type "Info"
                Write-LogMessage $summarySeparator -Type "Info"
                
                $uniqueRoles = $roleExclusions | Group-Object ExclusionName | Sort-Object Count -Descending
                foreach ($role in $uniqueRoles) {
                    Write-Host "  - " -NoNewline -ForegroundColor Gray
                    Write-Host $role.Name -NoNewline -ForegroundColor Yellow
                    Write-Host " (" -NoNewline -ForegroundColor Gray
                    Write-Host "$($role.Count) policies" -NoNewline -ForegroundColor Cyan
                    Write-Host ")" -ForegroundColor Gray
                }
            }
            
            # Security recommendations
            Write-LogMessage
            Write-LogMessage "SECURITY CONSIDERATIONS:" -Type "Warning"
            Write-LogMessage $summarySeparator -Type "Info"
            Write-LogMessage "- Review exclusions regularly to ensure they're still necessary" -Type "Info"
            Write-LogMessage "- Consider using break-glass accounts instead of broad exclusions" -Type "Info"
            Write-LogMessage "- Document the business justification for each exclusion" -Type "Info"
            Write-LogMessage "- Monitor sign-in logs for excluded users more closely" -Type "Info"
        }
        
        Write-Progress -Activity "Finalizing Results" -Completed
        Write-LogMessage
        Write-LogMessage "Analysis completed successfully!" -Type "Success"
        
        # Provide helpful next steps
        Write-LogMessage
        Write-LogMessage "NEXT STEPS:" -Type "Info"
        Write-LogMessage "1. Review the exclusions to ensure they align with your security policies" -Type "Info"
        Write-LogMessage "2. Consider removing unnecessary exclusions to improve security posture" -Type "Info"
        Write-LogMessage "3. Document why each exclusion exists for compliance purposes" -Type "Info"
        if (-not $OutputPath) {
            Write-LogMessage "4. Run with -OutputPath parameter to save results for documentation" -Type "Info"
        }
    }
    catch {
        Write-LogMessage "Script execution failed: $($_.Exception.Message)" -Type "Error"
        Write-LogMessage "Stack Trace: $($_.ScriptStackTrace)" -Type "Error"
        Write-LogMessage
        Write-LogMessage "For help, please refer to:" -Type "Info"
        Write-LogMessage "- GitHub: https://github.com/yourusername/ConditionalAccessTools" -Type "Info"
        Write-LogMessage "- Documentation: https://yourblog.com/conditional-access-exclusions" -Type "Info"
        exit 1
    }
}

#endregion Main Script Logic

# Script execution starts here
Write-Host "`n"
Write-Host "╔══════════════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║     Conditional Access User Exclusion Analyzer for Microsoft 365     ║" -ForegroundColor Cyan
Write-Host "║     Identify and understand your Conditional Access exclusions       ║" -ForegroundColor Cyan
Write-Host "╚══════════════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host "`n"

# Execute main function
Main

#region Cleanup
try {
    # Optional: Disconnect from Graph (commented out to maintain session for subsequent runs)
    # Disconnect-MgGraph
    Write-LogMessage "Script execution completed. Microsoft Graph session maintained for future use." -Type "Info"
    Write-LogMessage "To disconnect manually, run: Disconnect-MgGraph" -Type "Info"
}
catch {
    $errorMsg = "Warning during cleanup: " + $_.Exception.Message
    Write-LogMessage $errorMsg -Type "Warning"
}
#endregion Cleanup

# End of script
