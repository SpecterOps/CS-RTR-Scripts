<#
.SYNOPSIS
LOCAL GROUPS: Collect local group memberships.

.DESCRIPTION
Author: SpecterOps (Extracted from FETCH.ps1)
Collects local group memberships via ADSI and stages output for SharpHound collection.
Requires local Administrators rights, a domain-joined host with line of sight to a
domain controller, PowerShell 2.0+ and .NET Framework 3.5+.

Output/staging parameters: -StdOut, -Silent, -OutputDir, -LogDir, -TempDir, -CMPivotDir,
-Wmi, -WmiClassPrefix, -WmiNamespace, -DeleteOlderThanDays, -Debug, -Verbose, -Trace.

-TimeBudgetSeconds (default 240, 0 disables) stops enumeration once the budget is spent
and emits the results gathered so far, so a host always returns parseable JSON before an
external harness such as CrowdStrike RTR terminates the script.

NOTE: Falcon RTR refuses to execute cloud scripts larger than 32766 bytes. Keep this file
under that limit; check the size before uploading.

.EXAMPLE
.\fetch_localgroups.ps1 -StdOut -Silent

.LINK
https://github.com/BloodHoundAD/SharpHound
#>

[CmdletBinding()]
param(
    [switch]$Help,
    [ValidateScript({
        if ([string]::IsNullOrEmpty($_) -or (Test-Path $_)) {
            $true
        } else {
            throw "The specified directory does not exist: $_"
        }
    })]
    [string]$CMPivotDir = $null,    
    [ValidateRange(1,365)]
    [int]$DeleteOlderThanDays = 7,
    [ValidateScript({
        if ([string]::IsNullOrEmpty($_) -or $_ -eq "off" -or (Test-Path $_)) {
            $true
        } else {
            throw "The specified directory does not exist: $_"
        }
    })]
    [string]$LogDir = $null,
    [ValidateScript({
        if ([string]::IsNullOrEmpty($_) -or (Test-Path $_)) {
            $true
        } else {
            throw "The specified directory does not exist: $_"
        }
    })]
    [string]$OutputDir = $null,
    [switch]$Silent,
    [switch]$StdOut,
    [ValidateScript({
        if ([string]::IsNullOrEmpty($_) -or (Test-Path $_)) {
            $true
        } else {
            throw "The specified directory does not exist: $_"
        }
    })]
    [string]$TempDir = $null,
    [ValidateRange(0,3600)]
    [int]$TimeBudgetSeconds = 240,
    [switch]$Trace,
    [switch]$Wmi, 
    [string]$WmiClassPrefix = "BloodHound_",
    [ValidateScript({
        $prefix = $_.Replace('\','/')
        $parts = $prefix -split '/'
        if ($parts.Count -lt 2) {
            throw "The WMI namespace format is 'root\cimv2'."
        }
        $true
    })]
    [string]$WmiNamespace = "root\cimv2"
)

<#
-------------------------------------------
Helper functions
-------------------------------------------
#>

function Format-Result {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true)][AllowEmptyCollection()][hashtable[]]$Hashtable,
        [string]$String
    )
    # Initialize cid and aid with default empty values
    $cid = ""
    $aid = ""
    # Attempt to read CSAgent SIM values from the registry
    try {
        $regKey = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine', $env:ComputerName)
        if ($regKey) {
            $subKey = $regKey.OpenSubKey('SYSTEM\CurrentControlSet\Services\CSAgent\Sim')
            if ($subKey) {
                foreach ($i in @('AG', 'CU')) {
                    $value = $subKey.GetValue($i)
                    if ($value) {
                        $hexValue = [System.BitConverter]::ToString($value).Replace('-',$null).ToLower()
                        if ($i -eq 'AG') {
                            $aid = $hexValue
                        } elseif ($i -eq 'CU') {
                            $cid = $hexValue
                        }
                    }
                }
                $subKey.Dispose() # Dispose of the subKey
            }
            $regKey.Dispose() # Dispose of the regKey
        }
    } catch {
        Write-Warning "Could not read CSAgent SIM registry keys: $($_.Exception.Message)"
        # cid and aid will remain empty if an error occurs
    }
    # Return a hashtable containing the script name, cid, aid, and results
    [hashtable]@{
        script = $String;
        cid    = $cid;
        aid    = $aid;
        result = $Hashtable
    }
}

function Write-Json {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true)][hashtable]$Hashtable
    )
    # Check PowerShell version for JSON serialization method
    if ($PSVersionTable.PSVersion.Major -lt 3) {
        # For PowerShell versions older than 3.0, use System.Web.Extensions
        try {
            Add-Type -AssemblyName System.Web.Extensions
            $Serializer = New-Object System.Web.Script.Serialization.JavascriptSerializer
            $Serializer.Serialize($Hashtable)
        } catch {
            Write-Error "Failed to load System.Web.Extensions or serialize JSON: $($_.Exception.Message)"
            throw $_.Exception.Message
        }
    } else {
        # For PowerShell 3.0 and above, use ConvertTo-Json
        try {
            ConvertTo-Json $Hashtable -Depth 8 -Compress
        } catch {
            Write-Error "Failed to convert to JSON: $($_.Exception.Message)"
            throw $_.Exception.Message
        }
    }
}

function Write-Result {
    # Emit the collected results exactly once, including partial data. The calling collector
    # requires a JSON object with a top-level 'result' key; if the script dies without writing
    # one, the host is recorded as a total failure and everything gathered so far is discarded.
    if ($script:resultEmitted) { return }
    $script:resultEmitted = $true

    $groups = [hashtable[]]@()
    if ($null -ne $collectedGroups) {
        $groups = [hashtable[]]@($collectedGroups.ToArray())
    }

    $resultObject = Format-Result $groups "LocalGroups"

    # Diagnostics travel as extra top-level keys; the collector reads only 'result'
    $resultObject["truncated"] = [bool]$collectionTruncated
    $resultObject["groups_enumerated"] = [int]$groupsEnumerated
    $resultObject["groups_failed"] = [int]$groupsFailed
    if ($null -ne $collectionStopwatch) {
        $resultObject["elapsed_seconds"] = [math]::Round($collectionStopwatch.Elapsed.TotalSeconds, 1)
    }
    if ($null -ne $collectionErrors -and $collectionErrors.Count -gt 0) {
        # Cap the list so a pathological host cannot overflow the RTR stdout limit
        $resultObject["errors"] = @($collectionErrors.ToArray() | Select-Object -First 25)
        $resultObject["error_count"] = [int]$collectionErrors.Count
    }

    Write-Json $resultObject
}

function Add-WmiClass {
    param(
        [string]$WmiNamespace,
        [string]$WmiClassPrefix,
        [string]$CollectionType,
        [hashtable]$KeyProperty,
        [hashtable]$Properties)

    $wmiClassName = "$WmiClassPrefix$CollectionType"
    $query = "SELECT * FROM meta_class WHERE __class = '$wmiClassName'"
    $result = Get-WmiObject -Namespace $WmiNamespace -Query $query -ErrorAction Stop

    if ($null -eq $result) {
        Write-Log "VERBOSE" "$WmiNamespace\$wmiClassName does not exist, creating it now"

        foreach ($key in $KeyProperty.Keys) {
            $propertiesFormatted += "[key] $($KeyProperty[$key]) $key;`n"
        }
        
        $Properties.GetEnumerator() | ForEach-Object {
            $propertiesFormatted += "$($_.Value) $($_.Key);"
        }

        $wmiNamespaceFormatted = $WmiNamespace.Replace('\','\\')
        $mofContent = @"
#pragma namespace ("\\\\.\\$wmiNamespaceFormatted")
[ SMS_Report (TRUE),
SMS_Group_Name ("BloodHound $CollectionType"),
SMS_Class_ID ("SpecterOps|BloodHound $CollectionType|1.0")]
class $wmiClassName
{
$($propertiesFormatted.TrimEnd("`n"))
};
"@

        do {
            $randomPart = [System.IO.Path]::GetRandomFileName().Split('.')[0]
            $tempFilePath = Join-Path -Path $TempDir -ChildPath "temp-$randomPart"
        } while (Test-Path -Path $tempFilePath)

        Set-Content -Path $tempFilePath -Value $mofContent

        $mofcomp = $env:SystemRoot + "\system32\wbem\mofcomp.exe"
        $result = & $mofcomp $tempFilePath 2>&1

        if ($LASTEXITCODE -ne 0) {
            Write-Log "ERROR" "Failed to deploy WMI class: $result"
        } else {
            Write-Log "VERBOSE" "Successfully created $WmiNamespace\$wmiClassName"
        }

        Remove-Item -Path $tempFilePath -Force
    } else {
        Write-Log "VERBOSE" "$WmiNamespace\$wmiClassName already exists, skipping creation"
    }
}

function Add-WmiClassInstance {
    param(
        [Parameter(Mandatory=$true)]
        [string]$WmiNamespace,
        [Parameter(Mandatory=$true)]
        [string]$WmiClassPrefix,
        [Parameter(Mandatory=$true)]
        [string]$CollectionType,
        [Parameter(Mandatory=$true)]
        [hashtable]$Properties
    )

    $wmiClassName = "$WmiClassPrefix$CollectionType"
    $instance = ([WMICLASS]"\\.\${WmiNamespace}:${wmiClassName}").CreateInstance()

    $maxID = (Get-WmiObject -Namespace $WmiNamespace -Class $wmiClassName | Measure-Object -Property InstanceID -Maximum).Maximum
    $instance.InstanceID = $maxID + 1

    $instance.CollectionDatetime = [System.Management.ManagementDateTimeConverter]::ToDmtfDateTime((Get-Date))

    $instance.GroupName = $Properties.GroupName
    $instance.GroupSID = $Properties.GroupSID
    $instance.MemberType = $Properties.MemberType
    $instance.MemberSID = $Properties.MemberSID

    Write-DebugVar instance

    try {
        $instance.Put() | Out-Null
        Write-Log "VERBOSE" "Successfully saved collection data to ${WmiNamespace}\${wmiClassName}"
    } catch {
        Write-Log "ERROR" "Failed to save class instance. Error: $_"
    }
}

function Remove-OldInstances {
    param(
        [int]$DeleteOlderThanDays,
        [string]$WmiNamespace,
        [string]$WmiClassName
    )

    $instances = Get-WmiObject -Namespace $WmiNamespace -Class $WmiClassName -ErrorAction Stop
    $cutoffDate = (Get-Date).AddDays(-$DeleteOlderThanDays)

    $instancesToDelete = $instances | Where-Object { 
        try {
            $collectionTime = [System.Management.ManagementDateTimeConverter]::ToDateTime($_.CollectionDatetime)
            $collectionTime -lt $cutoffDate 
        } catch {
            Write-Log "WARNING" "Could not parse CollectionDatetime for instance: $($_.CollectionDatetime)"
            $false
        }
    }

    if ($instancesToDelete.Count -gt 0) {
        Write-Log "INFO" "Found $($instancesToDelete.Count) instances older than $DeleteOlderThanDays days in $WmiClassName. Deleting them."
        foreach ($instance in $instancesToDelete) {
            try {
                $instance.Delete()
                Write-Log "VERBOSE" "Deleted instance with CollectionDatetime: $($instance.CollectionDatetime)"
            }
            catch {
                Write-Log "WARNING" "Failed to delete instance with CollectionDatetime: $($instance.CollectionDatetime). Error: $_"
            }
        }
        Write-Log "VERBOSE" "Cleanup complete. Remaining instances: $((Get-WmiObject -Namespace $WmiNamespace -Class $WmiClassName).Count)"
    }
    else {
        Write-Log "INFO" "Found no instances older than $DeleteOlderThanDays days in $WmiClassName. No cleanup needed."
    }
}

function Write-DebugVar {
    param([string]$VariableName)
    Write-Log "DEBUG" "Line $($MyInvocation.ScriptLineNumber): `$${VariableName} = $(Get-Variable -Name $VariableName -ValueOnly | Out-String)"
}

function Write-Log {
    param(
        [string]$Level,
        [string]$Message
    )

    $timestamp = (Get-Date).ToUniversalTime().ToString("yyyy-MM-dd HH:mm:ss")
    $logEntry = "$timestamp UTC - $Message"
    
    if (-not $Silent) {
        switch ($Level) {
            "DEBUG" { 
                if ($Script:DebugPreference -eq 'Continue') { 
                    Write-Debug $logEntry 
                    if ($LogDir -ne 'off' -and $logFile) { $logEntry | Out-File -FilePath $logFile -Append }
                } 
            }
            "VERBOSE" { 
                if ($Script:VerbosePreference -eq 'Continue') { 
                    Write-Verbose $logEntry
                    if ($LogDir -ne 'off' -and $logFile) { $logEntry | Out-File -FilePath $logFile -Append }
                }
            }
            "INFO" {
                Write-Host "INFO: $logEntry"
                if ($LogDir -ne 'off' -and $logFile) { $logEntry | Out-File -FilePath $logFile -Append }
            }
            "WARNING" { 
                Write-Warning $logEntry 
                if ($LogDir -ne 'off' -and $logFile) { $logEntry | Out-File -FilePath $logFile -Append }
            }
        }
    }

    if ($Level -eq "OUTPUT") {
        Write-Output $Message
        if ($LogDir -ne 'off' -and $logFile) { $logEntry | Out-File -FilePath $logFile -Append }
    }

    if ($Level -eq "ERROR") {
        Write-Error $logEntry 
        if ($LogDir -ne 'off' -and $logFile) { $logEntry | Out-File -FilePath $logFile -Append }
        exit 1
    }
}

<#
-------------------------------------------
Main
-------------------------------------------
#>

# Display help text
if ($Help) {
    Get-Help $MyInvocation.MyCommand.Path
    exit
}

# Initialize JSON serializer for PowerShell < 3.0 compatibility
if($PSVersionTable.PSVersion.ToString() -lt 3.0){
    Add-Type -AssemblyName System.Web.Extensions
    $Script:Serializer = New-Object System.Web.Script.Serialization.JavascriptSerializer
}

$Script:InformationPreference = "Continue"
$Script:resultEmitted = $false

# Catch and log unexpected execution error messages
try {

    # Confirm this is running on a domain-joined machine (warn but continue for RTR compatibility)
    if (-not (Get-WmiObject Win32_ComputerSystem).PartOfDomain) {
        Write-Log "WARNING" "This system is not joined to Active Directory. Continuing anyway for RTR compatibility."
    }

    # Confirm this is running in a high integrity context (warn but continue for RTR compatibility)
    if (-not (New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Write-Log "WARNING" "This script should be executed with administrator privileges. Continuing anyway for RTR compatibility."
    }

    # Collect local system domain computer account SID via LDAP
    $thisComputerName = $env:COMPUTERNAME
    Write-DebugVar thisComputerName

    $thisComputerDomain = (Get-WmiObject Win32_ComputerSystem).Domain
    Write-DebugVar thisComputerDomain

    $thisComputerDomainAccount = New-Object System.Security.Principal.NTAccount("${thisComputerName}$")
    Write-DebugVar thisComputerDomainAccount

    try {
        $thisComputerDomainSID = $thisComputerDomainAccount.Translate([System.Security.Principal.SecurityIdentifier]).Value
        Write-DebugVar thisComputerDomainSID
    } catch {
        Write-Log "WARNING" "Could not translate the domain account to a SID. Using computer name as fallback."
        # Fallback to a placeholder if domain SID cannot be obtained
        $thisComputerDomainSID = "S-1-5-21-0000000000-0000000000-0000000000"
    }

    # Collect local system FQDN
    $thisComputerFQDN = $env:COMPUTERNAME
    $domain = (Get-WmiObject Win32_ComputerSystem).Domain
    if ($domain) {
        $thisComputerFQDN = "$env:COMPUTERNAME.$domain"
    }
    Write-DebugVar thisComputerFQDN

    # Get the local machine SID prefixed to local accounts
    $thisComputerMachineSID = ((Get-WmiObject -Class Win32_UserAccount -Filter "LocalAccount='True'" | Select-Object -First 1).SID -replace "-\d+$")
    Write-DebugVar thisComputerMachineSID

    # Initialize logging
    $now = "$((Get-Date).ToUniversalTime().ToString("yyyyMMdd-HHmmss"))-UTC"

    if ($DebugPreference -eq 'Inquire') {
        $Script:DebugPreference = "Continue"
        $Script:VerbosePreference = "Continue"
    }

    # Log to the specified directory, $OutputDir, current working directory, or off
    if ($LogDir -ne "off") {
        if ([string]::IsNullOrEmpty($LogDir)) {
            if (-not [string]::IsNullOrEmpty($OutputDir)) {
                $LogDir = $OutputDir
            } else {
                $LogDir = (Get-Location).Path
            }
        }
        $Script:logFile = "$LogDir\LocalGroupsExecution_$thisComputerFQDN`_$now.log"
        Write-Log "INFO" "Writing logs to $logFile"
    }

    # Write temp files to the specified directory, $OutputDir, or cwd
    if ([string]::IsNullOrEmpty($TempDir)) {
        if (-not [string]::IsNullOrEmpty($OutputDir)) {
            $TempDir = $OutputDir
        } else {
            $TempDir = (Get-Location).Path
        }
        Write-Log "INFO" "Writing temp files to $TempDir\"
    }

    # Trace logging - display lines as they are executed and store transcript
    if ($Trace) {
        $tracePath = "$LogDir\LocalGroupsTrace_$thisComputerFQDN`_$now.log"
        Write-Log "INFO" "Writing trace to $tracePath"
        Set-PSDebug -Trace 1
        Start-Transcript -Path $tracePath
    }

    # Stage for CMPivot with static file name
    if ($CMPivotDir) { 
        $outputFile = "$CMPivotDir\LocalGroupsResults.json" 
        Write-Log "INFO" "Writing results to $outputFile"
    } 

    # Otherwise append file name with computer name and timestamp
    elseif ($OutputDir) { 
        $outputFile = "$OutputDir\LocalGroupsResults_$thisComputerFQDN`_$now.json" 
        Write-Log "INFO" "Writing results to $outputFile"
    }

    # Output to stdout
    if ($StdOut) {
        Write-Log "INFO" "Writing results to stdout" 
    }

    # Output to WMI
    if ($Wmi) {
        Write-Log "INFO" "Writing results to: $WmiNamespace\$WmiClassPrefix`LocalGroups"
    }

    <#
    -------------------------------------------
    Collect local group memberships
    -------------------------------------------
    #>

    Write-Log "VERBOSE" "Attempting to retrieve local group memberships"
    # An ArrayList avoids the O(n^2) reallocation that `+=` incurs on hosts with large groups
    $collectedGroups = New-Object System.Collections.ArrayList

    # Track partial-collection state so the host still returns usable data on error or timeout
    $collectionErrors = New-Object System.Collections.ArrayList
    $collectionTruncated = $false
    $groupsEnumerated = 0
    $groupsFailed = 0
    $collectionStopwatch = [System.Diagnostics.Stopwatch]::StartNew()

    # If using WMI option, create storage class if it doesn't exist
    if ($Wmi) {
        $keyProp = @{ "InstanceID" = "uint32" }
        $props = @{ 
            "CollectionDatetime" = "datetime"
            "GroupName" = "string"
            "GroupSID" = "string"
            "MemberType" = "string"
            "MemberSID" = "string"
        }
        Add-WmiClass -WmiNamespace $WmiNamespace -WmiClassPrefix $WmiClassPrefix -CollectionType "LocalGroups" -KeyProperty $keyProp -Properties $props
        
        # Delete stale data before execution so that old instances aren't identified as duplicates and we get the latest
        if ($null -ne $DeleteOlderThanDays) {
            Remove-OldInstances -DeleteOlderThanDays $DeleteOlderThanDays -WmiNamespace $WmiNamespace -WmiClassName "$WmiClassPrefix`LocalGroups"
        }
        
        $existingGroupMembers = Get-WmiObject -Namespace $WmiNamespace -Class $WmiClassPrefix`LocalGroups
    }

    # Exclude domain controllers from local group collection
    $isDC = (Get-WmiObject -Class Win32_ComputerSystem).DomainRole -ge 4
    Write-DebugVar isDC

    if (-not $isDC) {

        # Resolve every local group SID up front with a single WMI query. The original script
        # issued "Get-WmiObject Win32_Group -Filter Name=..." once per group, which is the
        # dominant cost on domain-joined hosts. Constraining to LocalAccount='True' also stops
        # the provider reaching out to the domain for identically named domain groups.
        $localGroupSIDs = @{}
        try {
            foreach ($wmiGroup in @(Get-WmiObject -Class Win32_Group -Filter "LocalAccount='True'" -ErrorAction Stop)) {
                $localGroupSIDs[$wmiGroup.Name] = $wmiGroup.SID
            }
        } catch {
            [void]$collectionErrors.Add("Win32_Group enumeration failed: $($_.Exception.Message)")
            Write-Log "WARNING" "Could not bulk-enumerate local group SIDs: $($_.Exception.Message)"
        }
        Write-DebugVar localGroupSIDs

        # Create an ADSI object for the local computer
        $computer = [ADSI]("WinNT://$env:COMPUTERNAME,computer")
        Write-DebugVar computer

        # Iterate through each child object under the computer (these are local groups and users)
        $groupsObject = $computer.psbase.children | Where-Object { $_.SchemaClassName -eq 'group' }
        Write-DebugVar groupsObject

        foreach ($group in $groupsObject) {
            Write-DebugVar group

            # Stop cleanly once the budget is spent. Being terminated by the calling harness
            # returns no output at all, so partial results are strictly better than none.
            if ($TimeBudgetSeconds -gt 0 -and $collectionStopwatch.Elapsed.TotalSeconds -ge $TimeBudgetSeconds) {
                $collectionTruncated = $true
                Write-Log "WARNING" "Time budget of $TimeBudgetSeconds s reached after $groupsEnumerated group(s); returning partial results"
                break
            }

            # One unreadable group must not discard every other group on this host
            try {
                # Retrieve the name of the group
                $groupName = $group.GetType().InvokeMember("Name", 'GetProperty', $null, $group, $null)
                Write-DebugVar groupName

                # Look up the group SID from the prebuilt map, falling back to a targeted query
                $groupSID = $localGroupSIDs[$groupName]
                if ([string]::IsNullOrEmpty($groupSID)) {
                    $escapedGroupName = $groupName.Replace("'", "''")
                    $groupSID = (Get-WmiObject Win32_Group -Filter "Name='$escapedGroupName' AND LocalAccount='True'" -ErrorAction SilentlyContinue).SID
                }
                Write-DebugVar groupSID

                # Without a SID the original script threw on .Replace() and lost the whole host
                if ([string]::IsNullOrEmpty($groupSID)) {
                    $groupsFailed++
                    [void]$collectionErrors.Add("No SID resolved for local group '$groupName'")
                    Write-Log "WARNING" "Skipping local group '$groupName': no SID could be resolved"
                    continue
                }

                # Replace built-in local group SIDs with domain computer SID
                $groupObjectIdentifier = $($groupSID.Replace("S-1-5-32", $thisComputerDomainSID))
                $groupDisplayName = $groupName.ToUpper() + "@" + $thisComputerFQDN.ToUpper()

                # Iterate through each member of the current group
                $members = $group.psbase.Invoke("Members")
                Write-DebugVar members

                $groupsEnumerated++

                foreach ($member in $members) {
                    Write-DebugVar member

                    # Start with null output
                    $result = $null

                    # A member whose SID cannot be resolved (for example an orphaned account from
                    # a decommissioned domain) must not abort this group or the host
                    try {
                        # Retrieve the class of the member
                        $memberClass = $member.GetType().InvokeMember("Class", 'GetProperty', $null, $member, $null)
                        Write-DebugVar memberClass

                        # Retrieve name and SID and convert the SID to human-readable format
                        $memberName = $member.GetType().InvokeMember("Name", 'GetProperty', $null, $member, $null)
                        Write-DebugVar memberName
                        $memberSIDBytes = $member.GetType().InvokeMember("objectSid", 'GetProperty', $null, $member, $null)
                        Write-DebugVar memberSIDBytes
                        $memberSID = (New-Object System.Security.Principal.SecurityIdentifier $memberSIDBytes, 0).Value
                        Write-DebugVar memberSID

                        switch ($memberClass) {

                            "Group" {

                                # Default groups with well-known SIDs
                                if ($memberSID.Length -lt 14) {

                                    # Replace built-in local group SIDs with domain computer SID
                                    if ($memberSID -like "S-1-5-32-*") {
                                        $memberType = "LocalGroup"
                                        $result = @{
                                            "ObjectIdentifier" = $($memberSID.Replace("S-1-5-32", $thisComputerDomainSID))
                                            "ObjectType" = $memberType
                                        }

                                    # Everyone and Authenticated Users include domain users, so collect them
                                    } elseif ($memberSID -eq "S-1-1-0" -or $memberSID -eq "S-1-5-11") {
                                        $memberType = "Group"
                                        $result = @{
                                            "ObjectIdentifier" = "$($thisComputerDomain.ToUpper())-$memberSID"
                                            "ObjectType" = $memberType
                                        }

                                    # Skip other built-in SIDs (e.g., IUSR, INTERACTIVE)
                                    } else {
                                        Write-Log "VERBOSE" "Not collecting members of $memberName ($memberSID)"
                                    }

                                # This computer
                                } elseif ($memberSID -eq "$thisComputerMachineSID") {
                                    $memberType = "Computer"
                                    $result = @{
                                        "ObjectIdentifier" = $thisComputerDomainSID
                                        "ObjectType" = $memberType
                                    }

                                # Non-default local groups
                                } elseif ($memberSID -like "$thisComputerMachineSID*") {
                                    $memberType = "LocalGroup"
                                    $localGroupID = ($memberSID -split "-")[-1]
                                    $result = @{
                                        "ObjectIdentifier" = ($thisComputerDomainSID -join $localGroupID)
                                        "ObjectType" = $memberType
                                    }

                                # Domain groups
                                } else {
                                    $memberType = "Group"
                                    $result = @{
                                        "ObjectIdentifier" = $memberSID
                                        "ObjectType" = $memberType
                                    }
                                }
                            }

                            "User" {

                                # Skip local users
                                if ($memberSID -notlike "$thisComputerMachineSID*") {

                                    # Collect domain users and computers
                                    $memberType = "Base"
                                    $result = @{
                                        "ObjectIdentifier" = $memberSID
                                        "ObjectType" = $memberType
                                    }
                                } else {
                                    $memberType = "LocalUser"
                                }
                            }
                        }
                        Write-DebugVar result

                        if ($result) {
                            # Create group member object
                            $groupMember = @{
                                GroupName = $groupDisplayName
                                GroupSID = $groupObjectIdentifier
                                MemberType = $memberType
                                MemberSID = $memberSID
                                MemberName = $memberName
                                ObjectIdentifier = $result.ObjectIdentifier
                                ObjectType = $result.ObjectType
                            }

                            if ($Wmi) {
                                # Check if a group member with the same user SID already exists
                                $matchingGroupMember = $existingGroupMembers | Where-Object { $_.GroupSID -eq $groupMember.GroupSID -and $_.MemberSID -eq $groupMember.MemberSID }

                                if ($matchingGroupMember) {
                                    Write-Log "VERBOSE" "Skipping duplicate group member: $memberSID in $groupDisplayName"
                                } else {
                                    Write-Log "VERBOSE" "Found new $memberType $memberSID in $groupDisplayName ($groupObjectIdentifier)"
                                    Add-WmiClassInstance -WmiNamespace $WmiNamespace -WmiClassPrefix $WmiClassPrefix -CollectionType 'LocalGroups' -Properties $groupMember
                                }
                            }

                            # Add to collected results
                            [void]$collectedGroups.Add($groupMember)
                            Write-Log "VERBOSE" "Found member: $memberName ($memberSID) in group: $groupName"
                        } else {
                            Write-Log "VERBOSE" "Skipping $memberType $memberSID in $groupDisplayName ($groupObjectIdentifier)"
                        }
                    } catch {
                        [void]$collectionErrors.Add("Member of '$groupDisplayName' could not be read: $($_.Exception.Message)")
                        Write-Log "WARNING" "Skipping unreadable member of '$groupDisplayName': $($_.Exception.Message)"
                    }
                }
            } catch {
                $groupsFailed++
                [void]$collectionErrors.Add("Local group could not be enumerated: $($_.Exception.Message)")
                Write-Log "WARNING" "Skipping local group that could not be enumerated: $($_.Exception.Message)"
            }
        }
    } else {
        Write-Log "VERBOSE" "This system is a domain controller, skipping local group membership enumeration"
    }

    $collectionStopwatch.Stop()
    Write-Result

} catch {
    # Never exit without emitting a parseable result object. The collector treats missing JSON
    # as a total host failure, discarding everything already gathered for this host.
    Write-Log "ERROR" "Local group collection failed: $($_.Exception.Message)"
    if ($null -ne $collectionErrors) {
        [void]$collectionErrors.Add("Fatal: $($_.Exception.Message)")
    }
    if ($null -ne $collectionStopwatch) {
        $collectionStopwatch.Stop()
    }
    Write-Result
}
