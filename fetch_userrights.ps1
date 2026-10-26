<#
.SYNOPSIS
USER RIGHTS: Collect local user rights assignments.

.DESCRIPTION
Author: SpecterOps (Extracted from FETCH.ps1)
Purpose:
  - Collect local user rights assignments using secedit
  - Stage output for SharpHound collection via centralized management tools
Requirements:
  - Local Administrators group privileges
  - Domain-joined machine with line of sight to domain controller
  - PowerShell 2.0 or higher
  - .NET Framework 3.5 or higher

.PARAMETER CMPivotDir
Stage results in the specified directory for pickup using CMPivot (default: disabled).

.PARAMETER Debug
Enable debugging of script execution events (default: disabled).

.PARAMETER DeleteOlderThanDays
Delete files and/or class instances older than the specified number of days (default: 7 days).

.PARAMETER LogDir
Store script execution and trace logs in the specified directory. Specify 'off' to disable. (default: $OutputDir if set, otherwise current working directory)

.PARAMETER OutputDir
Store results in the specified directory (default: disabled).

.PARAMETER Silent
Do not write to the console or any output streams (default: disabled).

.PARAMETER StdOut
Write BloodHound data to the console (default: disabled).

.PARAMETER TempDir
Specifies the path for temporary files (default: $OutputDir if set, otherwise current working directory).

.PARAMETER Trace
Enables trace logging for detailed debugging. This will significantly slow down execution (default: disabled).

.PARAMETER Verbose
Enable verbose logging of script execution events (default: disabled).

.PARAMETER Wmi
Store results in the local WMI repository (default: disabled)

.PARAMETER WmiClassPrefix
Store results in local WMI classes named with the specified prefix (default: 'BloodHound_').

.PARAMETER WmiNamespace
Store results in local WMI classes in the specified namespace (default: 'root\cimv2').

.EXAMPLE
.\fetch_userrights.ps1 -Help
# Display help text

.EXAMPLE
.\fetch_userrights.ps1 -Wmi -Verbose
# Output to class instances in the local WMI repository, show verbose messages

.EXAMPLE
.\fetch_userrights.ps1 -OutputDir C:\Windows\Temp
# Collect user rights, output to a local directory

.EXAMPLE
.\fetch_userrights.ps1 -StdOut -Silent
# Output to stdout, silence other output streams

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
        [Parameter(Mandatory=$true)][hashtable[]]$Hashtable,
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

    $instance.Privilege = $Properties.Privilege
    $instance.ObjectIdentifier = $Properties.ObjectIdentifier
    $instance.ObjectType = $Properties.ObjectType

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
        $Script:logFile = "$LogDir\UserRightsExecution_$thisComputerFQDN`_$now.log"
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
        $tracePath = "$LogDir\UserRightsTrace_$thisComputerFQDN`_$now.log"
        Write-Log "INFO" "Writing trace to $tracePath"
        Set-PSDebug -Trace 1
        Start-Transcript -Path $tracePath
    }

    # Stage for CMPivot with static file name
    if ($CMPivotDir) { 
        $outputFile = "$CMPivotDir\UserRightsResults.json" 
        Write-Log "INFO" "Writing results to $outputFile"
    } 

    # Otherwise append file name with computer name and timestamp
    elseif ($OutputDir) { 
        $outputFile = "$OutputDir\UserRightsResults_$thisComputerFQDN`_$now.json" 
        Write-Log "INFO" "Writing results to $outputFile"
    }

    # Output to stdout
    if ($StdOut) {
        Write-Log "INFO" "Writing results to stdout" 
    }

    # Output to WMI
    if ($Wmi) {
        Write-Log "INFO" "Writing results to: $WmiNamespace\$WmiClassPrefix`UserRights"
    }

    <#
    -------------------------------------------
    Collect user rights assignments
    -------------------------------------------
    #>

    Write-Host "--- Attempting to retrieve user rights assignments ---"
    $collectedUserRights = @()

    # If using WMI option, create storage class if it doesn't exist
    if ($Wmi) {
        $keyProp = @{ "InstanceID" = "uint32" }
        $props = @{ 
            "CollectionDatetime" = "datetime"
            "Privilege" = "string"
            "ObjectIdentifier" = "string"
            "ObjectType" = "string"
        }
        Add-WmiClass -WmiNamespace $WmiNamespace -WmiClassPrefix $WmiClassPrefix -CollectionType "UserRights" -KeyProperty $keyProp -Properties $props
        
        # Delete stale data before execution so that old instances aren't identified as duplicates and we get the latest
        if ($null -ne $DeleteOlderThanDays) {
            Remove-OldInstances -DeleteOlderThanDays $DeleteOlderThanDays -WmiNamespace $WmiNamespace -WmiClassName "$WmiClassPrefix`UserRights"
        }
        
        $existingRights = Get-WmiObject -Namespace $WmiNamespace -Class $WmiClassPrefix`UserRights
    }

    # Export the security configuration to a file, discarding non-terminating errors to prevent stdout pollution
    Write-Log "VERBOSE" "Exporting user rights assignments with secedit"
    $seceditPath = $env:SystemRoot + "\system32\secedit.exe"
    
    # Use a more restricted directory when running as SYSTEM (C:\Windows\Temp instead of user TEMP)
    # Generate a random filename to prevent tampering
    $seceditTempDir = $env:SystemRoot + "\Temp"
    do {
        $randomPart = [System.IO.Path]::GetRandomFileName().Split('.')[0]
        $seceditTempFile = Join-Path -Path $seceditTempDir -ChildPath "secedit-$randomPart.cfg"
    } while (Test-Path -Path $seceditTempFile)
    
    try {
        & $seceditPath /export /areas USER_RIGHTS /cfg $seceditTempFile > $null 2>&1

        # Read the contents of the exported file
        $seceditContents = Get-Content $seceditTempFile | Out-String
        Write-DebugVar seceditContents
    } finally {
        # Always remove the exported file, even if there was an error
        if (Test-Path -Path $seceditTempFile) {
            Remove-Item $seceditTempFile -Force -ErrorAction SilentlyContinue
        }
    }

    # Extract and format user rights assignments from the secedit output
    $userRightsLines = $seceditContents -split "`r`n" | Where-Object { $_ -like "SeRemoteInteractiveLogonRight*" }
    Write-DebugVar userRightsLines

    foreach ($line in $userRightsLines) {
        # Split SIDs from rights assignments
        $lineParts = $line -split "="
        $right = $lineParts[0].Trim()
        # Split SIDs into a list
        $sids = $lineParts[1].Trim() -split ","
        $sids = $sids | ForEach-Object {
            # Remove leading asterisk from each SID
            $sid = $_ -replace "^\*", ""
            # Replace built-in local group SIDs with domain computer SID
            $sid = $sid -replace "S-1-5-32", $thisComputerDomainSID
            @{
                "ObjectIdentifier" = $sid
                "ObjectType" = "LocalGroup"
            }
        }

        foreach ($sid in $sids) {
            $objectIdentifier = $sid.ObjectIdentifier
            $objectType = $sid.ObjectType

            # Create user rights assignment object
            $userRightsAssignment = @{
                Privilege = $right
                ObjectIdentifier = $objectIdentifier
                ObjectType = $objectType
            }

            if ($Wmi) {
                # Check if a user rights assignment with the same permission and user SID already exists
                $matchingRight = $existingRights | Where-Object { $_.Privilege -eq $userRightsAssignment.Privilege -and $_.ObjectIdentifier -eq $userRightsAssignment.ObjectIdentifier }
                
                if ($matchingRight) {
                    Write-Log "VERBOSE" "Skipping duplicate user rights assignment found for $($userRightsAssignment.ObjectIdentifier): $($userRightsAssignment.Privilege)"
                } else {
                    Write-Log "VERBOSE" "Found new user rights assignment for $($userRightsAssignment.ObjectIdentifier): $($userRightsAssignment.Privilege)"
                    Add-WmiClassInstance -WmiNamespace $WmiNamespace -WmiClassPrefix $WmiClassPrefix -CollectionType 'UserRights' -Properties $userRightsAssignment
                }
            }

            # Add to collected results
            $collectedUserRights += $userRightsAssignment
            Write-Host "Found user right: $right for $objectIdentifier ($objectType)"
        }
    }

    # If any user rights were found and processed, format and write the JSON output
    if ($collectedUserRights.Count -gt 0) {
        Write-Json (Format-Result $collectedUserRights "UserRights")
    } else {
        throw "No user rights assignments could be found or processed."
    }

} catch {
    throw $_
}

