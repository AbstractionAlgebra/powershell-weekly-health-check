<#
.SYNOPSIS
    Weekly Health Check Script for Windows Server 2019 Domain Controller Environment

.DESCRIPTION
    Comprehensive health monitoring script designed for air-gapped, STIG-compliant Windows environments.
    Performs proactive health checks on Windows systems, Hyper-V infrastructure, Active Directory,
    DNS, security services (Trellix ENS, Splunk), and system resources.

.PARAMETER ConfigPath
    Path to the configuration JSON file. Defaults to .\Config\settings.json

.PARAMETER ReportPath
    Path where HTML and CSV reports will be saved. Defaults to .\Reports\

.PARAMETER ComputerName
    Array of computer names to check. If not specified, queries Active Directory for all Windows computers.

.PARAMETER SkipHyperV
    Switch to skip Hyper-V related checks if not applicable to the environment.

.EXAMPLE
    .\Invoke-WeeklyHealthCheck.ps1
    Runs health check on all Windows computers in the domain using default settings.

.EXAMPLE
    .\Invoke-WeeklyHealthCheck.ps1 -ComputerName "Server01", "Server02" -Verbose
    Runs health check on specific servers with verbose output.

.EXAMPLE
    .\Invoke-WeeklyHealthCheck.ps1 -SkipHyperV -ReportPath "C:\HealthReports\"
    Runs health check without Hyper-V checks, saving reports to custom location.

.NOTES
    File Name      : Invoke-WeeklyHealthCheck.ps1
    Author         : Michael Angel
    Prerequisite   : PowerShell 5.1+, Windows Server 2019, Domain Controller
    Created        : 2025-09-17

    REQUIREMENTS:
    - Run on Windows Server 2019 Domain Controller
    - PowerShell 5.1 or higher
    - Active Directory PowerShell module
    - Hyper-V PowerShell module (if Hyper-V checks enabled)
    - Administrative privileges
    - Network connectivity to target systems

    SCHEDULED TASK SETUP:
    1. Open Task Scheduler as Administrator
    2. Create Basic Task: "Weekly Health Check"
    3. Trigger: Weekly, Select day and time
    4. Action: Start a program
    5. Program: powershell.exe
    6. Arguments: -ExecutionPolicy Bypass -File "C:\Scripts\Invoke-WeeklyHealthCheck.ps1"
    7. Run with highest privileges: Enabled

    STIG COMPLIANCE:
    - Logs to Windows Event Log (Application, Source: HealthCheck)
    - No credentials stored in script
    - Uses secure authentication methods
    - Audit trail maintained in reports

.LINK
    https://github.com/your-org/powershell-weekly-health-check
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$ConfigPath = ".\Config\settings.json",

    [Parameter(Mandatory = $false)]
    [string]$ReportPath = ".\Reports\",

    [Parameter(Mandatory = $false)]
    [string[]]$ComputerName,

    [Parameter(Mandatory = $false)]
    [switch]$SkipHyperV
)

# Script variables
$Script:StartTime = Get-Date
$Script:ScriptVersion = "1.0.0"
$Script:HealthResults = @()
$Script:TrellixInfo = @()
$Script:WindowsSecuritySummary = @()
$Script:SummaryStats = @{
    Critical = 0
    Warning = 0
    Info = 0
    Total = 0
}

# Import required modules
try {
    Import-Module ActiveDirectory -ErrorAction Stop

    # Check for Hyper-V with fallback methods for different Windows versions
    if (-not $SkipHyperV) {
        $hypervInstalled = $false

        # Try Get-WindowsFeature first (Server versions with ServerManager module)
        try {
            $hypervFeature = Get-WindowsFeature -Name Hyper-V -ErrorAction Stop
            $hypervInstalled = $hypervFeature.InstallState -eq "Installed"
        }
        catch {
            # Fallback to registry check for systems without ServerManager module
            try {
                $hypervReg = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\Packages" -ErrorAction SilentlyContinue
                $hypervInstalled = $hypervReg -and ($hypervReg | Where-Object { $_.PSChildName -like "*Hyper-V*" })
            }
            catch {
                # Final fallback - try to load Hyper-V module directly
                try {
                    Import-Module Hyper-V -ErrorAction Stop
                    $hypervInstalled = $true
                }
                catch {
                    $hypervInstalled = $false
                }
            }
        }

        if ($hypervInstalled) {
            try {
                Import-Module Hyper-V -ErrorAction Stop
            }
            catch {
                Write-Warning "Hyper-V appears to be installed but module failed to load: $($_.Exception.Message)"
            }
        }
    }
}
catch {
    Write-Error "Failed to import required modules: $($_.Exception.Message)"
    exit 1
}

# Load configuration
function Get-Configuration {
    param([string]$Path)

    if (-not (Test-Path $Path)) {
        Write-Warning "Configuration file not found at $Path. Using default settings."
        return @{
            DiskSpaceWarningThreshold = 20
            DiskSpaceCriticalThreshold = 10
            UptimeWarningDays = 35
            UptimeCriticalDays = 45
            CertificateWarningDays = 90
            CertificateCriticalDays = 30
            TrellixServices = @("McAfeeFramework", "mfemms", "mfevtp")
            SplunkServices = @("SplunkForwarder")
            ConnectivityTimeoutSeconds = 10
            ConnectivityRetryCount = 2
            WinRMTimeoutSeconds = 15
            WMITimeoutSeconds = 30
        }
    }

    try {
        $config = Get-Content $Path -Raw | ConvertFrom-Json
        return $config
    }
    catch {
        Write-Warning "Failed to load configuration: $($_.Exception.Message). Using defaults."
        return Get-Configuration -Path "nonexistent"
    }
}

# Logging function
function Write-HealthLog {
    param(
        [string]$Message,
        [ValidateSet("Information", "Warning", "Error")]
        [string]$Level = "Information",
        [string]$Source = "HealthCheck"
    )

    $EventID = switch ($Level) {
        "Information" { 1001 }
        "Warning" { 2001 }
        "Error" { 3001 }
    }

    try {
        Write-EventLog -LogName Application -Source $Source -EventId $EventID -EntryType $Level -Message $Message
    }
    catch {
        # Fallback to Write-Host if EventLog fails
        Write-Host "[$Level] $Message" -ForegroundColor $(
            switch ($Level) {
                "Information" { "Green" }
                "Warning" { "Yellow" }
                "Error" { "Red" }
            }
        )
    }

    if ($VerbosePreference -ne 'SilentlyContinue') {
        Write-Host "[$Level] $Message"
    }
}

# Test basic connectivity with retries and timeout
function Test-ComputerConnectivity {
    param(
        [string]$ComputerName,
        [int]$TimeoutSeconds = 10,
        [int]$RetryCount = 2
    )

    for ($i = 0; $i -le $RetryCount; $i++) {
        try {
            # Try ping first for basic connectivity
            $pingResult = Test-Connection -ComputerName $ComputerName -Count 1 -Quiet -ErrorAction Stop
            if ($pingResult) {
                return $true
            }
        }
        catch {
            # Continue to retry
        }

        if ($i -lt $RetryCount) {
            Start-Sleep -Seconds 2
        }
    }
    return $false
}

# Test WinRM connectivity with retries and timeout
function Test-WinRMConnectivity {
    param(
        [string]$ComputerName,
        [int]$TimeoutSeconds = 15,
        [int]$RetryCount = 2
    )

    # First check basic connectivity
    if (-not (Test-ComputerConnectivity -ComputerName $ComputerName -TimeoutSeconds 5 -RetryCount 1)) {
        return $false
    }

    for ($attempt = 0; $attempt -le $RetryCount; $attempt++) {
        try {
            # Test WinRM port connectivity first
            $portTestResult = $false

            # Try Test-NetConnection first (available in PowerShell 4.0+)
            try {
                $portTestResult = Test-NetConnection -ComputerName $ComputerName -Port 5985 -InformationLevel Quiet -WarningAction SilentlyContinue -ErrorAction Stop
            }
            catch {
                # Fallback to alternative method for older PowerShell versions
                try {
                    $tcpClient = New-Object System.Net.Sockets.TcpClient
                    $result = $tcpClient.BeginConnect($ComputerName, 5985, $null, $null)
                    $wait = $result.AsyncWaitHandle.WaitOne(3000, $false)
                    $tcpClient.Close()
                    $portTestResult = $wait
                }
                catch {
                    $portTestResult = $false
                }
            }

            if (-not $portTestResult) {
                if ($attempt -lt $RetryCount) {
                    Start-Sleep -Seconds 2
                    continue
                }
                return $false
            }

            # Test actual WinRM functionality with timeout
            $job = Start-Job -ScriptBlock {
                param($comp)
                Invoke-Command -ComputerName $comp -ScriptBlock { $env:COMPUTERNAME } -ErrorAction Stop
            } -ArgumentList $ComputerName

            $completed = Wait-Job -Job $job -Timeout $TimeoutSeconds
            if ($completed) {
                $result = Receive-Job -Job $job -ErrorAction SilentlyContinue
                Remove-Job -Job $job -Force
                if ($result) {
                    return $true
                }
            } else {
                Remove-Job -Job $job -Force
            }
        }
        catch {
            # Continue to retry
        }

        if ($attempt -lt $RetryCount) {
            Start-Sleep -Seconds 2
        }
    }
    return $false
}

# Get remote service status with fallback methods and timeout
function Get-RemoteServiceStatus {
    param(
        [string]$ComputerName,
        [string]$ServiceName,
        [int]$TimeoutSeconds = 30
    )

    # Try WinRM first
    try {
        if (Test-WinRMConnectivity -ComputerName $ComputerName -TimeoutSeconds 10 -RetryCount 1) {
            $job = Start-Job -ScriptBlock {
                param($comp, $svc)
                Get-Service -Name $svc -ComputerName $comp -ErrorAction Stop
            } -ArgumentList $ComputerName, $ServiceName

            $completed = Wait-Job -Job $job -Timeout $TimeoutSeconds
            if ($completed) {
                $result = Receive-Job -Job $job -ErrorAction SilentlyContinue
                Remove-Job -Job $job -Force
                return $result
            } else {
                Remove-Job -Job $job -Force
                throw "WinRM service check timed out"
            }
        }
    }
    catch {
        # WinRM failed, try WMI
    }

    # Fallback to WMI with timeout
    try {
        $job = Start-Job -ScriptBlock {
            param($comp, $svc)
            $wmiService = Get-WmiObject -Class Win32_Service -ComputerName $comp -Filter "Name='$svc'" -ErrorAction Stop
            if ($wmiService) {
                return [PSCustomObject]@{
                    Name = $wmiService.Name
                    Status = switch ($wmiService.State) {
                        "Running" { "Running" }
                        "Stopped" { "Stopped" }
                        "Paused" { "Paused" }
                        default { $wmiService.State }
                    }
                    StartType = $wmiService.StartMode
                }
            }
            return $null
        } -ArgumentList $ComputerName, $ServiceName

        $completed = Wait-Job -Job $job -Timeout $TimeoutSeconds
        if ($completed) {
            $result = Receive-Job -Job $job -ErrorAction SilentlyContinue
            Remove-Job -Job $job -Force
            return $result
        } else {
            Remove-Job -Job $job -Force
            throw "WMI service check timed out after $TimeoutSeconds seconds"
        }
    }
    catch {
        throw "Could not check service '$ServiceName' on '$ComputerName': $($_.Exception.Message)"
    }
}

# Execute remote command with timeout and fallback
function Invoke-RemoteCommand {
    param(
        [string]$ComputerName,
        [scriptblock]$ScriptBlock,
        [string]$FallbackMessage = "Remote command execution not available",
        [int]$TimeoutSeconds = 60
    )

    # Try WinRM first
    try {
        if (Test-WinRMConnectivity -ComputerName $ComputerName -TimeoutSeconds 10 -RetryCount 1) {
            $job = Start-Job -ScriptBlock {
                param($comp, $script)
                Invoke-Command -ComputerName $comp -ScriptBlock $script -ErrorAction Stop
            } -ArgumentList $ComputerName, $ScriptBlock

            $completed = Wait-Job -Job $job -Timeout $TimeoutSeconds
            if ($completed) {
                $result = Receive-Job -Job $job -ErrorAction SilentlyContinue
                Remove-Job -Job $job -Force
                return $result
            } else {
                Remove-Job -Job $job -Force
                throw "Remote command timed out after $TimeoutSeconds seconds"
            }
        }
    }
    catch {
        if ($_.Exception.Message -like "*timed out*") {
            throw $_.Exception.Message
        }
        # WinRM failed
    }

    # For some operations, we can't provide a meaningful fallback
    throw $FallbackMessage
}

# Add result to collection
function Add-HealthResult {
    param(
        [string]$ComputerName,
        [string]$Component,
        [string]$Check,
        [ValidateSet("Critical", "Warning", "Info", "Pass")]
        [string]$Status,
        [string]$Message,
        [object]$Details = $null,
        [string]$OSVersion = ""
    )

    $result = [PSCustomObject]@{
        Timestamp = Get-Date
        ComputerName = $ComputerName
        OSVersion = $OSVersion
        Component = $Component
        Check = $Check
        Status = $Status
        Message = $Message
        Details = $Details
    }

    $Script:HealthResults += $result

    # Update summary stats
    if ($Status -in @("Critical", "Warning", "Info")) {
        $Script:SummaryStats[$Status]++
    }
    $Script:SummaryStats.Total++

    Write-HealthLog -Message "$ComputerName - $Component - $Check - $Status - $Message" -Level $(
        switch ($Status) {
            "Critical" { "Error" }
            "Warning" { "Warning" }
            default { "Information" }
        }
    )
}

# Test Active Directory Health
function Test-ADHealth {
    param([string[]]$DomainControllers)

    Write-Host "Checking Active Directory Health..." -ForegroundColor Cyan

    foreach ($DC in $DomainControllers) {
        try {
            # Test DC connectivity
            if (-not (Test-NetConnection -ComputerName $DC -Port 389 -InformationLevel Quiet)) {
                Add-HealthResult -ComputerName $DC -Component "ActiveDirectory" -Check "Connectivity" -Status "Critical" -Message "Cannot connect to LDAP port 389"
                continue
            }

            # Check AD services
            $services = @("ADWS", "KDC", "Netlogon", "DNS")
            foreach ($service in $services) {
                try {
                    $svc = Get-RemoteServiceStatus -ComputerName $DC -ServiceName $service
                    if ($svc -and $svc.Status -ne "Running") {
                        Add-HealthResult -ComputerName $DC -Component "ActiveDirectory" -Check "Service_$service" -Status "Critical" -Message "$service service is $($svc.Status)"
                    } elseif ($svc) {
                        Add-HealthResult -ComputerName $DC -Component "ActiveDirectory" -Check "Service_$service" -Status "Pass" -Message "$service service is running"
                    } else {
                        Add-HealthResult -ComputerName $DC -Component "ActiveDirectory" -Check "Service_$service" -Status "Warning" -Message "$service service not found"
                    }
                }
                catch {
                    Add-HealthResult -ComputerName $DC -Component "ActiveDirectory" -Check "Service_$service" -Status "Critical" -Message "Failed to check $service service: $($_.Exception.Message)"
                }
            }

            # Check replication
            try {
                $replStatus = Get-ADReplicationFailure -Target $DC -ErrorAction Stop
                if ($replStatus) {
                    Add-HealthResult -ComputerName $DC -Component "ActiveDirectory" -Check "Replication" -Status "Critical" -Message "Replication failures detected" -Details $replStatus
                } else {
                    Add-HealthResult -ComputerName $DC -Component "ActiveDirectory" -Check "Replication" -Status "Pass" -Message "No replication failures"
                }
            }
            catch {
                Add-HealthResult -ComputerName $DC -Component "ActiveDirectory" -Check "Replication" -Status "Warning" -Message "Could not check replication status: $($_.Exception.Message)"
            }

            # Check SYSVOL
            $sysvolPath = "\\$DC\SYSVOL"
            if (Test-Path $sysvolPath) {
                Add-HealthResult -ComputerName $DC -Component "ActiveDirectory" -Check "SYSVOL" -Status "Pass" -Message "SYSVOL accessible"
            } else {
                Add-HealthResult -ComputerName $DC -Component "ActiveDirectory" -Check "SYSVOL" -Status "Critical" -Message "SYSVOL not accessible"
            }

        }
        catch {
            Add-HealthResult -ComputerName $DC -Component "ActiveDirectory" -Check "General" -Status "Critical" -Message "Failed to check AD health: $($_.Exception.Message)"
        }
    }
}

# Test DNS Health
function Test-DNSHealth {
    param([string[]]$DNSServers)

    Write-Host "Checking DNS Health..." -ForegroundColor Cyan

    foreach ($DNSServer in $DNSServers) {
        try {
            # Check DNS service
            $dnsService = Get-RemoteServiceStatus -ComputerName $DNSServer -ServiceName "DNS"
            if ($dnsService -and $dnsService.Status -ne "Running") {
                Add-HealthResult -ComputerName $DNSServer -Component "DNS" -Check "Service" -Status "Critical" -Message "DNS service is $($dnsService.Status)"
            } elseif ($dnsService) {
                Add-HealthResult -ComputerName $DNSServer -Component "DNS" -Check "Service" -Status "Pass" -Message "DNS service is running"
            } else {
                Add-HealthResult -ComputerName $DNSServer -Component "DNS" -Check "Service" -Status "Critical" -Message "DNS service not found"
            }

            # Test DNS resolution
            try {
                $domain = (Get-ADDomain).DNSRoot
                $resolution = Resolve-DnsName -Name $domain -Server $DNSServer -ErrorAction Stop
                Add-HealthResult -ComputerName $DNSServer -Component "DNS" -Check "Resolution" -Status "Pass" -Message "DNS resolution working for $domain"
            }
            catch {
                Add-HealthResult -ComputerName $DNSServer -Component "DNS" -Check "Resolution" -Status "Critical" -Message "DNS resolution failed: $($_.Exception.Message)"
            }

            # Check DNS zones (requires WinRM)
            try {
                if (Test-WinRMConnectivity -ComputerName $DNSServer) {
                    $zones = Get-DnsServerZone -ComputerName $DNSServer -ErrorAction Stop
                    $errorZones = $zones | Where-Object { $_.ZoneType -eq "Primary" -and $_.IsDsIntegrated -eq $false }
                    if ($errorZones) {
                        Add-HealthResult -ComputerName $DNSServer -Component "DNS" -Check "Zones" -Status "Warning" -Message "Non-AD integrated zones detected" -Details $errorZones
                    } else {
                        Add-HealthResult -ComputerName $DNSServer -Component "DNS" -Check "Zones" -Status "Pass" -Message "All primary zones are AD integrated"
                    }
                } else {
                    Add-HealthResult -ComputerName $DNSServer -Component "DNS" -Check "Zones" -Status "Info" -Message "DNS zone check skipped - WinRM not available"
                }
            }
            catch {
                Add-HealthResult -ComputerName $DNSServer -Component "DNS" -Check "Zones" -Status "Warning" -Message "Could not check DNS zones: $($_.Exception.Message)"
            }

        }
        catch {
            Add-HealthResult -ComputerName $DNSServer -Component "DNS" -Check "General" -Status "Critical" -Message "Failed to check DNS health: $($_.Exception.Message)"
        }
    }
}

# Test System Health
function Test-SystemHealth {
    param(
        [string[]]$ComputerNames,
        [hashtable]$Config
    )

    Write-Host "Checking System Health..." -ForegroundColor Cyan

    foreach ($Computer in $ComputerNames) {
        Write-Verbose "Testing connectivity to $Computer..."

        # Test basic connectivity with retries - early exit if unreachable
        if (-not (Test-ComputerConnectivity -ComputerName $Computer -TimeoutSeconds $Config.ConnectivityTimeoutSeconds -RetryCount $Config.ConnectivityRetryCount)) {
            Add-HealthResult -ComputerName $Computer -Component "System" -Check "Connectivity" -Status "Critical" -Message "Computer is not reachable after $($Config.ConnectivityRetryCount) retries"

            # Add placeholder entries for other system checks to show they were skipped
            Add-HealthResult -ComputerName $Computer -Component "System" -Check "DiskSpace" -Status "Info" -Message "Skipped - Computer unreachable" -OSVersion "Unknown"
            Add-HealthResult -ComputerName $Computer -Component "System" -Check "Uptime" -Status "Info" -Message "Skipped - Computer unreachable" -OSVersion "Unknown"
            Add-HealthResult -ComputerName $Computer -Component "System" -Check "Memory" -Status "Info" -Message "Skipped - Computer unreachable" -OSVersion "Unknown"
            continue
        }

        Add-HealthResult -ComputerName $Computer -Component "System" -Check "Connectivity" -Status "Pass" -Message "Computer is reachable"

        try {

            # Get OS version for this computer
            $osVersion = ""
            try {
                $os = Get-WmiObject -Class Win32_OperatingSystem -ComputerName $Computer -ErrorAction Stop
                $osVersion = $os.Caption.Trim()
            }
            catch {
                $osVersion = "Unknown"
            }

            # Check disk space
            try {
                $disks = Get-WmiObject -Class Win32_LogicalDisk -ComputerName $Computer -Filter "DriveType=3" -ErrorAction Stop
                foreach ($disk in $disks) {
                    $freePercent = [math]::Round(($disk.FreeSpace / $disk.Size) * 100, 2)

                    if ($freePercent -lt $Config.DiskSpaceCriticalThreshold) {
                        Add-HealthResult -ComputerName $Computer -Component "System" -Check "DiskSpace_$($disk.DeviceID)" -Status "Critical" -Message "Disk $($disk.DeviceID) has only $freePercent% free space" -OSVersion $osVersion
                    }
                    elseif ($freePercent -lt $Config.DiskSpaceWarningThreshold) {
                        Add-HealthResult -ComputerName $Computer -Component "System" -Check "DiskSpace_$($disk.DeviceID)" -Status "Warning" -Message "Disk $($disk.DeviceID) has $freePercent% free space" -OSVersion $osVersion
                    }
                    else {
                        Add-HealthResult -ComputerName $Computer -Component "System" -Check "DiskSpace_$($disk.DeviceID)" -Status "Pass" -Message "Disk $($disk.DeviceID) has $freePercent% free space" -OSVersion $osVersion
                    }
                }
            }
            catch {
                Add-HealthResult -ComputerName $Computer -Component "System" -Check "DiskSpace" -Status "Warning" -Message "Could not check disk space: $($_.Exception.Message)" -OSVersion $osVersion
            }

            # Check uptime
            try {
                $os = Get-WmiObject -Class Win32_OperatingSystem -ComputerName $Computer -ErrorAction Stop
                $uptime = (Get-Date) - $os.ConvertToDateTime($os.LastBootUpTime)

                if ($uptime.Days -gt $Config.UptimeCriticalDays) {
                    Add-HealthResult -ComputerName $Computer -Component "System" -Check "Uptime" -Status "Critical" -Message "System has not rebooted in $($uptime.Days) days" -OSVersion $osVersion
                }
                elseif ($uptime.Days -gt $Config.UptimeWarningDays) {
                    Add-HealthResult -ComputerName $Computer -Component "System" -Check "Uptime" -Status "Warning" -Message "System has not rebooted in $($uptime.Days) days" -OSVersion $osVersion
                }
                else {
                    Add-HealthResult -ComputerName $Computer -Component "System" -Check "Uptime" -Status "Pass" -Message "System uptime: $($uptime.Days) days" -OSVersion $osVersion
                }
            }
            catch {
                Add-HealthResult -ComputerName $Computer -Component "System" -Check "Uptime" -Status "Warning" -Message "Could not check uptime: $($_.Exception.Message)" -OSVersion $osVersion
            }

            # Check memory usage
            try {
                $memory = Get-WmiObject -Class Win32_OperatingSystem -ComputerName $Computer -ErrorAction Stop
                $memoryUsage = [math]::Round((($memory.TotalVisibleMemorySize - $memory.FreePhysicalMemory) / $memory.TotalVisibleMemorySize) * 100, 2)

                if ($memoryUsage -gt 90) {
                    Add-HealthResult -ComputerName $Computer -Component "System" -Check "Memory" -Status "Critical" -Message "Memory usage is $memoryUsage%" -OSVersion $osVersion
                }
                elseif ($memoryUsage -gt 80) {
                    Add-HealthResult -ComputerName $Computer -Component "System" -Check "Memory" -Status "Warning" -Message "Memory usage is $memoryUsage%" -OSVersion $osVersion
                }
                else {
                    Add-HealthResult -ComputerName $Computer -Component "System" -Check "Memory" -Status "Pass" -Message "Memory usage is $memoryUsage%" -OSVersion $osVersion
                }
            }
            catch {
                Add-HealthResult -ComputerName $Computer -Component "System" -Check "Memory" -Status "Warning" -Message "Could not check memory usage: $($_.Exception.Message)" -OSVersion $osVersion
            }

        }
        catch {
            Add-HealthResult -ComputerName $Computer -Component "System" -Check "General" -Status "Critical" -Message "Failed to check system health: $($_.Exception.Message)" -OSVersion "Unknown"
        }
    }
}

# Test Storage Health
function Test-StorageHealth {
    param(
        [string[]]$ComputerNames,
        [hashtable]$Config
    )

    Write-Host "Checking Storage Health..." -ForegroundColor Cyan

    foreach ($Computer in $ComputerNames) {
        # Test basic connectivity first - skip if unreachable
        if (-not (Test-ComputerConnectivity -ComputerName $Computer -TimeoutSeconds 5 -RetryCount 1)) {
            Add-HealthResult -ComputerName $Computer -Component "Storage" -Check "Connectivity" -Status "Critical" -Message "Computer unreachable - storage checks skipped"
            continue
        }

        try {
            # Check for disk errors in event log (requires WinRM)
            if (Test-WinRMConnectivity -ComputerName $Computer -TimeoutSeconds $Config.WinRMTimeoutSeconds -RetryCount 1) {
                $diskErrors = Get-WinEvent -ComputerName $Computer -FilterHashtable @{LogName='System'; ID=7,11,15,153; StartTime=(Get-Date).AddDays(-21)} -ErrorAction SilentlyContinue

                if ($diskErrors) {
                    $criticalErrors = $diskErrors | Where-Object { $_.Id -in @(7, 11) }
                    $warningErrors = $diskErrors | Where-Object { $_.Id -in @(15, 153) }

                    if ($criticalErrors) {
                        Add-HealthResult -ComputerName $Computer -Component "Storage" -Check "DiskErrors" -Status "Critical" -Message "Critical disk errors detected in last 21 days" -Details $criticalErrors
                    }
                    elseif ($warningErrors) {
                        Add-HealthResult -ComputerName $Computer -Component "Storage" -Check "DiskErrors" -Status "Warning" -Message "Disk warnings detected in last 21 days" -Details $warningErrors
                    } else {
                        Add-HealthResult -ComputerName $Computer -Component "Storage" -Check "DiskErrors" -Status "Pass" -Message "No disk errors in last 21 days"
                    }
                }
                else {
                    Add-HealthResult -ComputerName $Computer -Component "Storage" -Check "DiskErrors" -Status "Pass" -Message "No disk errors in last 21 days"
                }
            } else {
                Add-HealthResult -ComputerName $Computer -Component "Storage" -Check "DiskErrors" -Status "Info" -Message "Event log check skipped - WinRM not available"
            }

            # Check disk performance
            try {
                $diskPerf = Get-WmiObject -Class Win32_PerfRawData_PerfDisk_PhysicalDisk -ComputerName $Computer -ErrorAction Stop | Where-Object { $_.Name -ne "_Total" }
                foreach ($disk in $diskPerf) {
                    $queueLength = $disk.CurrentDiskQueueLength
                    if ($queueLength -gt 10) {
                        Add-HealthResult -ComputerName $Computer -Component "Storage" -Check "Performance_$($disk.Name)" -Status "Warning" -Message "High disk queue length: $queueLength"
                    }
                    else {
                        Add-HealthResult -ComputerName $Computer -Component "Storage" -Check "Performance_$($disk.Name)" -Status "Pass" -Message "Disk queue length normal: $queueLength"
                    }
                }
            }
            catch {
                Add-HealthResult -ComputerName $Computer -Component "Storage" -Check "Performance" -Status "Warning" -Message "Could not check disk performance: $($_.Exception.Message)"
            }

        }
        catch {
            Add-HealthResult -ComputerName $Computer -Component "Storage" -Check "General" -Status "Warning" -Message "Could not check storage health: $($_.Exception.Message)"
        }
    }
}

# Test Security Services
function Test-SecurityServices {
    param(
        [string[]]$ComputerNames,
        [hashtable]$Config
    )

    Write-Host "Checking Security Services..." -ForegroundColor Cyan

    foreach ($Computer in $ComputerNames) {
        # Test basic connectivity first - skip if unreachable
        if (-not (Test-ComputerConnectivity -ComputerName $Computer -TimeoutSeconds 5 -RetryCount 1)) {
            Add-HealthResult -ComputerName $Computer -Component "Security" -Check "Connectivity" -Status "Critical" -Message "Computer unreachable - security checks skipped"
            continue
        }

        try {
            # Check Trellix ENS services
            foreach ($service in $Config.TrellixServices) {
                try {
                    $svc = Get-RemoteServiceStatus -ComputerName $Computer -ServiceName $service
                    if ($svc -and $svc.Status -ne "Running") {
                        Add-HealthResult -ComputerName $Computer -Component "Security" -Check "Trellix_$service" -Status "Critical" -Message "Trellix service $service is $($svc.Status)" -OSVersion "Unknown"
                    } elseif ($svc) {
                        Add-HealthResult -ComputerName $Computer -Component "Security" -Check "Trellix_$service" -Status "Pass" -Message "Trellix service $service is running" -OSVersion "Unknown"
                    } else {
                        Add-HealthResult -ComputerName $Computer -Component "Security" -Check "Trellix_$service" -Status "Warning" -Message "Trellix service $service not found" -OSVersion "Unknown"
                    }
                }
                catch {
                    Add-HealthResult -ComputerName $Computer -Component "Security" -Check "Trellix_$service" -Status "Warning" -Message "Trellix service $service not found or inaccessible: $($_.Exception.Message)" -OSVersion "Unknown"
                }
            }

            # Check Trellix DAT version and collect version info
            try {
                $trellixInfo = Invoke-RemoteCommand -ComputerName $Computer -ScriptBlock {
                    # Get DAT version
                    $datReg = Get-ItemProperty -Path "HKLM:\SOFTWARE\McAfee\AVEngine" -Name "AVDatVersion" -ErrorAction SilentlyContinue

                    # Get product version
                    $productReg = Get-ItemProperty -Path "HKLM:\SOFTWARE\McAfee\EPSCore" -Name "szProductVer" -ErrorAction SilentlyContinue
                    if (-not $productReg) {
                        $productReg = Get-ItemProperty -Path "HKLM:\SOFTWARE\McAfee\DesktopProtection" -Name "szProductVer" -ErrorAction SilentlyContinue
                    }

                    # Get engine version
                    $engineReg = Get-ItemProperty -Path "HKLM:\SOFTWARE\McAfee\AVEngine" -Name "EngineVersionMajor", "EngineVersionMinor" -ErrorAction SilentlyContinue

                    return @{
                        DATVersion = $datReg.AVDatVersion
                        ProductVersion = $productReg.szProductVer
                        EngineVersionMajor = $engineReg.EngineVersionMajor
                        EngineVersionMinor = $engineReg.EngineVersionMinor
                    }
                } -FallbackMessage "Could not retrieve Trellix information - WinRM not available"

                # Get OS version for this computer
                $osVersion = ""
                try {
                    $os = Get-WmiObject -Class Win32_OperatingSystem -ComputerName $Computer -ErrorAction Stop
                    $osVersion = $os.Caption.Trim()
                }
                catch {
                    $osVersion = "Unknown"
                }

                # Store Trellix info for separate table
                $Script:TrellixInfo += [PSCustomObject]@{
                    ComputerName = $Computer
                    OSVersion = $osVersion
                    ProductVersion = $trellixInfo.ProductVersion -replace $null, "Unknown"
                    EngineVersion = if ($trellixInfo.EngineVersionMajor -and $trellixInfo.EngineVersionMinor) {
                        "$($trellixInfo.EngineVersionMajor).$($trellixInfo.EngineVersionMinor)"
                    } else {
                        "Unknown"
                    }
                    DATVersion = $trellixInfo.DATVersion -replace $null, "Unknown"
                    DATDate = if ($trellixInfo.DATVersion) {
                        try {
                            [DateTime]::ParseExact($trellixInfo.DATVersion.Substring(0,8), "yyyyMMdd", $null).ToString('yyyy-MM-dd')
                        } catch {
                            "Unknown"
                        }
                    } else {
                        "Unknown"
                    }
                }

                if ($trellixInfo.DATVersion) {
                    $datDate = [DateTime]::ParseExact($trellixInfo.DATVersion.Substring(0,8), "yyyyMMdd", $null)
                    $daysSinceUpdate = (Get-Date) - $datDate

                    if ($daysSinceUpdate.Days -gt 7) {
                        Add-HealthResult -ComputerName $Computer -Component "Security" -Check "Trellix_DAT" -Status "Critical" -Message "Trellix DAT files are $($daysSinceUpdate.Days) days old" -OSVersion $osVersion
                    }
                    elseif ($daysSinceUpdate.Days -gt 3) {
                        Add-HealthResult -ComputerName $Computer -Component "Security" -Check "Trellix_DAT" -Status "Warning" -Message "Trellix DAT files are $($daysSinceUpdate.Days) days old" -OSVersion $osVersion
                    }
                    else {
                        Add-HealthResult -ComputerName $Computer -Component "Security" -Check "Trellix_DAT" -Status "Pass" -Message "Trellix DAT files are current ($($datDate.ToString('yyyy-MM-dd')))" -OSVersion $osVersion
                    }
                } else {
                    Add-HealthResult -ComputerName $Computer -Component "Security" -Check "Trellix_DAT" -Status "Warning" -Message "Could not determine Trellix DAT version" -OSVersion $osVersion
                }
            }
            catch {
                Add-HealthResult -ComputerName $Computer -Component "Security" -Check "Trellix_DAT" -Status "Warning" -Message "Could not check Trellix DAT version: $($_.Exception.Message)" -OSVersion "Unknown"

                # Add minimal Trellix info entry for failed checks
                $Script:TrellixInfo += [PSCustomObject]@{
                    ComputerName = $Computer
                    OSVersion = "Unknown"
                    ProductVersion = "Check Failed"
                    EngineVersion = "Check Failed"
                    DATVersion = "Check Failed"
                    DATDate = "Check Failed"
                }
            }

            # Check Splunk services
            foreach ($service in $Config.SplunkServices) {
                try {
                    $svc = Get-RemoteServiceStatus -ComputerName $Computer -ServiceName $service
                    if ($svc -and $svc.Status -ne "Running") {
                        Add-HealthResult -ComputerName $Computer -Component "Security" -Check "Splunk_$service" -Status "Critical" -Message "Splunk service $service is $($svc.Status)"
                    } elseif ($svc) {
                        Add-HealthResult -ComputerName $Computer -Component "Security" -Check "Splunk_$service" -Status "Pass" -Message "Splunk service $service is running"
                    } else {
                        Add-HealthResult -ComputerName $Computer -Component "Security" -Check "Splunk_$service" -Status "Warning" -Message "Splunk service $service not found"
                    }
                }
                catch {
                    Add-HealthResult -ComputerName $Computer -Component "Security" -Check "Splunk_$service" -Status "Warning" -Message "Splunk service $service not found or inaccessible: $($_.Exception.Message)"
                }
            }

            # Check Windows Updates
            try {
                $lastUpdate = Get-HotFix -ComputerName $Computer | Sort-Object InstalledOn -Descending | Select-Object -First 1
                if ($lastUpdate.InstalledOn) {
                    $daysSinceUpdate = (Get-Date) - $lastUpdate.InstalledOn

                    if ($daysSinceUpdate.Days -gt 60) {
                        Add-HealthResult -ComputerName $Computer -Component "Security" -Check "WindowsUpdates" -Status "Critical" -Message "Last update installed $($daysSinceUpdate.Days) days ago"
                    }
                    elseif ($daysSinceUpdate.Days -gt 30) {
                        Add-HealthResult -ComputerName $Computer -Component "Security" -Check "WindowsUpdates" -Status "Warning" -Message "Last update installed $($daysSinceUpdate.Days) days ago"
                    }
                    else {
                        Add-HealthResult -ComputerName $Computer -Component "Security" -Check "WindowsUpdates" -Status "Pass" -Message "Updates current (last: $($lastUpdate.InstalledOn.ToString('yyyy-MM-dd')))"
                    }
                } else {
                    Add-HealthResult -ComputerName $Computer -Component "Security" -Check "WindowsUpdates" -Status "Warning" -Message "Could not determine last update date"
                }
            }
            catch {
                Add-HealthResult -ComputerName $Computer -Component "Security" -Check "WindowsUpdates" -Status "Warning" -Message "Could not check Windows Update status: $($_.Exception.Message)"
            }

            # Check certificates
            try {
                $expiredCerts = Invoke-RemoteCommand -ComputerName $Computer -ScriptBlock {
                    Get-ChildItem -Path Cert:\LocalMachine\My | Where-Object {
                        $_.NotAfter -lt (Get-Date).AddDays(90) -and $_.NotAfter -gt (Get-Date)
                    }
                } -FallbackMessage "Could not check certificates - WinRM not available"

                if ($expiredCerts) {
                    $criticalCerts = $expiredCerts | Where-Object { $_.NotAfter -lt (Get-Date).AddDays(30) }
                    if ($criticalCerts) {
                        Add-HealthResult -ComputerName $Computer -Component "Security" -Check "Certificates" -Status "Critical" -Message "Certificates expiring within 30 days" -Details $criticalCerts
                    } else {
                        Add-HealthResult -ComputerName $Computer -Component "Security" -Check "Certificates" -Status "Warning" -Message "Certificates expiring within 90 days" -Details $expiredCerts
                    }
                } else {
                    Add-HealthResult -ComputerName $Computer -Component "Security" -Check "Certificates" -Status "Pass" -Message "No certificates expiring soon"
                }
            }
            catch {
                if ($_.Exception.Message -like "*WinRM not available*") {
                    Add-HealthResult -ComputerName $Computer -Component "Security" -Check "Certificates" -Status "Info" -Message "Certificate check skipped - WinRM not available"
                } else {
                    Add-HealthResult -ComputerName $Computer -Component "Security" -Check "Certificates" -Status "Warning" -Message "Could not check certificates: $($_.Exception.Message)"
                }
            }

        }
        catch {
            Add-HealthResult -ComputerName $Computer -Component "Security" -Check "General" -Status "Critical" -Message "Failed to check security services: $($_.Exception.Message)"
        }
    }
}

# Test Client OS Health (Windows 10/11 specific checks)
function Test-ClientOSHealth {
    param(
        [string[]]$ComputerNames,
        [hashtable]$Config
    )

    Write-Host "Checking Client OS Health..." -ForegroundColor Cyan

    foreach ($Computer in $ComputerNames) {
        try {
            # Test connectivity first
            if (-not (Test-NetConnection -ComputerName $Computer -InformationLevel Quiet)) {
                continue
            }

            # Get OS version for this computer
            $osVersion = ""
            try {
                $os = Get-WmiObject -Class Win32_OperatingSystem -ComputerName $Computer -ErrorAction Stop
                $osVersion = $os.Caption.Trim()
            }
            catch {
                $osVersion = "Unknown"
            }

            # Check BitLocker encryption status
            try {
                $bitlockerStatus = Invoke-Command -ComputerName $Computer -ScriptBlock {
                    $drives = Get-WmiObject -Class Win32_EncryptableVolume -Namespace "Root\CIMv2\Security\MicrosoftVolumeEncryption" -ErrorAction SilentlyContinue
                    $results = @()
                    foreach ($drive in $drives) {
                        $results += [PSCustomObject]@{
                            Drive = $drive.DriveLetter
                            EncryptionMethod = $drive.EncryptionMethod
                            ProtectionStatus = $drive.ProtectionStatus
                            ConversionStatus = $drive.ConversionStatus
                        }
                    }
                    return $results
                } -ErrorAction Stop

                if ($bitlockerStatus) {
                    foreach ($drive in $bitlockerStatus) {
                        if ($drive.Drive -eq "C:") {
                            if ($drive.ProtectionStatus -eq 1) {
                                Add-HealthResult -ComputerName $Computer -Component "Security" -Check "BitLocker_$($drive.Drive)" -Status "Pass" -Message "BitLocker enabled and protecting drive $($drive.Drive)" -OSVersion $osVersion
                            }
                            elseif ($drive.ProtectionStatus -eq 0 -and $drive.ConversionStatus -eq 2) {
                                Add-HealthResult -ComputerName $Computer -Component "Security" -Check "BitLocker_$($drive.Drive)" -Status "Warning" -Message "BitLocker encryption in progress on drive $($drive.Drive)" -OSVersion $osVersion
                            }
                            else {
                                Add-HealthResult -ComputerName $Computer -Component "Security" -Check "BitLocker_$($drive.Drive)" -Status "Critical" -Message "BitLocker not enabled on system drive $($drive.Drive)" -OSVersion $osVersion
                            }
                        }
                        else {
                            if ($drive.ProtectionStatus -eq 1) {
                                Add-HealthResult -ComputerName $Computer -Component "Security" -Check "BitLocker_$($drive.Drive)" -Status "Pass" -Message "BitLocker enabled on drive $($drive.Drive)" -OSVersion $osVersion
                            }
                            else {
                                Add-HealthResult -ComputerName $Computer -Component "Security" -Check "BitLocker_$($drive.Drive)" -Status "Info" -Message "BitLocker not enabled on drive $($drive.Drive)" -OSVersion $osVersion
                            }
                        }
                    }
                } else {
                    Add-HealthResult -ComputerName $Computer -Component "Security" -Check "BitLocker" -Status "Critical" -Message "BitLocker not available or accessible" -OSVersion $osVersion
                }
            }
            catch {
                Add-HealthResult -ComputerName $Computer -Component "Security" -Check "BitLocker" -Status "Warning" -Message "Could not check BitLocker status: $($_.Exception.Message)" -OSVersion $osVersion
            }

            # Check User Profile health
            try {
                $profileHealth = Invoke-Command -ComputerName $Computer -ScriptBlock {
                    $tempProfiles = Get-ChildItem "C:\Users" | Where-Object { $_.Name -like "TEMP*" }
                    $corruptProfiles = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\*" -ErrorAction SilentlyContinue |
                                      Where-Object { $_.State -eq 0x2 -or $_.State -eq 0x4 }

                    return @{
                        TempProfileCount = $tempProfiles.Count
                        CorruptProfileCount = $corruptProfiles.Count
                    }
                } -ErrorAction Stop

                if ($profileHealth.CorruptProfileCount -gt 0) {
                    Add-HealthResult -ComputerName $Computer -Component "System" -Check "UserProfiles" -Status "Critical" -Message "$($profileHealth.CorruptProfileCount) corrupt user profiles detected" -OSVersion $osVersion
                }
                elseif ($profileHealth.TempProfileCount -gt 0) {
                    Add-HealthResult -ComputerName $Computer -Component "System" -Check "UserProfiles" -Status "Warning" -Message "$($profileHealth.TempProfileCount) temporary profiles detected" -OSVersion $osVersion
                }
                else {
                    Add-HealthResult -ComputerName $Computer -Component "System" -Check "UserProfiles" -Status "Pass" -Message "User profiles healthy" -OSVersion $osVersion
                }
            }
            catch {
                Add-HealthResult -ComputerName $Computer -Component "System" -Check "UserProfiles" -Status "Warning" -Message "Could not check user profile health: $($_.Exception.Message)" -OSVersion $osVersion
            }

            # Check Hardware and Driver health
            try {
                $deviceIssues = Invoke-Command -ComputerName $Computer -ScriptBlock {
                    $errorDevices = Get-WmiObject -Class Win32_PnPEntity | Where-Object {
                        $_.ConfigManagerErrorCode -ne 0 -and $_.ConfigManagerErrorCode -ne $null
                    }
                    return $errorDevices.Count
                } -ErrorAction Stop

                if ($deviceIssues -gt 0) {
                    Add-HealthResult -ComputerName $Computer -Component "Hardware" -Check "DeviceManager" -Status "Warning" -Message "$deviceIssues devices with errors in Device Manager" -OSVersion $osVersion
                }
                else {
                    Add-HealthResult -ComputerName $Computer -Component "Hardware" -Check "DeviceManager" -Status "Pass" -Message "No device errors detected" -OSVersion $osVersion
                }
            }
            catch {
                Add-HealthResult -ComputerName $Computer -Component "Hardware" -Check "DeviceManager" -Status "Warning" -Message "Could not check device status: $($_.Exception.Message)" -OSVersion $osVersion
            }

            # Check TPM status (Windows 11 requirement)
            try {
                $tpmStatus = Invoke-Command -ComputerName $Computer -ScriptBlock {
                    $tpm = Get-WmiObject -Class Win32_Tpm -Namespace "Root\CIMv2\Security\MicrosoftTpm" -ErrorAction SilentlyContinue
                    if ($tpm) {
                        return @{
                            Present = $true
                            Enabled = $tpm.IsEnabled_InitialValue
                            Activated = $tpm.IsActivated_InitialValue
                            Version = $tpm.SpecVersion
                        }
                    }
                    return @{ Present = $false }
                } -ErrorAction Stop

                if ($tpmStatus.Present) {
                    if ($tpmStatus.Enabled -and $tpmStatus.Activated) {
                        Add-HealthResult -ComputerName $Computer -Component "Hardware" -Check "TPM" -Status "Pass" -Message "TPM $($tpmStatus.Version) enabled and activated" -OSVersion $osVersion
                    }
                    else {
                        Add-HealthResult -ComputerName $Computer -Component "Hardware" -Check "TPM" -Status "Warning" -Message "TPM present but not properly configured" -OSVersion $osVersion
                    }
                }
                else {
                    Add-HealthResult -ComputerName $Computer -Component "Hardware" -Check "TPM" -Status "Critical" -Message "TPM not present (required for Windows 11)" -OSVersion $osVersion
                }
            }
            catch {
                Add-HealthResult -ComputerName $Computer -Component "Hardware" -Check "TPM" -Status "Info" -Message "Could not check TPM status" -OSVersion $osVersion
            }

            # Check Network adapter status
            try {
                $networkIssues = Invoke-Command -ComputerName $Computer -ScriptBlock {
                    $adapters = Get-WmiObject -Class Win32_NetworkAdapter | Where-Object {
                        $_.NetConnectionStatus -ne $null -and $_.AdapterType -like "*Ethernet*" -or $_.AdapterType -like "*802.11*"
                    }
                    $downAdapters = $adapters | Where-Object { $_.NetConnectionStatus -ne 2 }
                    return $downAdapters.Count
                } -ErrorAction Stop

                if ($networkIssues -gt 0) {
                    Add-HealthResult -ComputerName $Computer -Component "Network" -Check "NetworkAdapters" -Status "Warning" -Message "$networkIssues network adapters not connected" -OSVersion $osVersion
                }
                else {
                    Add-HealthResult -ComputerName $Computer -Component "Network" -Check "NetworkAdapters" -Status "Pass" -Message "Network adapters connected" -OSVersion $osVersion
                }
            }
            catch {
                Add-HealthResult -ComputerName $Computer -Component "Network" -Check "NetworkAdapters" -Status "Warning" -Message "Could not check network adapter status: $($_.Exception.Message)" -OSVersion $osVersion
            }

        }
        catch {
            Add-HealthResult -ComputerName $Computer -Component "ClientOS" -Check "General" -Status "Critical" -Message "Failed to check client OS health: $($_.Exception.Message)" -OSVersion "Unknown"
        }
    }
}

# Collect Windows Security Summary
function Get-WindowsSecuritySummary {
    param([string[]]$ComputerNames)

    Write-Host "Collecting Windows Security Summary..." -ForegroundColor Cyan

    foreach ($Computer in $ComputerNames) {
        try {
            # Test connectivity first with retries
            if (-not (Test-ComputerConnectivity -ComputerName $Computer -TimeoutSeconds 5 -RetryCount 1)) {
                # Add entry for failed connection
                $Script:WindowsSecuritySummary += [PSCustomObject]@{
                    ComputerName = $Computer
                    OSName = "Connection Failed"
                    OSVersion = "N/A"
                    BitLockerStatus = "N/A"
                    SecureBootEnabled = "N/A"
                    UptimeDays = "N/A"
                }
                continue
            }

            # Collect comprehensive security information
            $securityInfo = Invoke-RemoteCommand -ComputerName $Computer -ScriptBlock {
                $results = @{}

                # Get OS information
                try {
                    $os = Get-WmiObject -Class Win32_OperatingSystem -ErrorAction Stop
                    $results.OSName = $os.Caption.Trim()

                    # Extract OS version (build number and feature update)
                    $osVersionInfo = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" -ErrorAction SilentlyContinue
                    if ($osVersionInfo) {
                        $buildNumber = $osVersionInfo.CurrentBuild
                        $ubr = $osVersionInfo.UBR
                        $displayVersion = $osVersionInfo.DisplayVersion
                        $releaseId = $osVersionInfo.ReleaseId

                        # Determine version name based on build number
                        $versionName = switch ($buildNumber) {
                            "17763" { "1809" }
                            "18362" { "1903" }
                            "18363" { "1909" }
                            "19041" { "2004" }
                            "19042" { "20H2" }
                            "19043" { "21H1" }
                            "19044" { "21H2" }
                            "22000" { "21H2" }
                            "22621" { "22H2" }
                            "22631" { "23H2" }
                            "26100" { "24H2" }
                            default {
                                if ($displayVersion) { $displayVersion }
                                elseif ($releaseId) { $releaseId }
                                else { $buildNumber }
                            }
                        }

                        # Check for LTSC
                        if ($results.OSName -like "*LTSC*" -or $results.OSName -like "*Long-Term Servicing*") {
                            $versionName += " LTSC"
                        }

                        $results.OSVersion = $versionName
                    } else {
                        $results.OSVersion = "Unknown"
                    }

                    # Calculate uptime
                    $uptime = (Get-Date) - $os.ConvertToDateTime($os.LastBootUpTime)
                    $results.UptimeDays = $uptime.Days
                } catch {
                    $results.OSName = "Unknown"
                    $results.OSVersion = "Unknown"
                    $results.UptimeDays = "Unknown"
                }

                # Check BitLocker status for all drives
                try {
                    $bitlockerDrives = Get-WmiObject -Class Win32_EncryptableVolume -Namespace "Root\CIMv2\Security\MicrosoftVolumeEncryption" -ErrorAction SilentlyContinue
                    if ($bitlockerDrives) {
                        $encryptedDrives = $bitlockerDrives | Where-Object { $_.ProtectionStatus -eq 1 }
                        $totalDrives = $bitlockerDrives | Where-Object { $_.DriveLetter -match "^[A-Z]:$" }

                        if ($encryptedDrives.Count -eq $totalDrives.Count -and $totalDrives.Count -gt 0) {
                            $results.BitLockerStatus = "Fully Encrypted"
                        } elseif ($encryptedDrives.Count -gt 0) {
                            $results.BitLockerStatus = "Partially Encrypted ($($encryptedDrives.Count)/$($totalDrives.Count))"
                        } else {
                            $results.BitLockerStatus = "Not Encrypted"
                        }
                    } else {
                        $results.BitLockerStatus = "Not Supported"
                    }
                } catch {
                    $results.BitLockerStatus = "Check Failed"
                }

                # Check Secure Boot status (with Server 2019 compatibility)
                try {
                    $secureBootPolicy = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\State" -Name "UEFISecureBootEnabled" -ErrorAction SilentlyContinue
                    if ($secureBootPolicy -and $secureBootPolicy.UEFISecureBootEnabled -eq 1) {
                        $results.SecureBootEnabled = "Enabled"
                    } else {
                        # Alternative check for Secure Boot (may not be available on Server SKUs)
                        try {
                            # Check if Confirm-SecureBootUEFI is available
                            if (Get-Command Confirm-SecureBootUEFI -ErrorAction SilentlyContinue) {
                                $confirmSecureBoot = Confirm-SecureBootUEFI -ErrorAction SilentlyContinue
                                if ($confirmSecureBoot) {
                                    $results.SecureBootEnabled = "Enabled"
                                } else {
                                    $results.SecureBootEnabled = "Disabled"
                                }
                            } else {
                                # Server versions may not have this cmdlet - check registry only
                                $results.SecureBootEnabled = "Disabled"
                            }
                        }
                        catch {
                            $results.SecureBootEnabled = "Disabled"
                        }
                    }
                } catch {
                    $results.SecureBootEnabled = "Check Failed"
                }

                return $results
            } -FallbackMessage "Could not collect security information - WinRM not available"

            # Create security summary entry
            $Script:WindowsSecuritySummary += [PSCustomObject]@{
                ComputerName = $Computer
                OSName = $securityInfo.OSName
                OSVersion = $securityInfo.OSVersion
                BitLockerStatus = $securityInfo.BitLockerStatus
                SecureBootEnabled = $securityInfo.SecureBootEnabled
                UptimeDays = $securityInfo.UptimeDays
            }

        } catch {
            # Add entry for failed data collection
            $reason = if ($_.Exception.Message -like "*WinRM not available*") {
                "WinRM Not Available"
            } else {
                "Data Collection Failed"
            }

            $Script:WindowsSecuritySummary += [PSCustomObject]@{
                ComputerName = $Computer
                OSName = $reason
                OSVersion = "N/A"
                BitLockerStatus = "N/A"
                SecureBootEnabled = "N/A"
                UptimeDays = "N/A"
            }
        }
    }
}

# Test Hyper-V Health
function Test-HyperVHealth {
    param([string[]]$HyperVHosts)

    Write-Host "Checking Hyper-V Health..." -ForegroundColor Cyan

    foreach ($HyperVHost in $HyperVHosts) {
        try {
            # Check Hyper-V service
            $hypervService = Get-RemoteServiceStatus -ComputerName $HyperVHost -ServiceName "vmms"
            if ($hypervService -and $hypervService.Status -ne "Running") {
                Add-HealthResult -ComputerName $HyperVHost -Component "HyperV" -Check "Service" -Status "Critical" -Message "Hyper-V Management service is $($hypervService.Status)"
                continue
            } elseif ($hypervService) {
                Add-HealthResult -ComputerName $HyperVHost -Component "HyperV" -Check "Service" -Status "Pass" -Message "Hyper-V Management service is running"
            } else {
                Add-HealthResult -ComputerName $HyperVHost -Component "HyperV" -Check "Service" -Status "Critical" -Message "Hyper-V Management service not found"
                continue
            }

            # Check VMs (requires WinRM)
            try {
                if (Test-WinRMConnectivity -ComputerName $HyperVHost) {
                    $vms = Get-VM -ComputerName $HyperVHost -ErrorAction Stop
                    foreach ($vm in $vms) {
                        if ($vm.State -eq "Running") {
                            # Check integration services
                            $integrationServices = Get-VMIntegrationService -VM $vm
                            $outdatedServices = $integrationServices | Where-Object { $_.OperationalStatus -ne "Ok" }

                            if ($outdatedServices) {
                                Add-HealthResult -ComputerName $HyperVHost -Component "HyperV" -Check "VM_$($vm.Name)_Integration" -Status "Warning" -Message "Integration services need attention" -Details $outdatedServices
                            } else {
                                Add-HealthResult -ComputerName $HyperVHost -Component "HyperV" -Check "VM_$($vm.Name)_Integration" -Status "Pass" -Message "Integration services OK"
                            }

                            # Check VM resources
                            if ($vm.MemoryAssigned -gt ($vm.MemoryMaximum * 0.9)) {
                                Add-HealthResult -ComputerName $HyperVHost -Component "HyperV" -Check "VM_$($vm.Name)_Memory" -Status "Warning" -Message "VM memory usage high"
                            } else {
                                Add-HealthResult -ComputerName $HyperVHost -Component "HyperV" -Check "VM_$($vm.Name)_Memory" -Status "Pass" -Message "VM memory usage normal"
                            }
                        }
                        elseif ($vm.State -eq "Off") {
                            Add-HealthResult -ComputerName $HyperVHost -Component "HyperV" -Check "VM_$($vm.Name)_State" -Status "Warning" -Message "VM is powered off"
                        }
                        else {
                            Add-HealthResult -ComputerName $HyperVHost -Component "HyperV" -Check "VM_$($vm.Name)_State" -Status "Critical" -Message "VM is in $($vm.State) state"
                        }
                    }
                } else {
                    Add-HealthResult -ComputerName $HyperVHost -Component "HyperV" -Check "VMs" -Status "Info" -Message "VM check skipped - WinRM not available"
                }
            }
            catch {
                Add-HealthResult -ComputerName $HyperVHost -Component "HyperV" -Check "VMs" -Status "Warning" -Message "Could not check VMs: $($_.Exception.Message)"
            }

            # Check host resources (requires WinRM)
            try {
                if (Test-WinRMConnectivity -ComputerName $HyperVHost) {
                    $hostInfo = Get-VMHost -ComputerName $HyperVHost -ErrorAction Stop
                    $memoryUsage = [math]::Round(($hostInfo.MemoryCapacity - $hostInfo.MemoryAvailable) / $hostInfo.MemoryCapacity * 100, 2)

                    if ($memoryUsage -gt 90) {
                        Add-HealthResult -ComputerName $HyperVHost -Component "HyperV" -Check "HostMemory" -Status "Critical" -Message "Host memory usage is $memoryUsage%"
                    }
                    elseif ($memoryUsage -gt 80) {
                        Add-HealthResult -ComputerName $HyperVHost -Component "HyperV" -Check "HostMemory" -Status "Warning" -Message "Host memory usage is $memoryUsage%"
                    }
                    else {
                        Add-HealthResult -ComputerName $HyperVHost -Component "HyperV" -Check "HostMemory" -Status "Pass" -Message "Host memory usage is $memoryUsage%"
                    }
                } else {
                    Add-HealthResult -ComputerName $HyperVHost -Component "HyperV" -Check "HostResources" -Status "Info" -Message "Host resource check skipped - WinRM not available"
                }
            }
            catch {
                Add-HealthResult -ComputerName $HyperVHost -Component "HyperV" -Check "HostResources" -Status "Warning" -Message "Could not check host resources: $($_.Exception.Message)"
            }

        }
        catch {
            Add-HealthResult -ComputerName $HyperVHost -Component "HyperV" -Check "General" -Status "Critical" -Message "Failed to check Hyper-V health: $($_.Exception.Message)"
        }
    }
}

# Test Licensing Health
function Test-LicensingHealth {
    param(
        [string[]]$ComputerNames,
        [hashtable]$Config
    )

    Write-Host "Checking Licensing Health..." -ForegroundColor Cyan

    foreach ($Computer in $ComputerNames) {
        # Test basic connectivity first - skip if unreachable
        if (-not (Test-ComputerConnectivity -ComputerName $Computer -TimeoutSeconds 5 -RetryCount 1)) {
            Add-HealthResult -ComputerName $Computer -Component "Licensing" -Check "Connectivity" -Status "Critical" -Message "Computer unreachable - licensing checks skipped"
            continue
        }

        try {
            # Check Windows activation status
            try {
                $activationStatus = Invoke-Command -ComputerName $Computer -ScriptBlock {
                    $slmgr = & cscript //nologo "$env:windir\system32\slmgr.vbs" /xpr 2>&1
                    $dli = & cscript //nologo "$env:windir\system32\slmgr.vbs" /dli 2>&1
                    return @{
                        Status = $slmgr
                        Details = $dli
                    }
                } -ErrorAction Stop

                if ($activationStatus.Status -like "*permanently activated*") {
                    Add-HealthResult -ComputerName $Computer -Component "Licensing" -Check "WindowsActivation" -Status "Pass" -Message "Windows is permanently activated"
                }
                elseif ($activationStatus.Status -like "*will expire*") {
                    $expiryMatch = $activationStatus.Status | Select-String "(\d{1,2}/\d{1,2}/\d{4})"
                    if ($expiryMatch) {
                        $expiryDate = [DateTime]::Parse($expiryMatch.Matches[0].Value)
                        $daysUntilExpiry = ($expiryDate - (Get-Date)).Days

                        if ($daysUntilExpiry -lt 7) {
                            Add-HealthResult -ComputerName $Computer -Component "Licensing" -Check "WindowsActivation" -Status "Critical" -Message "Windows activation expires in $daysUntilExpiry days"
                        }
                        elseif ($daysUntilExpiry -lt 30) {
                            Add-HealthResult -ComputerName $Computer -Component "Licensing" -Check "WindowsActivation" -Status "Warning" -Message "Windows activation expires in $daysUntilExpiry days"
                        }
                        else {
                            Add-HealthResult -ComputerName $Computer -Component "Licensing" -Check "WindowsActivation" -Status "Pass" -Message "Windows activation expires in $daysUntilExpiry days"
                        }
                    }
                    else {
                        Add-HealthResult -ComputerName $Computer -Component "Licensing" -Check "WindowsActivation" -Status "Warning" -Message "Windows activation will expire (date unknown)"
                    }
                }
                elseif ($activationStatus.Status -like "*grace period*") {
                    Add-HealthResult -ComputerName $Computer -Component "Licensing" -Check "WindowsActivation" -Status "Warning" -Message "Windows is in grace period"
                }
                else {
                    Add-HealthResult -ComputerName $Computer -Component "Licensing" -Check "WindowsActivation" -Status "Critical" -Message "Windows activation status unknown or not activated"
                }
            }
            catch {
                Add-HealthResult -ComputerName $Computer -Component "Licensing" -Check "WindowsActivation" -Status "Warning" -Message "Could not check Windows activation: $($_.Exception.Message)"
            }

            # Check Office activation status
            try {
                $officeStatus = Invoke-Command -ComputerName $Computer -ScriptBlock {
                    $officeVersions = @()

                    # Check for Office 2016/2019/2021/365
                    $officePaths = @(
                        "${env:ProgramFiles}\Microsoft Office\Office16\ospp.vbs",
                        "${env:ProgramFiles(x86)}\Microsoft Office\Office16\ospp.vbs",
                        "${env:ProgramFiles}\Microsoft Office\Office15\ospp.vbs",
                        "${env:ProgramFiles(x86)}\Microsoft Office\Office15\ospp.vbs"
                    )

                    foreach ($path in $officePaths) {
                        if (Test-Path $path) {
                            try {
                                $osppResult = & cscript //nologo $path /dstatus 2>&1
                                $officeVersions += $osppResult -join "`n"
                                break
                            }
                            catch {
                                # Continue to next path
                            }
                        }
                    }

                    return $officeVersions
                } -ErrorAction Stop

                if ($officeStatus) {
                    if ($officeStatus -like "*LICENSED*") {
                        Add-HealthResult -ComputerName $Computer -Component "Licensing" -Check "OfficeActivation" -Status "Pass" -Message "Microsoft Office is activated"
                    }
                    elseif ($officeStatus -like "*GRACE*") {
                        Add-HealthResult -ComputerName $Computer -Component "Licensing" -Check "OfficeActivation" -Status "Warning" -Message "Microsoft Office is in grace period"
                    }
                    elseif ($officeStatus -like "*UNLICENSED*") {
                        Add-HealthResult -ComputerName $Computer -Component "Licensing" -Check "OfficeActivation" -Status "Critical" -Message "Microsoft Office is not activated"
                    }
                    else {
                        Add-HealthResult -ComputerName $Computer -Component "Licensing" -Check "OfficeActivation" -Status "Info" -Message "Office activation status unclear"
                    }
                } else {
                    Add-HealthResult -ComputerName $Computer -Component "Licensing" -Check "OfficeActivation" -Status "Info" -Message "Microsoft Office not found or not accessible"
                }
            }
            catch {
                Add-HealthResult -ComputerName $Computer -Component "Licensing" -Check "OfficeActivation" -Status "Info" -Message "Could not check Office activation"
            }

            # Check SQL Server licensing (if installed)
            try {
                $sqlStatus = Invoke-Command -ComputerName $Computer -ScriptBlock {
                    $sqlServices = Get-Service -Name "MSSQL*" -ErrorAction SilentlyContinue
                    if ($sqlServices) {
                        $sqlInfo = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\*\Setup" -Name "Edition" -ErrorAction SilentlyContinue
                        return @{
                            Services = $sqlServices.Count
                            Editions = $sqlInfo.Edition -join ", "
                        }
                    }
                    return $null
                } -ErrorAction Stop

                if ($sqlStatus -and $sqlStatus.Services -gt 0) {
                    if ($sqlStatus.Editions -like "*Express*" -or $sqlStatus.Editions -like "*Developer*") {
                        Add-HealthResult -ComputerName $Computer -Component "Licensing" -Check "SQLServerLicensing" -Status "Pass" -Message "SQL Server free edition detected: $($sqlStatus.Editions)"
                    }
                    elseif ($sqlStatus.Editions -like "*Standard*" -or $sqlStatus.Editions -like "*Enterprise*") {
                        Add-HealthResult -ComputerName $Computer -Component "Licensing" -Check "SQLServerLicensing" -Status "Info" -Message "SQL Server commercial edition detected: $($sqlStatus.Editions)"
                    }
                    else {
                        Add-HealthResult -ComputerName $Computer -Component "Licensing" -Check "SQLServerLicensing" -Status "Warning" -Message "SQL Server edition unknown: $($sqlStatus.Editions)"
                    }
                } else {
                    Add-HealthResult -ComputerName $Computer -Component "Licensing" -Check "SQLServerLicensing" -Status "Info" -Message "SQL Server not installed"
                }
            }
            catch {
                Add-HealthResult -ComputerName $Computer -Component "Licensing" -Check "SQLServerLicensing" -Status "Info" -Message "Could not check SQL Server licensing"
            }

            # Check Terminal Services/RDS CAL usage
            try {
                $rdsStatus = Invoke-RemoteCommand -ComputerName $Computer -ScriptBlock {
                    $rdsInstalled = $false

                    # Try Get-WindowsFeature first
                    try {
                        $rdsRole = Get-WindowsFeature -Name "RDS-RD-Server" -ErrorAction SilentlyContinue
                        $rdsInstalled = $rdsRole -and $rdsRole.InstallState -eq "Installed"
                    }
                    catch {
                        # Fallback to service check for systems without ServerManager module
                        $rdsService = Get-Service -Name "TermService" -ErrorAction SilentlyContinue
                        $rdsInstalled = $rdsService -ne $null
                    }

                    if ($rdsInstalled) {
                        try {
                            $calInfo = Get-WmiObject -Class Win32_TSLicenseReport -ErrorAction SilentlyContinue
                            return @{
                                RDSInstalled = $true
                                CALInfo = $calInfo
                            }
                        }
                        catch {
                            return @{
                                RDSInstalled = $true
                                CALInfo = $null
                            }
                        }
                    }
                    return @{ RDSInstalled = $false }
                } -FallbackMessage "Could not check RDS licensing - WinRM not available"

                if ($rdsStatus.RDSInstalled) {
                    if ($rdsStatus.CALInfo) {
                        Add-HealthResult -ComputerName $Computer -Component "Licensing" -Check "RDSLicensing" -Status "Pass" -Message "RDS CAL information available"
                    } else {
                        Add-HealthResult -ComputerName $Computer -Component "Licensing" -Check "RDSLicensing" -Status "Warning" -Message "RDS installed but CAL information unavailable"
                    }
                } else {
                    Add-HealthResult -ComputerName $Computer -Component "Licensing" -Check "RDSLicensing" -Status "Info" -Message "RDS not installed"
                }
            }
            catch {
                Add-HealthResult -ComputerName $Computer -Component "Licensing" -Check "RDSLicensing" -Status "Info" -Message "Could not check RDS licensing"
            }

        }
        catch {
            Add-HealthResult -ComputerName $Computer -Component "Licensing" -Check "General" -Status "Warning" -Message "Failed to check licensing health: $($_.Exception.Message)"
        }
    }
}

# Test Critical Services
function Test-CriticalServices {
    param(
        [string[]]$ComputerNames,
        [hashtable]$Config
    )

    Write-Host "Checking Critical Services..." -ForegroundColor Cyan

    foreach ($Computer in $ComputerNames) {
        # Test basic connectivity first - skip if unreachable
        if (-not (Test-ComputerConnectivity -ComputerName $Computer -TimeoutSeconds 5 -RetryCount 1)) {
            Add-HealthResult -ComputerName $Computer -Component "Services" -Check "Connectivity" -Status "Critical" -Message "Computer unreachable - service checks skipped"
            continue
        }

        try {
            # Check time synchronization
            try {
                $timeSource = Invoke-RemoteCommand -ComputerName $Computer -ScriptBlock {
                    w32tm /query /source
                } -FallbackMessage "Could not check time synchronization - WinRM not available"

                if ($timeSource -like "*Local*") {
                    Add-HealthResult -ComputerName $Computer -Component "Services" -Check "TimeSync" -Status "Warning" -Message "Time source is local CMOS clock"
                } else {
                    Add-HealthResult -ComputerName $Computer -Component "Services" -Check "TimeSync" -Status "Pass" -Message "Time synchronized with $timeSource"
                }
            }
            catch {
                if ($_.Exception.Message -like "*WinRM not available*") {
                    Add-HealthResult -ComputerName $Computer -Component "Services" -Check "TimeSync" -Status "Info" -Message "Time sync check skipped - WinRM not available"
                } else {
                    Add-HealthResult -ComputerName $Computer -Component "Services" -Check "TimeSync" -Status "Warning" -Message "Could not check time synchronization: $($_.Exception.Message)"
                }
            }

            # Check print spooler (if server)
            try {
                $spooler = Get-RemoteServiceStatus -ComputerName $Computer -ServiceName "Spooler"
                if ($spooler -and $spooler.Status -ne "Running") {
                    Add-HealthResult -ComputerName $Computer -Component "Services" -Check "PrintSpooler" -Status "Warning" -Message "Print spooler is $($spooler.Status)"
                } elseif ($spooler) {
                    Add-HealthResult -ComputerName $Computer -Component "Services" -Check "PrintSpooler" -Status "Pass" -Message "Print spooler is running"
                } else {
                    Add-HealthResult -ComputerName $Computer -Component "Services" -Check "PrintSpooler" -Status "Info" -Message "Print spooler service not found"
                }
            }
            catch {
                Add-HealthResult -ComputerName $Computer -Component "Services" -Check "PrintSpooler" -Status "Info" -Message "Print spooler service not available: $($_.Exception.Message)"
            }

            # Check system file integrity
            try {
                $sfcResults = Invoke-RemoteCommand -ComputerName $Computer -ScriptBlock {
                    $sfcLog = Get-Content "$env:windir\Logs\CBS\CBS.log" -Tail 50 -ErrorAction SilentlyContinue
                    $corruptFiles = $sfcLog | Where-Object { $_ -like "*corrupt*" -or $_ -like "*repair*" }
                    return $corruptFiles.Count
                } -FallbackMessage "Could not check system file integrity - WinRM not available"

                if ($sfcResults -gt 0) {
                    Add-HealthResult -ComputerName $Computer -Component "Services" -Check "SystemIntegrity" -Status "Warning" -Message "System file corruption detected in CBS log"
                } else {
                    Add-HealthResult -ComputerName $Computer -Component "Services" -Check "SystemIntegrity" -Status "Pass" -Message "No system file corruption detected"
                }
            }
            catch {
                if ($_.Exception.Message -like "*WinRM not available*") {
                    Add-HealthResult -ComputerName $Computer -Component "Services" -Check "SystemIntegrity" -Status "Info" -Message "System integrity check skipped - WinRM not available"
                } else {
                    Add-HealthResult -ComputerName $Computer -Component "Services" -Check "SystemIntegrity" -Status "Info" -Message "Could not check system file integrity: $($_.Exception.Message)"
                }
            }

        }
        catch {
            Add-HealthResult -ComputerName $Computer -Component "Services" -Check "General" -Status "Warning" -Message "Failed to check critical services: $($_.Exception.Message)"
        }
    }
}

# Get Windows computers from AD
function Get-WindowsComputers {
    try {
        $computers = Get-ADComputer -Filter * -Properties OperatingSystem |
                    Where-Object { $_.OperatingSystem -like "*Windows*" -and $_.Enabled -eq $true } |
                    Select-Object -ExpandProperty Name

        Write-HealthLog -Message "Found $($computers.Count) Windows computers in Active Directory"
        return $computers
    }
    catch {
        Write-HealthLog -Message "Failed to query Active Directory for computers: $($_.Exception.Message)" -Level "Error"
        return @()
    }
}

# Generate HTML Report
function New-HealthReport {
    param(
        [array]$Results,
        [hashtable]$Summary,
        [string]$OutputPath
    )

    $reportDate = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $runtime = (Get-Date) - $Script:StartTime

    $html = @"
<!DOCTYPE html>
<html>
<head>
    <title>Weekly Health Check Report - $reportDate</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .header { background-color: #2c3e50; color: white; padding: 20px; border-radius: 5px; margin-bottom: 20px; }
        .summary { display: flex; gap: 20px; margin-bottom: 20px; }
        .summary-card { flex: 1; padding: 15px; border-radius: 5px; text-align: center; color: white; }
        .critical { background-color: #e74c3c; }
        .warning { background-color: #f39c12; }
        .info { background-color: #3498db; }
        .pass { background-color: #27ae60; }
        .total { background-color: #34495e; }
        .results-table { width: 100%; border-collapse: collapse; margin-top: 20px; }
        .results-table th, .results-table td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        .results-table th { background-color: #34495e; color: white; }
        .system-group-header {
            background: linear-gradient(135deg, #34495e, #2c3e50) !important;
            color: white !important;
            font-weight: bold;
            font-size: 1.1em;
            padding: 12px !important;
            border-left: 5px solid #3498db !important;
            text-align: center;
        }
        .system-group-odd { background-color: #f8f9fa; }
        .system-group-even { background-color: #ffffff; }
        .system-group-border { border-top: 2px solid #bdc3c7; }
        .results-table tbody tr:hover {
            background-color: #e8f4fd !important;
            transition: background-color 0.2s;
        }
        .status-critical { color: #e74c3c; font-weight: bold; }
        .status-warning { color: #f39c12; font-weight: bold; }
        .status-info { color: #3498db; font-weight: bold; }
        .status-pass { color: #27ae60; font-weight: bold; }
        .footer { margin-top: 30px; padding: 15px; background-color: #ecf0f1; border-radius: 5px; }
    </style>
</head>
<body>
    <div class="header">
        <h1>Weekly Health Check Report</h1>
        <p>Generated: $reportDate | Runtime: $($runtime.ToString("hh\:mm\:ss")) | Script Version: $Script:ScriptVersion</p>
    </div>

    <div class="summary">
        <div class="summary-card critical">
            <h3>Critical</h3>
            <h2>$($Summary.Critical)</h2>
        </div>
        <div class="summary-card warning">
            <h3>Warning</h3>
            <h2>$($Summary.Warning)</h2>
        </div>
        <div class="summary-card info">
            <h3>Info</h3>
            <h2>$($Summary.Info)</h2>
        </div>
        <div class="summary-card pass">
            <h3>Pass</h3>
            <h2>$(($Results | Where-Object {$_.Status -eq "Pass"}).Count)</h2>
        </div>
        <div class="summary-card total">
            <h3>Total Checks</h3>
            <h2>$($Summary.Total)</h2>
        </div>
    </div>

    <h2>Detailed Results</h2>
    <table class="results-table">
        <thead>
            <tr>
                <th>Timestamp</th>
                <th>Computer</th>
                <th>OS Version</th>
                <th>Component</th>
                <th>Check</th>
                <th>Status</th>
                <th>Message</th>
            </tr>
        </thead>
        <tbody>
"@

    # Group results by computer for system grouping
    $groupedResults = $Results | Sort-Object ComputerName, Component, Check | Group-Object ComputerName
    $systemIndex = 0

    foreach ($computerGroup in $groupedResults) {
        $computerName = $computerGroup.Name
        $computerResults = $computerGroup.Group
        $isOddGroup = ($systemIndex % 2) -eq 1
        $groupClass = if ($isOddGroup) { "system-group-odd" } else { "system-group-even" }
        $borderClass = if ($systemIndex -gt 0) { "system-group-border" } else { "" }

        # Get OS version from first result for this computer
        $osVersion = if ($computerResults.Count -gt 0) { $computerResults[0].OSVersion } else { "Unknown" }

        # Add system header row
        $html += @"
            <tr class="system-group-header $borderClass">
                <td colspan="7">$computerName ($osVersion)</td>
            </tr>
"@

        # Add individual result rows for this computer
        foreach ($result in $computerResults) {
            $statusClass = "status-" + $result.Status.ToLower()
            $html += @"
            <tr class="$groupClass">
                <td>$($result.Timestamp.ToString('yyyy-MM-dd HH:mm:ss'))</td>
                <td>$($result.ComputerName)</td>
                <td>$($result.OSVersion)</td>
                <td>$($result.Component)</td>
                <td>$($result.Check)</td>
                <td class="$statusClass">$($result.Status)</td>
                <td>$($result.Message)</td>
            </tr>
"@
        }

        $systemIndex++
    }

    $html += @"
        </tbody>
    </table>

    <h2>Windows Security Summary</h2>
    <table class="results-table">
        <thead>
            <tr>
                <th>Computer Name</th>
                <th>OS Name</th>
                <th>OS Version</th>
                <th>BitLocker Status</th>
                <th>SecureBoot Enabled</th>
                <th>Uptime (Days)</th>
            </tr>
        </thead>
        <tbody>
"@

    foreach ($security in ($Script:WindowsSecuritySummary | Sort-Object ComputerName)) {
        # Apply color coding based on security status
        $bitlockerClass = switch ($security.BitLockerStatus) {
            "Fully Encrypted" { "status-pass" }
            { $_ -like "Partially Encrypted*" } { "status-warning" }
            "Not Encrypted" { "status-critical" }
            "Not Supported" { "status-info" }
            default { "" }
        }

        $secureBootClass = switch ($security.SecureBootEnabled) {
            "Enabled" { "status-pass" }
            "Disabled" { "status-warning" }
            default { "" }
        }

        $uptimeClass = ""
        if ($security.UptimeDays -ne "N/A" -and $security.UptimeDays -ne "Unknown") {
            $uptimeClass = if ([int]$security.UptimeDays -gt 45) { "status-critical" }
                          elseif ([int]$security.UptimeDays -gt 35) { "status-warning" }
                          else { "status-pass" }
        }

        $html += @"
            <tr>
                <td>$($security.ComputerName)</td>
                <td>$($security.OSName)</td>
                <td>$($security.OSVersion)</td>
                <td class="$bitlockerClass">$($security.BitLockerStatus)</td>
                <td class="$secureBootClass">$($security.SecureBootEnabled)</td>
                <td class="$uptimeClass">$($security.UptimeDays)</td>
            </tr>
"@
    }

    $html += @"
        </tbody>
    </table>

    <h2>Trellix Endpoint Security Status</h2>
    <table class="results-table">
        <thead>
            <tr>
                <th>Computer Name</th>
                <th>OS Version</th>
                <th>Product Version</th>
                <th>Engine Version</th>
                <th>DAT Version</th>
                <th>DAT Date</th>
            </tr>
        </thead>
        <tbody>
"@

    foreach ($trellix in ($Script:TrellixInfo | Sort-Object ComputerName)) {
        $html += @"
            <tr>
                <td>$($trellix.ComputerName)</td>
                <td>$($trellix.OSVersion)</td>
                <td>$($trellix.ProductVersion)</td>
                <td>$($trellix.EngineVersion)</td>
                <td>$($trellix.DATVersion)</td>
                <td>$($trellix.DATDate)</td>
            </tr>
"@
    }

    $html += @"
        </tbody>
    </table>

    <div class="footer">
        <p><strong>Report Summary:</strong></p>
        <ul>
            <li>Total Systems Checked: $(($Results | Select-Object ComputerName -Unique).Count)</li>
            <li>Critical Issues: $($Summary.Critical)</li>
            <li>Warning Issues: $($Summary.Warning)</li>
            <li>Informational Items: $($Summary.Info)</li>
            <li>Successful Checks: $(($Results | Where-Object {$_.Status -eq "Pass"}).Count)</li>
        </ul>
        <p><small>This report was generated by the Weekly Health Check script v$Script:ScriptVersion</small></p>
    </div>
</body>
</html>
"@

    try {
        $html | Out-File -FilePath $OutputPath -Encoding UTF8
        Write-HealthLog -Message "HTML report saved to $OutputPath"
    }
    catch {
        Write-HealthLog -Message "Failed to save HTML report: $($_.Exception.Message)" -Level "Error"
    }
}

# Main execution
function Main {
    Write-Host "Starting Weekly Health Check..." -ForegroundColor Green
    Write-HealthLog -Message "Weekly Health Check started"

    # Load configuration
    $config = Get-Configuration -Path $ConfigPath

    # Ensure report directory exists
    if (-not (Test-Path $ReportPath)) {
        New-Item -ItemType Directory -Path $ReportPath -Force | Out-Null
    }

    # Get target computers
    if ($ComputerName) {
        $targetComputers = $ComputerName
    } else {
        $targetComputers = Get-WindowsComputers
    }

    if ($targetComputers.Count -eq 0) {
        Write-Error "No target computers found or specified"
        exit 1
    }

    Write-Host "Target computers: $($targetComputers -join ', ')" -ForegroundColor Cyan
    Write-Host "Connectivity timeout: $($config.ConnectivityTimeoutSeconds)s, Retries: $($config.ConnectivityRetryCount), WinRM timeout: $($config.WinRMTimeoutSeconds)s" -ForegroundColor Yellow

    # Get domain controllers
    $domainControllers = (Get-ADDomainController -Filter *).Name

    # Get Hyper-V hosts with compatibility for different Windows versions
    $hypervHosts = @()
    if (-not $SkipHyperV) {
        foreach ($computer in $targetComputers) {
            try {
                $isHypervHost = $false

                # Try Get-WindowsFeature first (Server versions with ServerManager module)
                try {
                    if (Test-WinRMConnectivity -ComputerName $computer) {
                        $feature = Get-WindowsFeature -Name Hyper-V -ComputerName $computer -ErrorAction Stop
                        $isHypervHost = $feature.InstallState -eq "Installed"
                    }
                }
                catch {
                    # Fallback to WMI check for systems without ServerManager module
                    try {
                        $hypervService = Get-WmiObject -Class Win32_Service -ComputerName $computer -Filter "Name='vmms'" -ErrorAction Stop
                        $isHypervHost = $hypervService -ne $null
                    }
                    catch {
                        # Final fallback - try to query Hyper-V directly
                        try {
                            if (Test-WinRMConnectivity -ComputerName $computer) {
                                $testResult = Invoke-Command -ComputerName $computer -ScriptBlock {
                                    Get-Service -Name vmms -ErrorAction SilentlyContinue
                                } -ErrorAction Stop
                                $isHypervHost = $testResult -ne $null
                            }
                        }
                        catch {
                            $isHypervHost = $false
                        }
                    }
                }

                if ($isHypervHost) {
                    $hypervHosts += $computer
                }
            }
            catch {
                # Skip this computer if all checks fail
                continue
            }
        }
    }

    # Categorize computers by OS type
    $serverComputers = @()
    $clientComputers = @()

    foreach ($computer in $targetComputers) {
        try {
            $os = Get-WmiObject -Class Win32_OperatingSystem -ComputerName $computer -ErrorAction Stop
            if ($os.Caption -like "*Server*") {
                $serverComputers += $computer
            }
            elseif ($os.Caption -like "*Windows 10*" -or $os.Caption -like "*Windows 11*") {
                $clientComputers += $computer
            }
            else {
                # Default to server category for unknown Windows versions
                $serverComputers += $computer
            }
        }
        catch {
            # If we can't determine OS, default to server category
            $serverComputers += $computer
        }
    }

    Write-Host "Found $($serverComputers.Count) server systems and $($clientComputers.Count) client systems" -ForegroundColor Cyan

    # Run infrastructure health checks (always run these)
    Test-ADHealth -DomainControllers $domainControllers
    Test-DNSHealth -DNSServers $domainControllers

    # Run health checks for all systems
    Test-SystemHealth -ComputerNames $targetComputers -Config $config
    Test-StorageHealth -ComputerNames $targetComputers -Config $config
    Test-SecurityServices -ComputerNames $targetComputers -Config $config
    Test-LicensingHealth -ComputerNames $targetComputers -Config $config

    # Collect Windows Security Summary for all systems
    Get-WindowsSecuritySummary -ComputerNames $targetComputers

    # Run server-specific checks
    if ($serverComputers.Count -gt 0) {
        Test-CriticalServices -ComputerNames $serverComputers -Config $config
    }

    # Run client-specific checks
    if ($clientComputers.Count -gt 0) {
        Test-ClientOSHealth -ComputerNames $clientComputers -Config $config
    }

    # Run Hyper-V checks
    if ($hypervHosts.Count -gt 0) {
        Test-HyperVHealth -HyperVHosts $hypervHosts
    }

    # Generate reports
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $htmlReportPath = Join-Path $ReportPath "HealthCheck_$timestamp.html"
    $csvReportPath = Join-Path $ReportPath "HealthCheck_$timestamp.csv"

    New-HealthReport -Results $Script:HealthResults -Summary $Script:SummaryStats -OutputPath $htmlReportPath

    # Export CSV
    try {
        $Script:HealthResults | Export-Csv -Path $csvReportPath -NoTypeInformation
        Write-HealthLog -Message "CSV report saved to $csvReportPath"
    }
    catch {
        Write-HealthLog -Message "Failed to save CSV report: $($_.Exception.Message)" -Level "Error"
    }

    # Final summary
    $endTime = Get-Date
    $runtime = $endTime - $Script:StartTime

    Write-Host "`nHealth Check Complete!" -ForegroundColor Green
    Write-Host "Runtime: $($runtime.ToString('hh\:mm\:ss'))" -ForegroundColor Green
    Write-Host "Critical: $($Script:SummaryStats.Critical)" -ForegroundColor Red
    Write-Host "Warning: $($Script:SummaryStats.Warning)" -ForegroundColor Yellow
    Write-Host "Info: $($Script:SummaryStats.Info)" -ForegroundColor Cyan
    Write-Host "Pass: $(($Script:HealthResults | Where-Object {$_.Status -eq "Pass"}).Count)" -ForegroundColor Green
    Write-Host "Total Checks: $($Script:SummaryStats.Total)" -ForegroundColor White
    Write-Host "HTML Report: $htmlReportPath" -ForegroundColor Cyan
    Write-Host "CSV Report: $csvReportPath" -ForegroundColor Cyan

    Write-HealthLog -Message "Weekly Health Check completed. Critical: $($Script:SummaryStats.Critical), Warning: $($Script:SummaryStats.Warning), Total: $($Script:SummaryStats.Total)"
}

# Run main function
Main