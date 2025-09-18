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

.PARAMETER Verbose
    Enables verbose output for detailed logging and troubleshooting.

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
    Author         : System Administrator
    Prerequisite   : PowerShell 5.1+, Windows Server 2019, Domain Controller
    Created        : $(Get-Date -Format 'yyyy-MM-dd')

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
    [switch]$SkipHyperV,

    [Parameter(Mandatory = $false)]
    [switch]$Verbose
)

# Script variables
$Script:StartTime = Get-Date
$Script:ScriptVersion = "1.0.0"
$Script:HealthResults = @()
$Script:SummaryStats = @{
    Critical = 0
    Warning = 0
    Info = 0
    Total = 0
}

# Import required modules
try {
    Import-Module ActiveDirectory -ErrorAction Stop
    if (-not $SkipHyperV -and (Get-WindowsFeature -Name Hyper-V).InstallState -eq "Installed") {
        Import-Module Hyper-V -ErrorAction Stop
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

    if ($Verbose) {
        Write-Host "[$Level] $Message"
    }
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
        [object]$Details = $null
    )

    $result = [PSCustomObject]@{
        Timestamp = Get-Date
        ComputerName = $ComputerName
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
                    $svc = Get-Service -Name $service -ComputerName $DC -ErrorAction Stop
                    if ($svc.Status -ne "Running") {
                        Add-HealthResult -ComputerName $DC -Component "ActiveDirectory" -Check "Service_$service" -Status "Critical" -Message "$service service is $($svc.Status)"
                    } else {
                        Add-HealthResult -ComputerName $DC -Component "ActiveDirectory" -Check "Service_$service" -Status "Pass" -Message "$service service is running"
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
            $dnsService = Get-Service -Name DNS -ComputerName $DNSServer -ErrorAction Stop
            if ($dnsService.Status -ne "Running") {
                Add-HealthResult -ComputerName $DNSServer -Component "DNS" -Check "Service" -Status "Critical" -Message "DNS service is $($dnsService.Status)"
            } else {
                Add-HealthResult -ComputerName $DNSServer -Component "DNS" -Check "Service" -Status "Pass" -Message "DNS service is running"
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

            # Check DNS zones
            try {
                $zones = Get-DnsServerZone -ComputerName $DNSServer -ErrorAction Stop
                $errorZones = $zones | Where-Object { $_.ZoneType -eq "Primary" -and $_.IsDsIntegrated -eq $false }
                if ($errorZones) {
                    Add-HealthResult -ComputerName $DNSServer -Component "DNS" -Check "Zones" -Status "Warning" -Message "Non-AD integrated zones detected" -Details $errorZones
                } else {
                    Add-HealthResult -ComputerName $DNSServer -Component "DNS" -Check "Zones" -Status "Pass" -Message "All primary zones are AD integrated"
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
        try {
            # Test connectivity
            if (-not (Test-NetConnection -ComputerName $Computer -InformationLevel Quiet)) {
                Add-HealthResult -ComputerName $Computer -Component "System" -Check "Connectivity" -Status "Critical" -Message "Computer is not reachable"
                continue
            }

            # Check disk space
            try {
                $disks = Get-WmiObject -Class Win32_LogicalDisk -ComputerName $Computer -Filter "DriveType=3" -ErrorAction Stop
                foreach ($disk in $disks) {
                    $freePercent = [math]::Round(($disk.FreeSpace / $disk.Size) * 100, 2)

                    if ($freePercent -lt $Config.DiskSpaceCriticalThreshold) {
                        Add-HealthResult -ComputerName $Computer -Component "System" -Check "DiskSpace_$($disk.DeviceID)" -Status "Critical" -Message "Disk $($disk.DeviceID) has only $freePercent% free space"
                    }
                    elseif ($freePercent -lt $Config.DiskSpaceWarningThreshold) {
                        Add-HealthResult -ComputerName $Computer -Component "System" -Check "DiskSpace_$($disk.DeviceID)" -Status "Warning" -Message "Disk $($disk.DeviceID) has $freePercent% free space"
                    }
                    else {
                        Add-HealthResult -ComputerName $Computer -Component "System" -Check "DiskSpace_$($disk.DeviceID)" -Status "Pass" -Message "Disk $($disk.DeviceID) has $freePercent% free space"
                    }
                }
            }
            catch {
                Add-HealthResult -ComputerName $Computer -Component "System" -Check "DiskSpace" -Status "Warning" -Message "Could not check disk space: $($_.Exception.Message)"
            }

            # Check uptime
            try {
                $os = Get-WmiObject -Class Win32_OperatingSystem -ComputerName $Computer -ErrorAction Stop
                $uptime = (Get-Date) - $os.ConvertToDateTime($os.LastBootUpTime)

                if ($uptime.Days -gt $Config.UptimeCriticalDays) {
                    Add-HealthResult -ComputerName $Computer -Component "System" -Check "Uptime" -Status "Critical" -Message "System has not rebooted in $($uptime.Days) days"
                }
                elseif ($uptime.Days -gt $Config.UptimeWarningDays) {
                    Add-HealthResult -ComputerName $Computer -Component "System" -Check "Uptime" -Status "Warning" -Message "System has not rebooted in $($uptime.Days) days"
                }
                else {
                    Add-HealthResult -ComputerName $Computer -Component "System" -Check "Uptime" -Status "Pass" -Message "System uptime: $($uptime.Days) days"
                }
            }
            catch {
                Add-HealthResult -ComputerName $Computer -Component "System" -Check "Uptime" -Status "Warning" -Message "Could not check uptime: $($_.Exception.Message)"
            }

            # Check memory usage
            try {
                $memory = Get-WmiObject -Class Win32_OperatingSystem -ComputerName $Computer -ErrorAction Stop
                $memoryUsage = [math]::Round((($memory.TotalVisibleMemorySize - $memory.FreePhysicalMemory) / $memory.TotalVisibleMemorySize) * 100, 2)

                if ($memoryUsage -gt 90) {
                    Add-HealthResult -ComputerName $Computer -Component "System" -Check "Memory" -Status "Critical" -Message "Memory usage is $memoryUsage%"
                }
                elseif ($memoryUsage -gt 80) {
                    Add-HealthResult -ComputerName $Computer -Component "System" -Check "Memory" -Status "Warning" -Message "Memory usage is $memoryUsage%"
                }
                else {
                    Add-HealthResult -ComputerName $Computer -Component "System" -Check "Memory" -Status "Pass" -Message "Memory usage is $memoryUsage%"
                }
            }
            catch {
                Add-HealthResult -ComputerName $Computer -Component "System" -Check "Memory" -Status "Warning" -Message "Could not check memory usage: $($_.Exception.Message)"
            }

        }
        catch {
            Add-HealthResult -ComputerName $Computer -Component "System" -Check "General" -Status "Critical" -Message "Failed to check system health: $($_.Exception.Message)"
        }
    }
}

# Test Storage Health
function Test-StorageHealth {
    param([string[]]$ComputerNames)

    Write-Host "Checking Storage Health..." -ForegroundColor Cyan

    foreach ($Computer in $ComputerNames) {
        try {
            # Check for disk errors in event log
            $diskErrors = Get-WinEvent -ComputerName $Computer -FilterHashtable @{LogName='System'; ID=7,11,15,153; StartTime=(Get-Date).AddDays(-7)} -ErrorAction SilentlyContinue

            if ($diskErrors) {
                $criticalErrors = $diskErrors | Where-Object { $_.Id -in @(7, 11) }
                $warningErrors = $diskErrors | Where-Object { $_.Id -in @(15, 153) }

                if ($criticalErrors) {
                    Add-HealthResult -ComputerName $Computer -Component "Storage" -Check "DiskErrors" -Status "Critical" -Message "Critical disk errors detected in last 7 days" -Details $criticalErrors
                }
                elseif ($warningErrors) {
                    Add-HealthResult -ComputerName $Computer -Component "Storage" -Check "DiskErrors" -Status "Warning" -Message "Disk warnings detected in last 7 days" -Details $warningErrors
                }
            }
            else {
                Add-HealthResult -ComputerName $Computer -Component "Storage" -Check "DiskErrors" -Status "Pass" -Message "No disk errors in last 7 days"
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
        try {
            # Check Trellix ENS services
            foreach ($service in $Config.TrellixServices) {
                try {
                    $svc = Get-Service -Name $service -ComputerName $Computer -ErrorAction Stop
                    if ($svc.Status -ne "Running") {
                        Add-HealthResult -ComputerName $Computer -Component "Security" -Check "Trellix_$service" -Status "Critical" -Message "Trellix service $service is $($svc.Status)"
                    } else {
                        Add-HealthResult -ComputerName $Computer -Component "Security" -Check "Trellix_$service" -Status "Pass" -Message "Trellix service $service is running"
                    }
                }
                catch {
                    Add-HealthResult -ComputerName $Computer -Component "Security" -Check "Trellix_$service" -Status "Warning" -Message "Trellix service $service not found or inaccessible"
                }
            }

            # Check Trellix DAT version
            try {
                $trellixReg = Invoke-Command -ComputerName $Computer -ScriptBlock {
                    Get-ItemProperty -Path "HKLM:\SOFTWARE\McAfee\AVEngine" -Name "AVDatVersion" -ErrorAction SilentlyContinue
                } -ErrorAction Stop

                if ($trellixReg.AVDatVersion) {
                    $datDate = [DateTime]::ParseExact($trellixReg.AVDatVersion.Substring(0,8), "yyyyMMdd", $null)
                    $daysSinceUpdate = (Get-Date) - $datDate

                    if ($daysSinceUpdate.Days -gt 7) {
                        Add-HealthResult -ComputerName $Computer -Component "Security" -Check "Trellix_DAT" -Status "Critical" -Message "Trellix DAT files are $($daysSinceUpdate.Days) days old"
                    }
                    elseif ($daysSinceUpdate.Days -gt 3) {
                        Add-HealthResult -ComputerName $Computer -Component "Security" -Check "Trellix_DAT" -Status "Warning" -Message "Trellix DAT files are $($daysSinceUpdate.Days) days old"
                    }
                    else {
                        Add-HealthResult -ComputerName $Computer -Component "Security" -Check "Trellix_DAT" -Status "Pass" -Message "Trellix DAT files are current ($($datDate.ToString('yyyy-MM-dd')))"
                    }
                } else {
                    Add-HealthResult -ComputerName $Computer -Component "Security" -Check "Trellix_DAT" -Status "Warning" -Message "Could not determine Trellix DAT version"
                }
            }
            catch {
                Add-HealthResult -ComputerName $Computer -Component "Security" -Check "Trellix_DAT" -Status "Warning" -Message "Could not check Trellix DAT version: $($_.Exception.Message)"
            }

            # Check Splunk services
            foreach ($service in $Config.SplunkServices) {
                try {
                    $svc = Get-Service -Name $service -ComputerName $Computer -ErrorAction Stop
                    if ($svc.Status -ne "Running") {
                        Add-HealthResult -ComputerName $Computer -Component "Security" -Check "Splunk_$service" -Status "Critical" -Message "Splunk service $service is $($svc.Status)"
                    } else {
                        Add-HealthResult -ComputerName $Computer -Component "Security" -Check "Splunk_$service" -Status "Pass" -Message "Splunk service $service is running"
                    }
                }
                catch {
                    Add-HealthResult -ComputerName $Computer -Component "Security" -Check "Splunk_$service" -Status "Warning" -Message "Splunk service $service not found or inaccessible"
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
                $expiredCerts = Invoke-Command -ComputerName $Computer -ScriptBlock {
                    Get-ChildItem -Path Cert:\LocalMachine\My | Where-Object {
                        $_.NotAfter -lt (Get-Date).AddDays(90) -and $_.NotAfter -gt (Get-Date)
                    }
                } -ErrorAction Stop

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
                Add-HealthResult -ComputerName $Computer -Component "Security" -Check "Certificates" -Status "Warning" -Message "Could not check certificates: $($_.Exception.Message)"
            }

        }
        catch {
            Add-HealthResult -ComputerName $Computer -Component "Security" -Check "General" -Status "Critical" -Message "Failed to check security services: $($_.Exception.Message)"
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
            $hypervService = Get-Service -Name vmms -ComputerName $HyperVHost -ErrorAction Stop
            if ($hypervService.Status -ne "Running") {
                Add-HealthResult -ComputerName $HyperVHost -Component "HyperV" -Check "Service" -Status "Critical" -Message "Hyper-V Management service is $($hypervService.Status)"
                continue
            } else {
                Add-HealthResult -ComputerName $HyperVHost -Component "HyperV" -Check "Service" -Status "Pass" -Message "Hyper-V Management service is running"
            }

            # Check VMs
            try {
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
            }
            catch {
                Add-HealthResult -ComputerName $HyperVHost -Component "HyperV" -Check "VMs" -Status "Warning" -Message "Could not check VMs: $($_.Exception.Message)"
            }

            # Check host resources
            try {
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
    param([string[]]$ComputerNames)

    Write-Host "Checking Licensing Health..." -ForegroundColor Cyan

    foreach ($Computer in $ComputerNames) {
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
                $rdsStatus = Invoke-Command -ComputerName $Computer -ScriptBlock {
                    $rdsRole = Get-WindowsFeature -Name "RDS-RD-Server" -ErrorAction SilentlyContinue
                    if ($rdsRole -and $rdsRole.InstallState -eq "Installed") {
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
                } -ErrorAction Stop

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
    param([string[]]$ComputerNames)

    Write-Host "Checking Critical Services..." -ForegroundColor Cyan

    foreach ($Computer in $ComputerNames) {
        try {
            # Check time synchronization
            try {
                $timeSource = Invoke-Command -ComputerName $Computer -ScriptBlock {
                    w32tm /query /source
                } -ErrorAction Stop

                if ($timeSource -like "*Local*") {
                    Add-HealthResult -ComputerName $Computer -Component "Services" -Check "TimeSync" -Status "Warning" -Message "Time source is local CMOS clock"
                } else {
                    Add-HealthResult -ComputerName $Computer -Component "Services" -Check "TimeSync" -Status "Pass" -Message "Time synchronized with $timeSource"
                }
            }
            catch {
                Add-HealthResult -ComputerName $Computer -Component "Services" -Check "TimeSync" -Status "Warning" -Message "Could not check time synchronization: $($_.Exception.Message)"
            }

            # Check print spooler (if server)
            try {
                $spooler = Get-Service -Name Spooler -ComputerName $Computer -ErrorAction Stop
                if ($spooler.Status -ne "Running") {
                    Add-HealthResult -ComputerName $Computer -Component "Services" -Check "PrintSpooler" -Status "Warning" -Message "Print spooler is $($spooler.Status)"
                } else {
                    Add-HealthResult -ComputerName $Computer -Component "Services" -Check "PrintSpooler" -Status "Pass" -Message "Print spooler is running"
                }
            }
            catch {
                Add-HealthResult -ComputerName $Computer -Component "Services" -Check "PrintSpooler" -Status "Info" -Message "Print spooler service not available"
            }

            # Check system file integrity
            try {
                $sfcResults = Invoke-Command -ComputerName $Computer -ScriptBlock {
                    $sfcLog = Get-Content "$env:windir\Logs\CBS\CBS.log" -Tail 50 -ErrorAction SilentlyContinue
                    $corruptFiles = $sfcLog | Where-Object { $_ -like "*corrupt*" -or $_ -like "*repair*" }
                    return $corruptFiles.Count
                } -ErrorAction Stop

                if ($sfcResults -gt 0) {
                    Add-HealthResult -ComputerName $Computer -Component "Services" -Check "SystemIntegrity" -Status "Warning" -Message "System file corruption detected in CBS log"
                } else {
                    Add-HealthResult -ComputerName $Computer -Component "Services" -Check "SystemIntegrity" -Status "Pass" -Message "No system file corruption detected"
                }
            }
            catch {
                Add-HealthResult -ComputerName $Computer -Component "Services" -Check "SystemIntegrity" -Status "Info" -Message "Could not check system file integrity"
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
        .results-table tr:nth-child(even) { background-color: #f2f2f2; }
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
                <th>Component</th>
                <th>Check</th>
                <th>Status</th>
                <th>Message</th>
            </tr>
        </thead>
        <tbody>
"@

    foreach ($result in ($Results | Sort-Object ComputerName, Component, Check)) {
        $statusClass = "status-" + $result.Status.ToLower()
        $html += @"
            <tr>
                <td>$($result.Timestamp.ToString('yyyy-MM-dd HH:mm:ss'))</td>
                <td>$($result.ComputerName)</td>
                <td>$($result.Component)</td>
                <td>$($result.Check)</td>
                <td class="$statusClass">$($result.Status)</td>
                <td>$($result.Message)</td>
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

    # Get domain controllers
    $domainControllers = (Get-ADDomainController -Filter *).Name

    # Get Hyper-V hosts
    $hypervHosts = @()
    if (-not $SkipHyperV) {
        $hypervHosts = $targetComputers | Where-Object {
            try {
                $feature = Get-WindowsFeature -Name Hyper-V -ComputerName $_ -ErrorAction Stop
                return $feature.InstallState -eq "Installed"
            }
            catch {
                return $false
            }
        }
    }

    # Run health checks
    Test-ADHealth -DomainControllers $domainControllers
    Test-DNSHealth -DNSServers $domainControllers
    Test-SystemHealth -ComputerNames $targetComputers -Config $config
    Test-StorageHealth -ComputerNames $targetComputers
    Test-SecurityServices -ComputerNames $targetComputers -Config $config
    Test-LicensingHealth -ComputerNames $targetComputers
    Test-CriticalServices -ComputerNames $targetComputers

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