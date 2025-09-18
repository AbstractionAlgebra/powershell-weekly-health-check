# PowerShell Weekly Health Check

A comprehensive health monitoring script designed for Windows Server 2019 Domain Controller environments in air-gapped, STIG-compliant networks.

## Overview

This script performs proactive health checks on Windows systems, Active Directory infrastructure, Hyper-V environments, and security services. It generates detailed HTML and CSV reports with executive summaries for system administrators.

## Features

- **Active Directory Health**: Replication status, FSMO roles, service health
- **DNS Health**: Service status, zone health, resolution testing
- **System Health**: Disk space, uptime tracking, memory usage
- **Storage Health**: Disk error detection, performance monitoring
- **Security Services**: Trellix ENS status, DAT versions, Splunk monitoring
- **Hyper-V Health**: VM status, integration services, resource utilization
- **Critical Services**: Time synchronization, print services, system integrity
- **Comprehensive Reporting**: HTML dashboard with color-coded status indicators

## Requirements

- Windows Server 2019 Domain Controller
- PowerShell 5.1 or higher
- Active Directory PowerShell module
- Hyper-V PowerShell module (if Hyper-V checks enabled)
- Administrative privileges
- Network connectivity to target systems

## Installation

1. Clone or download the repository to your Domain Controller
2. Extract to a directory such as `C:\Scripts\HealthCheck\`
3. Ensure the executing user has administrative privileges
4. Verify PowerShell execution policy allows script execution

```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope LocalMachine
```

## Configuration

Edit `Config\settings.json` to customize thresholds and service names:

```json
{
    "DiskSpaceWarningThreshold": 20,
    "DiskSpaceCriticalThreshold": 10,
    "UptimeWarningDays": 35,
    "UptimeCriticalDays": 45,
    "TrellixServices": ["McAfeeFramework", "mfemms", "mfevtp"],
    "SplunkServices": ["SplunkForwarder"]
}
```

## Usage

### Basic Usage
```powershell
.\Invoke-WeeklyHealthCheck.ps1
```

### Check Specific Computers
```powershell
.\Invoke-WeeklyHealthCheck.ps1 -ComputerName "Server01", "Server02"
```

### Skip Hyper-V Checks
```powershell
.\Invoke-WeeklyHealthCheck.ps1 -SkipHyperV
```

### Custom Report Location
```powershell
.\Invoke-WeeklyHealthCheck.ps1 -ReportPath "C:\HealthReports\"
```

### Verbose Output
```powershell
.\Invoke-WeeklyHealthCheck.ps1 -Verbose
```

## Scheduled Task Setup

1. Open **Task Scheduler** as Administrator
2. Create Basic Task: "Weekly Health Check"
3. **Trigger**: Weekly, select preferred day and time
4. **Action**: Start a program
   - Program: `powershell.exe`
   - Arguments: `-ExecutionPolicy Bypass -File "C:\Scripts\Invoke-WeeklyHealthCheck.ps1"`
5. **Settings**:
   - Run with highest privileges: ✓ Enabled
   - Run whether user is logged on or not: ✓ Enabled

## Health Checks Performed

### Active Directory
- Domain controller connectivity (LDAP port 389)
- Critical AD services (ADWS, KDC, Netlogon, DNS)
- Replication status and failures
- SYSVOL accessibility
- Group Policy replication

### DNS
- DNS service status
- Zone health and configuration
- Forward/reverse lookup resolution
- AD integration validation

### System Health
- Disk space monitoring (Warning: <20%, Critical: <10%)
- Memory utilization tracking
- System uptime (Warning: >35 days, Critical: >45 days)
- Performance counter analysis

### Storage Health
- Event log analysis for disk errors (IDs: 7, 11, 15, 153)
- Disk performance monitoring
- Queue length analysis
- Bad sector detection

### Security Services
- **Trellix ENS**: Service status and DAT version monitoring
- **Splunk**: Universal Forwarder service health
- **Windows Updates**: Last patch installation tracking
- **Certificates**: Expiration monitoring (90/30 day warnings)

### Hyper-V Infrastructure
- Virtual machine status and health
- Integration services validation
- Host resource utilization
- Virtual disk health monitoring
- Backup job status verification

### Critical Services
- Time synchronization validation
- Print spooler health
- System file integrity checks
- Registry monitoring

## Output

### HTML Report
- Executive summary with status counts
- Color-coded dashboard (Critical/Warning/Info/Pass)
- Detailed results table with timestamps
- System overview and recommendations

### CSV Export
- Raw data for historical analysis
- Suitable for importing into monitoring systems
- Trend analysis and reporting

### Event Log Integration
- Windows Application Event Log entries
- Event IDs: 1001 (Info), 2001 (Warning), 3001 (Error)
- Source: "HealthCheck"
- STIG-compliant audit trail

## Customization

### Adding Custom Checks
Extend the script by adding new functions following the pattern:

```powershell
function Test-CustomHealth {
    param([string[]]$ComputerNames)

    foreach ($Computer in $ComputerNames) {
        # Your custom health check logic
        Add-HealthResult -ComputerName $Computer -Component "Custom" -Check "YourCheck" -Status "Pass" -Message "Custom check passed"
    }
}
```

### Modifying Thresholds
Update `Config\settings.json` with your environment-specific values.

## Troubleshooting

### Common Issues

**"Cannot connect to LDAP port 389"**
- Verify network connectivity to domain controllers
- Check Windows Firewall settings
- Ensure LDAP service is running

**"Failed to import required modules"**
- Install RSAT-AD-PowerShell feature
- Verify Hyper-V role installation (if applicable)
- Run as Administrator

**"Access Denied" errors**
- Ensure running account has administrative privileges
- Verify WMI permissions for remote computers
- Check firewall settings for WMI traffic

### Event Log Monitoring
Monitor the Application Event Log for script execution details:
```powershell
Get-WinEvent -FilterHashtable @{LogName='Application'; ProviderName='HealthCheck'}
```

## Security Considerations

- Script designed for STIG-compliant environments
- No credentials stored in script files
- Uses current user's security context
- Audit trail maintained via Event Log
- Network traffic limited to administrative protocols

## Support

For issues and feature requests, please refer to your organization's IT support procedures.

## Version History

- **1.0.0**: Initial release with comprehensive health checking capabilities

## License

MIT License - See LICENSE file for details.