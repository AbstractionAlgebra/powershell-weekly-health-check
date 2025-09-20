# PowerShell Weekly Health Check - Troubleshooting Guide

## Connection Methods and DISA STIG Configuration

This guide explains how the PowerShell Weekly Health Check script connects to remote systems and what configurations are required for DISA STIG environments.

## Connection Methods Used

The script uses a **dual-layered connection approach** with automatic fallbacks:

### 1. Primary: WinRM (Windows Remote Management)
- **Port**: 5985 (HTTP)
- **Function**: `Test-WinRMConnectivity` at line 235
- **Usage**: `Invoke-Command` for remote script execution
- **Timeout**: 15 seconds (configurable via `WinRMTimeoutSeconds`)
- **Retry Logic**: 2 attempts with 2-second delays

### 2. Fallback: WMI (Windows Management Instrumentation)
- **Protocol**: DCOM over RPC
- **Timeout**: 30 seconds (configurable via `WMITimeoutSeconds`)
- **Usage**: `Get-WmiObject` calls for basic system information

### 3. Basic Connectivity Tests
- **LDAP**: Port 389 for domain controller connectivity
- **Network**: `Test-NetConnection` for general reachability

## Required DISA STIG Configurations

### WinRM Service Configuration
```powershell
# Enable WinRM service
Enable-PSRemoting -Force

# Configure WinRM for domain authentication
winrm set winrm/config/service/auth '@{Kerberos="true";Negotiate="true"}'
winrm set winrm/config/client/auth '@{Kerberos="true";Negotiate="true"}'

# Set memory limits (STIG compliant)
winrm set winrm/config/winrs '@{MaxMemoryPerShellMB="2048"}'
```

### Windows Firewall Rules
```powershell
# Enable WinRM firewall rules
Enable-NetFirewallRule -DisplayGroup "Windows Remote Management"

# Or create custom rules:
New-NetFirewallRule -DisplayName "WinRM-In" -Direction Inbound -Protocol TCP -LocalPort 5985
```

### Group Policy Settings (GPO)
- **Computer Configuration > Administrative Templates > Windows Components > Windows Remote Management**
  - Allow remote server management through WinRM: **Enabled**
  - Allow Basic authentication: **Disabled** (STIG requirement)
  - Allow unencrypted traffic: **Disabled** (STIG requirement)

### Service Account Permissions
The script requires accounts with:
- **Local Administrator** rights on target systems
- **Domain Admin** privileges for AD health checks
- **Log on as a service** right for scheduled execution

### DCOM/WMI Configuration
```powershell
# Set DCOM authentication level
dcomcnfg.exe
# Navigate to Component Services > Computers > My Computer > DCOM Config
# Configure "Windows Management Instrumentation" for authentication
```

## Network Security Considerations

### Ports Required (add to firewall allow-lists):
- **5985**: WinRM HTTP
- **135**: RPC Endpoint Mapper
- **445**: SMB (for file system access)
- **389**: LDAP (Active Directory)
- **Dynamic RPC**: Ports 1024-49151 (or configure static endpoint)

### Authentication Flow:
1. **Kerberos** (preferred in domain environments)
2. **NTLM** (fallback, may be restricted in STIG environments)
3. **No credential delegation** (follows least-privilege principle)

## Air-Gapped Environment Considerations

Since this runs in an air-gapped network:

1. **DNS Resolution**: Ensure internal DNS properly resolves all computer names
2. **Time Synchronization**: Critical for Kerberos authentication - verify NTP configuration
3. **Certificate Validation**: May need to configure trusted root CAs for internal certificates
4. **WSUS**: Configure internal Windows Update services if checking update compliance

## Potential STIG Conflicts

The script may encounter issues with these STIG controls:
- **WinRM HTTP**: Some STIGs require HTTPS-only (port 5986)
- **NTLM Restrictions**: May need Kerberos-only configuration
- **RPC Hardening**: Dynamic port ranges may be restricted
- **PowerShell Constrained Language Mode**: May limit script functionality

## Recommended STIG-Compliant Modifications

```powershell
# Force HTTPS WinRM (modify in script)
$portTestResult = Test-NetConnection -ComputerName $ComputerName -Port 5986

# Use CIM instead of WMI where possible
Get-CimInstance -ClassName Win32_OperatingSystem -ComputerName $Computer
```

## Common Troubleshooting Steps

### Connection Issues
1. **Test WinRM connectivity manually**:
   ```powershell
   Test-WSMan -ComputerName <target-computer>
   ```

2. **Verify firewall rules**:
   ```powershell
   Get-NetFirewallRule -DisplayGroup "Windows Remote Management" | Select-Object DisplayName, Enabled
   ```

3. **Check service status**:
   ```powershell
   Get-Service WinRM
   ```

### Authentication Issues
1. **Verify Kerberos tickets**:
   ```powershell
   klist tickets
   ```

2. **Test domain connectivity**:
   ```powershell
   Test-ComputerSecureChannel -Verbose
   ```

3. **Check time synchronization**:
   ```powershell
   w32tm /query /status
   ```

### Permission Issues
1. **Verify local admin rights**:
   ```powershell
   ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")
   ```

2. **Test WMI access**:
   ```powershell
   Get-WmiObject -Class Win32_OperatingSystem -ComputerName <target-computer>
   ```

## Script Behavior Notes

The script is designed to gracefully handle connectivity failures and will skip checks when WinRM is unavailable, making it suitable for restrictive STIG environments where some services may be disabled.

When WinRM is not available, you'll see messages like:
- "DNS zone check skipped - WinRM not available"
- "Event log check skipped - WinRM not available"
- "Certificate check skipped - WinRM not available"

This allows the script to continue running and perform what checks it can with the available connectivity methods.