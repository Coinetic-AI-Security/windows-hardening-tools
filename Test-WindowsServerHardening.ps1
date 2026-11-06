<#PSScriptInfo
.VERSION 1.0.0
.GUID 6f4b1f3e-2c8a-4d57-9a61-3b0e7c5d9a21
.AUTHOR Coinetic AI Security - https://coinetic.io
.COMPANYNAME Coinetic AI Security
.COPYRIGHT (c) 2026 Salus Alpha Group AG. MIT licence.
.TAGS Coinetic Windows WindowsServer Security Hardening Firewall RDP SMB Audit Checklist CIS
.LICENSEURI https://github.com/Coinetic-AI-Security/windows-hardening-tools/blob/main/LICENSE
.PROJECTURI https://github.com/Coinetic-AI-Security/windows-hardening-tools
.ICONURI https://coinetic.io/logo-192.png
.RELEASENOTES First release: firewall, open ports, RDP, SMB, updates, accounts and logging checks.
#>

<#
.SYNOPSIS
    Read-only hardening check for Windows Servers and PCs (firewall, open ports, RDP, SMB, updates, accounts, logging).

    Free tool by Coinetic AI Security - https://coinetic.io

.DESCRIPTION
    Runs the network and logon checks of the Windows Server hardening checklist
    (https://coinetic.io/windows-server-hardening-checklist) and shows OK / WARN / INFO for each point,
    with a link to the explanation and the fix.

    The script CHANGES NOTHING. It only reads settings with built-in Windows commands, so it is safe on
    production Servers. It works on every Windows display language (no text output of Windows tools is parsed).

    Run it as administrator for all checks; without administrator rights a few checks are skipped.

.PARAMETER PassThru
    Also return the results as objects (for Export-Csv, ConvertTo-Json, ...).

.PARAMETER Quiet
    Do not print the report; only return the objects (implies -PassThru).

.EXAMPLE
    .\Test-WindowsServerHardening.ps1

.EXAMPLE
    .\Test-WindowsServerHardening.ps1 -Quiet | Export-Csv hardening.csv -NoTypeInformation

.LINK
    https://coinetic.io

.LINK
    https://coinetic.io/windows-server-hardening-checklist
#>
[CmdletBinding()]
param([switch]$PassThru, [switch]$Quiet)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
$Guide = 'https://coinetic.io/windows-server-hardening-checklist'
$Results = New-Object System.Collections.Generic.List[object]

function Add-Result([string]$Section, [string]$Check, [string]$Status, [string]$Severity, [string]$Detail, [string]$Anchor) {
    $Results.Add([pscustomobject]@{
        Section = $Section; Check = $Check; Status = $Status; Severity = $Severity
        Detail = $Detail; Link = if ($Anchor) { "$Guide#$Anchor" } else { '' }
    })
}
# run one check; an unexpected error becomes SKIP instead of stopping the whole report
function Invoke-Check([string]$Section, [string]$Check, [string]$Anchor, [scriptblock]$Body) {
    try { & $Body } catch { Add-Result $Section $Check 'SKIP' '' ("Could not check: " + $_.Exception.Message) $Anchor }
}
function Get-RegValue([string]$Path, [string]$Name) {
    try { (Get-ItemProperty -Path $Path -Name $Name -ErrorAction Stop).$Name } catch { $null }
}

$IsAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
$Os = Get-CimInstance Win32_OperatingSystem
$Cs = Get-CimInstance Win32_ComputerSystem
$IsServer = $Os.ProductType -ne 1                 # 1 = workstation, 2 = domain controller, 3 = server
$IsDC = $Cs.DomainRole -ge 4                      # 4 / 5 = backup / primary domain controller
$Build = [int]$Os.BuildNumber

# ---------------------------------------------------------------- 1. Updates and a small attack surface
Invoke-Check 'Updates' 'Supported Windows version' 'updates' {
    # end of extended support (Microsoft lifecycle); unknown builds are only shown
    $eos = @{ 14393 = '2027-01-12'; 17763 = '2029-01-09'; 20348 = '2031-10-14'; 26100 = '2034-10-10' }
    $name = "$($Os.Caption) (build $Build)"
    if ($Build -lt 10240) { Add-Result 'Updates' 'Supported Windows version' 'WARN' 'High' "${name}: no more security updates (without paid Extended Security Updates). Plan the upgrade." 'updates' }
    elseif (-not $IsServer -and $Build -lt 22000) { Add-Result 'Updates' 'Supported Windows version' 'WARN' 'High' "${name}: Windows 10 support ended on 2025-10-14 (only with Extended Security Updates)." 'updates' }
    elseif ($IsServer -and $eos.ContainsKey($Build)) {
        $end = [datetime]::ParseExact($eos[$Build], 'yyyy-MM-dd', [Globalization.CultureInfo]::InvariantCulture)
        $days = ($end - (Get-Date)).Days
        if ($days -lt 0) { Add-Result 'Updates' 'Supported Windows version' 'WARN' 'High' "${name}: support ended on $($eos[$Build])." 'updates' }
        elseif ($days -lt 365) { Add-Result 'Updates' 'Supported Windows version' 'WARN' 'Medium' "${name}: support ends on $($eos[$Build]) - plan the upgrade." 'updates' }
        else { Add-Result 'Updates' 'Supported Windows version' 'OK' '' "$name, supported until $($eos[$Build])." 'updates' }
    }
    else { Add-Result 'Updates' 'Supported Windows version' 'INFO' '' "$name - keep feature updates current (Settings > Windows Update)." 'updates' }
}

Invoke-Check 'Updates' 'Security updates installed recently' 'updates' {
    $last = $null
    try {   # Windows Update history: the newest successfully installed update (ResultCode 2 = succeeded)
        $s = (New-Object -ComObject Microsoft.Update.Session).CreateUpdateSearcher()
        $n = $s.GetTotalHistoryCount()
        if ($n -gt 0) { $last = $s.QueryHistory(0, [Math]::Min($n, 200)) | Where-Object { $_.ResultCode -eq 2 -and $_.Operation -eq 1 } | Sort-Object Date -Descending | Select-Object -First 1 -ExpandProperty Date }
    } catch { }
    if (-not $last) { $last = Get-HotFix | Where-Object { $_.InstalledOn } | Sort-Object InstalledOn -Descending | Select-Object -First 1 -ExpandProperty InstalledOn }
    if (-not $last) { Add-Result 'Updates' 'Security updates installed recently' 'WARN' 'Medium' 'No installed update found in the update history.' 'updates'; return }
    $age = [int]((Get-Date) - $last.ToLocalTime()).TotalDays
    if ($age -gt 45) { Add-Result 'Updates' 'Security updates installed recently' 'WARN' 'High' "Last update installed $age days ago ($($last.ToString('yyyy-MM-dd'))). Microsoft releases security updates every month." 'updates' }
    else { Add-Result 'Updates' 'Security updates installed recently' 'OK' '' "Last update installed $age days ago ($($last.ToString('yyyy-MM-dd')))." 'updates' }
}

Invoke-Check 'Updates' 'Print Spooler on a domain controller' 'updates' {
    if (-not $IsDC) { Add-Result 'Updates' 'Print Spooler on a domain controller' 'OK' '' 'Not a domain controller.' 'updates'; return }
    $sp = Get-Service -Name Spooler -ErrorAction SilentlyContinue
    if ($sp -and $sp.Status -eq 'Running') { Add-Result 'Updates' 'Print Spooler on a domain controller' 'WARN' 'High' 'The Print Spooler runs on this domain controller. Microsoft recommends disabling it (PrintNightmare).' 'updates' }
    else { Add-Result 'Updates' 'Print Spooler on a domain controller' 'OK' '' 'Print Spooler is not running.' 'updates' }
}

# ---------------------------------------------------------------- 2. Windows Firewall
Invoke-Check 'Firewall' 'Firewall on, inbound blocked' 'firewall' {
    foreach ($p in Get-NetFirewallProfile -PolicyStore ActiveStore) {   # ActiveStore = what really applies (incl. Group Policy)
        $on = "$($p.Enabled)" -eq 'True'
        $block = @('Block', 'NotConfigured') -contains "$($p.DefaultInboundAction)"
        if (-not $on) { Add-Result 'Firewall' "Profile $($p.Name)" 'WARN' 'High' "The firewall is OFF for the $($p.Name) profile." 'firewall' }
        elseif (-not $block) { Add-Result 'Firewall' "Profile $($p.Name)" 'WARN' 'High' "The $($p.Name) profile ALLOWS all inbound connections by default." 'firewall' }
        else { Add-Result 'Firewall' "Profile $($p.Name)" 'OK' '' 'On, inbound blocked unless a rule allows it.' 'firewall' }
    }
}

Invoke-Check 'Firewall' 'Network profile' 'firewall' {
    $profiles = @(Get-NetConnectionProfile -ErrorAction SilentlyContinue)
    if ($profiles.Count -eq 0) { Add-Result 'Firewall' 'Network profile' 'INFO' '' 'No network connection profile found.' 'firewall'; return }
    $list = ($profiles | ForEach-Object { "$($_.InterfaceAlias): $($_.NetworkCategory)" }) -join ', '
    if ($Cs.PartOfDomain -and ($profiles | Where-Object { "$($_.NetworkCategory)" -ne 'DomainAuthenticated' })) {
        Add-Result 'Firewall' 'Network profile' 'WARN' 'Medium' "Domain member, but not every network is 'DomainAuthenticated' ($list) - other firewall rules apply there." 'firewall'
    } else { Add-Result 'Firewall' 'Network profile' 'OK' '' $list 'firewall' }
}

# ---------------------------------------------------------------- 3. Open ports: listening AND allowed from any address
$RdpPort = Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' 'PortNumber'
if (-not $RdpPort) { $RdpPort = 3389 }
$Risky = @{ 21 = @('FTP', 'Medium'); 23 = @('Telnet', 'High'); 135 = @('RPC', 'Medium'); 139 = @('NetBIOS / SMB', 'High'); 445 = @('SMB / file sharing', 'High')
    1433 = @('SQL Server', 'Medium'); 3306 = @('MySQL / MariaDB', 'Medium'); 5432 = @('PostgreSQL', 'Medium'); 5985 = @('WinRM (remote PowerShell)', 'Medium'); 5986 = @('WinRM over HTTPS', 'Medium') }
$Risky[[int]$RdpPort] = @('Remote Desktop', 'High')
5900..5910 | ForEach-Object { $Risky[$_] = @('VNC', 'High') }

Invoke-Check 'Open ports' 'Admin ports open to any address' 'ports' {
    $listen = @(Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue | Where-Object { $_.LocalAddress -notmatch '^(127\.|::1$)' } | Select-Object -ExpandProperty LocalPort -Unique)
    # enabled inbound allow rules whose remote address is Any, with their TCP ports
    # only rules for a network profile that is in use now (Domain / Private / Public)
    $active = @(Get-NetConnectionProfile -ErrorAction SilentlyContinue | ForEach-Object { switch ("$($_.NetworkCategory)") { 'DomainAuthenticated' { 'Domain' } 'Private' { 'Private' } default { 'Public' } } } | Select-Object -Unique)
    if ($active.Count -eq 0) { $active = @('Domain', 'Private', 'Public') }
    $rules = @{}
    Get-NetFirewallRule -Enabled True -Direction Inbound -Action Allow -PolicyStore ActiveStore | Where-Object {
        $p = "$($_.Profile)"; $p -eq 'Any' -or @($active | Where-Object { $p -match $_ }).Count -gt 0
    } | ForEach-Object { $rules[$_.InstanceID] = $_ }
    $anyAddr = @{}; Get-NetFirewallAddressFilter -PolicyStore ActiveStore | Where-Object { $rules.ContainsKey($_.InstanceID) -and (@($_.RemoteAddress) -contains 'Any') } | ForEach-Object { $anyAddr[$_.InstanceID] = $true }
    $open = @{}
    foreach ($pf in Get-NetFirewallPortFilter -PolicyStore ActiveStore) {
        if (-not $anyAddr.ContainsKey($pf.InstanceID) -or @('TCP', 'Any') -notcontains "$($pf.Protocol)") { continue }
        foreach ($lp in @($pf.LocalPort)) {
            $ports = @()
            if ($lp -match '^\d+$') { $ports = @([int]$lp) }
            elseif ($lp -match '^(\d+)-(\d+)$') { $ports = [int]$Matches[1]..[int]$Matches[2] | Where-Object { $Risky.Contains($_) } }
            elseif ($lp -eq 'RPCEPMap') { $ports = @(135) }
            foreach ($port in $ports) { if ($Risky.Contains($port) -and $listen -contains $port) { if (-not $open[$port]) { $open[$port] = @() }; $r = $rules[$pf.InstanceID]; $open[$port] += [pscustomobject]@{ Name = $r.DisplayName; Profile = "$($r.Profile)" } } }
        }
    }
    if ($open.Count -eq 0) { Add-Result 'Open ports' 'Admin ports open to any address' 'OK' '' 'No listening admin / database / remote-access port is allowed from any address.' 'ports'; return }
    foreach ($port in ($open.Keys | Sort-Object)) {
        $what = $Risky[$port]; $by = @($open[$port] | Sort-Object Name -Unique)
        $text = ($by | ForEach-Object { "$($_.Name) [$($_.Profile -replace ', ', '/')]" }) -join '; '
        # open only on the domain network (behind the company's own network): lower risk than Private / Public / Any
        $domainOnly = @($by | Where-Object { $_.Profile -ne 'Domain' }).Count -eq 0
        $sev = if ($domainOnly) { 'Low' } else { $what[1] }
        $note = if ($domainOnly) { ' Domain network only - fine inside a trusted LAN; make sure the domain network is never the internet side.' } else { " Limit the rule's remote addresses, or reach it through a VPN." }
        Add-Result 'Open ports' "Port $port ($($what[0]))" 'WARN' $sev ("Listening and allowed from ANY address by: $text." + $note + ' (Whether it is reachable from the internet also depends on your router.)') 'ports'
    }
}

# ---------------------------------------------------------------- 4. RDP
Invoke-Check 'RDP' 'Remote Desktop' 'rdp' {
    $ts = 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server'
    $deny = Get-RegValue $ts 'fDenyTSConnections'
    $denyPol = Get-RegValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' 'fDenyTSConnections'
    if ($null -ne $denyPol) { $deny = $denyPol }
    if ($deny -ne 0) { Add-Result 'RDP' 'Remote Desktop' 'OK' '' 'Remote Desktop is switched off.' 'rdp'; return }
    $nla = Get-RegValue "$ts\WinStations\RDP-Tcp" 'UserAuthentication'
    $nlaPol = Get-RegValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' 'UserAuthentication'
    if ($null -ne $nlaPol) { $nla = $nlaPol }
    if ($nla -eq 1) { Add-Result 'RDP' 'Network Level Authentication' 'OK' '' "Remote Desktop is on (port $RdpPort) with Network Level Authentication." 'rdp' }
    else { Add-Result 'RDP' 'Network Level Authentication' 'WARN' 'High' "Remote Desktop is on (port $RdpPort) WITHOUT Network Level Authentication: a session is created before the password is checked." 'rdp' }
    if ($RdpPort -ne 3389) { Add-Result 'RDP' 'RDP port' 'INFO' '' "RDP uses port $RdpPort. A different port only hides it from the laziest scanners; it is not a protection on its own." 'rdp' }
}

# ---------------------------------------------------------------- 5. SMB
Invoke-Check 'SMB' 'SMBv1' 'smb' {
    $svc = Get-Service -Name mrxsmb10 -ErrorAction SilentlyContinue           # the SMBv1 client driver
    $srv = Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' 'SMB1'
    $smb1Server = $null
    try { $smb1Server = (Get-SmbServerConfiguration).EnableSMB1Protocol } catch { if ($null -ne $srv) { $smb1Server = $srv -ne 0 } }
    if ($null -eq $smb1Server -and $Build -lt 16299) { $smb1Server = $true }   # older Windows: on unless switched off
    if ($smb1Server -eq $true) { Add-Result 'SMB' 'SMBv1 server' 'WARN' 'High' 'SMBv1 is enabled on the server side (WannaCry / EternalBlue). Check that no old device needs it, then switch it off.' 'smb' }
    else { Add-Result 'SMB' 'SMBv1 server' 'OK' '' 'SMBv1 server is off.' 'smb' }
    if ($svc) { Add-Result 'SMB' 'SMBv1 client' 'INFO' '' 'The SMBv1 client component is installed (mrxsmb10). Remove it when no old NAS or scanner needs it.' 'smb' }
}

Invoke-Check 'SMB' 'SMB signing' 'smb' {
    $req = Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' 'RequireSecuritySignature'
    if ($req -eq 1) { Add-Result 'SMB' 'SMB signing required' 'OK' '' 'The SMB server requires signing.' 'smb' }
    elseif ($IsDC) { Add-Result 'SMB' 'SMB signing required' 'WARN' 'High' 'This domain controller does not require SMB signing.' 'smb' }
    else { Add-Result 'SMB' 'SMB signing required' 'INFO' '' 'SMB signing is not required. Recommended on file Servers (Microsoft Security Baseline).' 'smb' }
}

# ---------------------------------------------------------------- 6. Accounts
Invoke-Check 'Accounts' 'Local accounts' 'accounts' {
    if ($IsDC) { Add-Result 'Accounts' 'Local accounts' 'INFO' '' 'Domain controller: no local accounts - check the domain accounts.' 'accounts'; return }
    $users = @(Get-LocalUser)
    $admin = $users | Where-Object { $_.SID.Value -like '*-500' }
    $guest = $users | Where-Object { $_.SID.Value -like '*-501' }
    if ($guest -and $guest.Enabled) { Add-Result 'Accounts' 'Guest account' 'WARN' 'High' 'The built-in Guest account is enabled.' 'accounts' }
    else { Add-Result 'Accounts' 'Guest account' 'OK' '' 'Guest account disabled.' 'accounts' }
    if ($admin -and $admin.Enabled) {
        Add-Result 'Accounts' 'Built-in Administrator' 'INFO' '' "The built-in administrator '$($admin.Name)' is enabled - its name is known, so it is the first one attackers try. Rename or disable it and use a named admin account." 'accounts'
    } else { Add-Result 'Accounts' 'Built-in Administrator' 'OK' '' 'Built-in administrator disabled or renamed.' 'accounts' }
}

Invoke-Check 'Accounts' 'Unique local admin passwords (LAPS)' 'accounts' {
    if (-not $Cs.PartOfDomain -or $IsDC) { Add-Result 'Accounts' 'Unique local admin passwords (LAPS)' 'INFO' '' 'Not a domain member Server/PC - use a unique, long local admin password.' 'accounts'; return }
    $win = (Get-RegValue 'HKLM:\SOFTWARE\Microsoft\Policies\LAPS' 'BackupDirectory'), (Get-RegValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\LAPS' 'BackupDirectory') | Where-Object { $null -ne $_ -and $_ -ne 0 }
    $legacy = Get-RegValue 'HKLM:\SOFTWARE\Policies\Microsoft Services\AdmPwd' 'AdmPwdEnabled'
    if ($win -or $legacy -eq 1) { Add-Result 'Accounts' 'Unique local admin passwords (LAPS)' 'OK' '' 'LAPS is configured.' 'accounts' }
    else { Add-Result 'Accounts' 'Unique local admin passwords (LAPS)' 'WARN' 'Medium' 'No LAPS policy found. The same local admin password on many machines lets an attacker move from one to all.' 'accounts' }
}

# ---------------------------------------------------------------- 7. Logging
if (-not ('HardeningCheck.Audit' -as [type])) {
    Add-Type -TypeDefinition @'
using System; using System.Runtime.InteropServices;
namespace HardeningCheck {
  public static class Audit {
    [StructLayout(LayoutKind.Sequential)] struct AUDIT_POLICY_INFORMATION { public Guid Sub; public uint Info; public Guid Cat; }
    [DllImport("advapi32.dll", SetLastError = true)] static extern bool AuditQuerySystemPolicy([In] Guid[] subs, uint count, out IntPtr policy);
    [DllImport("advapi32.dll")] static extern void AuditFree(IntPtr buffer);
    // 1 = success, 2 = failure, 3 = both, 0 = none; -1 = not readable (needs administrator)
    public static int Get(Guid sub) {
      IntPtr p; if (!AuditQuerySystemPolicy(new[] { sub }, 1, out p)) return -1;
      try { return (int)((AUDIT_POLICY_INFORMATION)Marshal.PtrToStructure(p, typeof(AUDIT_POLICY_INFORMATION))).Info & 3; } finally { AuditFree(p); }
    }
  }
}
'@
}

Invoke-Check 'Logging' 'Audit policy' 'logging' {
    if (-not $IsAdmin) { Add-Result 'Logging' 'Audit policy' 'SKIP' '' 'Needs administrator rights.' 'logging'; return }
    $need = [ordered]@{ 'Logon' = @('0CCE9215-69AE-11D9-BED3-505054503030', 3); 'Account Lockout' = @('0CCE9217-69AE-11D9-BED3-505054503030', 2)
        'Credential Validation' = @('0CCE923F-69AE-11D9-BED3-505054503030', 2); 'User Account Management' = @('0CCE9235-69AE-11D9-BED3-505054503030', 1) }
    $names = @{ 0 = 'No auditing'; 1 = 'Success'; 2 = 'Failure'; 3 = 'Success and Failure' }
    foreach ($k in $need.Keys) {
        $v = [HardeningCheck.Audit]::Get([guid]$need[$k][0]); $want = $need[$k][1]
        if ($v -lt 0) { Add-Result 'Logging' "Audit: $k" 'SKIP' '' 'Not readable.' 'logging' }
        elseif (($v -band $want) -eq $want) { Add-Result 'Logging' "Audit: $k" 'OK' '' $names[$v] 'logging' }
        else { Add-Result 'Logging' "Audit: $k" 'WARN' 'Medium' "$($names[$v]) - recommended: $($names[$want])." 'logging' }
    }
    $force = Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'SCENoApplyLegacyAuditPolicy'
    if ($force -ne 1) { Add-Result 'Logging' 'Advanced audit policy enforced' 'INFO' '' "'Force audit policy subcategory settings' is not set - old category settings can overwrite the advanced audit policy." 'logging' }
}

Invoke-Check 'Logging' 'Security log size' 'logging' {
    $bytes = $null
    $pol = Get-RegValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security' 'MaxSize'          # KB, set by Group Policy
    if ($pol) { $bytes = [int64]$pol * 1KB } else { $bytes = Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Security' 'MaxSize' }
    if (-not $bytes) { Add-Result 'Logging' 'Security log size' 'SKIP' '' 'Size not readable.' 'logging'; return }
    $mb = [int]($bytes / 1MB)
    if ($mb -lt 192) { Add-Result 'Logging' 'Security log size' 'WARN' $(if ($IsServer) { 'Medium' } else { 'Low' }) "$mb MB - on a busy machine that covers only hours or days. Microsoft's baseline: at least 192 MB." 'logging' }
    else { Add-Result 'Logging' 'Security log size' 'OK' '' "$mb MB." 'logging' }
}

# ---------------------------------------------------------------- 8. Backups (cannot be checked from here)
Add-Result 'Backups' 'Offline / immutable backup' 'INFO' '' 'Not checkable by a script: keep at least one copy the domain admin password cannot reach, and test a restore.' 'backups'

# ---------------------------------------------------------------- report
if (-not $Quiet) {
    $colors = @{ OK = 'Green'; WARN = 'Yellow'; INFO = 'Cyan'; SKIP = 'DarkGray' }
    Write-Host ''
    Write-Host "Windows hardening check - $env:COMPUTERNAME - $($Os.Caption) - $(Get-Date -Format 'yyyy-MM-dd HH:mm')" -ForegroundColor White
    if (-not $IsAdmin) { Write-Host 'Not running as administrator: some checks are skipped.' -ForegroundColor DarkYellow }
    foreach ($g in $Results | Group-Object Section) {
        Write-Host ''; Write-Host $g.Name -ForegroundColor White
        foreach ($r in $g.Group) {
            $sev = if ($r.Severity) { " [$($r.Severity)]" } else { '' }
            Write-Host ('  {0,-5}' -f $r.Status) -ForegroundColor $colors[$r.Status] -NoNewline
            Write-Host (" {0}{1}: {2}" -f $r.Check, $sev, $r.Detail)
            if ($r.Status -eq 'WARN') { Write-Host "        How to fix: $($r.Link)" -ForegroundColor DarkGray }
        }
    }
    $w = @($Results | Where-Object Status -eq 'WARN')
    Write-Host ''
    Write-Host ("{0} OK, {1} warnings ({2} high), {3} info, {4} skipped." -f @($Results | Where-Object Status -eq 'OK').Count, $w.Count, @($w | Where-Object Severity -eq 'High').Count, @($Results | Where-Object Status -eq 'INFO').Count, @($Results | Where-Object Status -eq 'SKIP').Count) -ForegroundColor White
    Write-Host 'This is a one-time check - settings drift with every update, installer and quick test.'
    Write-Host 'Coinetic AI Security watches them continuously, bans attackers and alerts you: https://coinetic.io (30 days free)' -ForegroundColor DarkGray
    Write-Host ''
}
if ($PassThru -or $Quiet) { $Results }
