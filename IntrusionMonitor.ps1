#requires -version 5.1
<#
================================================================================
 INTRUSION MONITOR
 A host-based early-warning sensor for autonomous-scanner / ARTEX-style activity.

 WHAT IT IS
   A single PowerShell script. No install. Runs as a normal user (does more if
   elevated). Watches THIS PC only - what your own machine can legitimately see
   - and raises a large, high-contrast alert the moment something looks wrong.
   Serious alerts pop an interactive window showing where the connection comes
   from (country / ISP / owner) with a "Disconnect & Block" button.

 WHAT IT CANNOT DO
   On a switched / Wi-Fi network your PC does not see traffic between OTHER
   machines. This detects activity against *this host*, plus this host talking
   to known-bad infrastructure. It is a host sensor, not a network tap.

 DETECTIONS
   Standard user : own outbound connections vs known-bad IPs; DNS cache vs
                   known-bad domains / "artex" strings; canary tripwire; new
                   ARP neighbours (informational); incoming TCP connections
                   counted per source address.
   Elevated adds : firewall log -> every refused (and allowed) inbound attempt
                   counted per source address and port, port-scan detection,
                   repeated-attempt alerts; a decoy SMB share; and the
                   Disconnect & Block action.

 WHERE A CONNECTION COMES FROM
   This PC       127.0.0.1, ::1 and this PC's own addresses - apps on this
                 computer talking to each other. Listed, never alarmed.
   Home network  192.168.x.x, 10.x.x.x, 172.16-31.x.x and similar. Listed;
                 a scan or repeated refusals gives an amber warning only.
   Internet      everything else. Can raise the red alarm and the pop-up.

 CONNECTION LOGS (logs folder)
   Connections_YYYYMMDD.csv  one line per incoming attempt: time, source
                             address, where from, port, protocol, refused/allowed
   ConnectionSummary.csv     one line per source address: attempts, refused,
                             allowed, every port tried with a count
   The Connections button shows the same table live.

 USAGE
   IntrusionMonitor.vbs             starts silently, minimised (recommended)
   Run-IntrusionMonitor.cmd         standard user (detect + alert; no blocking)
   Run-IntrusionMonitor-Admin.cmd   elevated (adds port-scan + decoy + blocking)
   Close the window, or press Stop, to end it.
================================================================================
#>

param(
    # Self-test: read a saved firewall log, write the connection logs, print the counts.
    [string]$TestFirewallLog,
    # Self-test only: also open the Connections window on the test data.
    [switch]$ShowConnections
)

# ---------------------------------------------------------------------------
# CONFIG  - safe to edit
# ---------------------------------------------------------------------------
$Config = [ordered]@{
    ScanIntervalSeconds   = 10
    AlertCooldownSeconds  = 300
    Logging               = $true
    LogDir                = "$PSScriptRoot\logs"

    CanaryEnabled         = $true
    CanaryDir             = "$env:USERPROFILE\Documents\_IntrusionMonitor_DoNotTouch"
    CanaryBaitName        = "ACCOUNTS_BACKUP.txt"

    ArpWatchEnabled       = $true

    LlmEgressAlert        = $false

    # geo / owner lookup for source IPs (needs internet; free tier, rate-limited)
    IpLookupEnabled       = $true
    IpLookupUrl           = 'http://ip-api.com/json/{0}?fields=status,country,regionName,city,isp,org,as,query'
    IpLookupTimeoutSec    = 4

    # active response (elevated only)
    AutoBlockOnHigh       = $false    # auto-block without asking? default NO - use the button
    BlockBothDirections   = $true     # block inbound AND outbound to the IP
    FirewallGroup         = 'IntrusionMonitor'
    AutoElevate           = $false    # if not elevated, relaunch elevated on start (UAC prompt each time)

    # elevated firewall log / port scan
    AutoEnableFwLogging   = $true
    FwLogPath             = "$env:windir\system32\LogFiles\Firewall\pfirewall.log"
    FwLogMaxKB            = 16384     # firewall log size before Windows rolls it over
    PortScanDistinctPorts = 15
    PortScanWindowSeconds = 60
    ShareDecoyEnabled     = $true
    ShareDecoyName        = "Backups"

    # incoming connection counter
    TrackInbound          = $true     # count incoming attempts per source address and port
    LogAllowedInbound     = $true     # elevated: also count attempts the firewall let through
    IgnoreBroadcast       = $true     # skip LAN broadcast/multicast chatter (NetBIOS, SSDP, mDNS)
    CountThisPc           = $true     # list this PC's own apps (127.0.0.1 etc) - they never alarm
    AlertOnHomeNetwork    = $true     # home-network devices: amber warning (no pop-up) on scans/refusals
    DroppedAlertThreshold = 25        # warn once an address has been refused this many times

    # appearance (high contrast / low glare)
    BackColor             = "#101010"
    TextColor             = "#FFD400"
    HighColor             = "#FF4C4C"
    MedColor              = "#FFB000"
    ThisPcColor           = "#C8C8C8" # rows for this PC's own apps
    FontName              = "Consolas"
    FontSize              = 14
    AlertBalloons         = $true
    StartMinimized        = $true     # launch minimised; pop to front only when a HIGH alert fires
}

# ---------------------------------------------------------------------------
# KNOWN INDICATORS  (public reporting, Oct-Nov 2026 - will age)
# ---------------------------------------------------------------------------
$Indicators = @{
    BadIPs = @(
        '38.244.50.120','101.53.80.20','205.214.59.31','124.155.252.63',
        '154.201.79.246','23.248.249.90','23.158.220.98','103.248.148.84',
        '203.160.133.172','209.209.85.38','130.94.31.86','156.251.11.39',
        '23.248.226.250'
    )
    BadDomains = @('xcai.pro')
    BadStrings = @('artex','artx','/.claude/claude.md','autonomous penetration')
    LlmDomains = @('api.deepseek.com','api.anthropic.com','api.openai.com','api.x.ai',
                   'open.bigmodel.cn','generativelanguage.googleapis.com','openrouter.ai')
}

# ===========================================================================
#   Implementation
# ===========================================================================
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

$script:IsAdmin = ([Security.Principal.WindowsPrincipal] `
    [Security.Principal.WindowsIdentity]::GetCurrent()
    ).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
$script:ScriptPath = $PSCommandPath

$script:LastAlert    = @{}
$script:ArpBaseline  = $null
$script:FwPos        = -1           # read position in the firewall log (-1 = start at the end)
$script:FwTail       = ''           # part-line carried over to the next read
$script:FwReadable   = $false
$script:Inbound      = @{}          # source address -> attempt record
$script:TcpSeen      = @{}
$script:AttemptBuf   = New-Object System.Collections.Generic.List[string]
$script:SummaryDirty = $false
$script:InboundNoted = $false
$script:SelfIps      = @()
$script:TestMode     = [bool]$TestFirewallLog
$script:CanaryQueue  = [System.Collections.Queue]::Synchronized((New-Object System.Collections.Queue))
$script:FirstSweep   = $true
$script:Paused       = $false
$script:IpCache      = @{}
$script:AllowList    = @()          # IPs we must never block (self, gateway, loopback)

function Write-Log {
    param([string]$Line)
    if (-not $Config.Logging) { return }
    try {
        if (-not (Test-Path $Config.LogDir)) { New-Item -ItemType Directory -Path $Config.LogDir -Force | Out-Null }
        $f = Join-Path $Config.LogDir ("IntrusionMonitor_{0:yyyyMMdd}.log" -f (Get-Date))
        Add-Content -Path $f -Value $Line -Encoding UTF8
    } catch { }
}

function Test-PrivateIp {
    param([string]$ip)
    return ($ip -match '^(10\.|127\.|169\.254\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[0-1])\.|fe[89ab][0-9a-f]:|f[cd][0-9a-f]{2}:)')
}

function Get-Origin {
    # This PC / Home network / Internet
    param([string]$Ip)
    if ($Ip -match '^(127\.|0\.0\.0\.0$|::1$|::$)') { return 'This PC' }
    if ($script:SelfIps -contains $Ip) { return 'This PC' }
    if (Test-PrivateIp $Ip) { return 'Home network' }
    return 'Internet'
}

function Build-AllowList {
    $list = @('127.0.0.1','::1')
    try { $list += (Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue | Select-Object -ExpandProperty NextHop) } catch {}
    try { $list += (Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue | Select-Object -ExpandProperty IPAddress) } catch {}
    $script:AllowList = $list | Where-Object { $_ } | Select-Object -Unique
    try { $script:SelfIps = @(Get-NetIPAddress -ErrorAction SilentlyContinue | Select-Object -ExpandProperty IPAddress) } catch { $script:SelfIps = @() }
}

function Get-IpInfo {
    param([string]$ip)
    if ($script:IpCache.ContainsKey($ip)) { return $script:IpCache[$ip] }
    if (Test-PrivateIp $ip) {
        $r = [pscustomobject]@{ One = "Local / private network ($ip)"; Full = "$ip is on your own local network (not an internet host)." }
        $script:IpCache[$ip] = $r; return $r
    }
    $r = [pscustomobject]@{ One = "$ip (lookup unavailable)"; Full = "$ip`nLookup unavailable (no internet, or rate-limited)." }
    if ($Config.IpLookupEnabled) {
        try {
            $u = $Config.IpLookupUrl -f $ip
            $j = Invoke-RestMethod -Uri $u -TimeoutSec $Config.IpLookupTimeoutSec -ErrorAction Stop
            if ($j.status -eq 'success') {
                $loc = (@($j.city,$j.regionName,$j.country) | Where-Object { $_ }) -join ', '
                $r = [pscustomobject]@{
                    One  = "$($j.country) / $($j.isp)"
                    Full = "IP:    $ip`nWhere: $loc`nISP:   $($j.isp)`nOwner: $($j.org)`nAS:    $($j.as)"
                }
            }
        } catch { }
    }
    $script:IpCache[$ip] = $r
    return $r
}

function Clear-Blocks {
    if (-not $script:IsAdmin) { return }
    try {
        Get-NetFirewallRule -Group $Config.FirewallGroup -ErrorAction SilentlyContinue | Remove-NetFirewallRule -ErrorAction SilentlyContinue
        Raise-Alert INFO 'Blocks cleared' "All Intrusion Monitor firewall blocks removed."
    } catch { Write-Log "[unblock] $($_.Exception.Message)" }
}

function Invoke-Elevate {
    # relaunch this script with admin rights (UAC prompt). On success, close this instance.
    try {
        Start-Process -FilePath 'powershell.exe' -Verb RunAs -ErrorAction Stop -ArgumentList @(
            '-NoProfile','-ExecutionPolicy','Bypass','-STA','-WindowStyle','Hidden','-File', $script:ScriptPath)
        if ($form) { $form.Close() }
    } catch {
        [System.Windows.Forms.MessageBox]::Show("Elevation was cancelled - still running without admin.","Intrusion Monitor") | Out-Null
    }
}

function Disconnect-Ip {
    param([string]$ip)
    if (-not $script:IsAdmin) {
        [System.Windows.Forms.MessageBox]::Show("Blocking needs admin rights - press Elevate first.","Intrusion Monitor") | Out-Null
        return
    }
    if ($script:AllowList -contains $ip -or (Get-Origin $ip) -eq 'This PC') {
        [System.Windows.Forms.MessageBox]::Show("$ip is this PC or your own gateway - not blocking it (that would cut you off).","Intrusion Monitor") | Out-Null
        return
    }
    $ts = Get-Date -Format 'yyyyMMdd-HHmmss'
    try {
        New-NetFirewallRule -DisplayName "IM-Block-IN-$ip-$ts" -Group $Config.FirewallGroup -Direction Inbound  -RemoteAddress $ip -Action Block -Profile Any -ErrorAction Stop | Out-Null
        if ($Config.BlockBothDirections) {
            New-NetFirewallRule -DisplayName "IM-Block-OUT-$ip-$ts" -Group $Config.FirewallGroup -Direction Outbound -RemoteAddress $ip -Action Block -Profile Any -ErrorAction Stop | Out-Null
        }
        Raise-Alert HIGH 'Blocked' "Firewall now dropping all traffic to/from $ip."
    } catch {
        Write-Log "[block] $($_.Exception.Message)"
        [System.Windows.Forms.MessageBox]::Show("Block failed: $($_.Exception.Message)","Intrusion Monitor") | Out-Null
    }
}

# -------- alert pipeline ------------------------------------------------------
function Raise-Alert {
    param(
        [ValidateSet('HIGH','MED','INFO')]$Severity,
        [string]$Category,
        [string]$Detail,
        [string]$DedupKey,
        [string]$Ip,
        [string]$Direction
    )
    $key = if ($DedupKey) { $DedupKey } else { "$Category|$Detail" }
    $now = Get-Date
    if ($script:LastAlert.ContainsKey($key)) {
        if (($now - $script:LastAlert[$key]).TotalSeconds -lt $Config.AlertCooldownSeconds) { return }
    }
    $script:LastAlert[$key] = $now

    $stamp = $now.ToString('HH:mm:ss')
    $line  = "[{0}] {1,-4} {2}: {3}" -f $stamp, $Severity, $Category, $Detail
    Write-Log $line
    if ($script:TestMode) { return }
    if ($Ip -and $Severity -eq 'HIGH') {
        $liFull = (Get-IpInfo $Ip).Full -replace "`r?`n", "; "
        $liDir  = if ($Direction) { "$Direction; " } else { "" }
        Write-Log ("           source -> " + $liDir + $liFull)
    }

    if ($script:LogBox) {
        $colour = switch ($Severity) { 'HIGH' {$Config.HighColor} 'MED' {$Config.MedColor} default {$Config.TextColor} }
        $script:LogBox.Invoke([Action]{
            $script:LogBox.SelectionStart = 0; $script:LogBox.SelectionLength = 0
            $script:LogBox.SelectionColor = [System.Drawing.ColorTranslator]::FromHtml($colour)
            $script:LogBox.SelectedText   = $line + "`n"
            $script:LogBox.SelectionStart = 0; $script:LogBox.ScrollToCaret()
        })
    }
    if ($Config.AlertBalloons -and $script:Tray -and $Severity -ne 'INFO') {
        $ico = if ($Severity -eq 'HIGH') { [System.Windows.Forms.ToolTipIcon]::Error } else { [System.Windows.Forms.ToolTipIcon]::Warning }
        try { $script:Tray.ShowBalloonTip(8000, "Intrusion Monitor - $Severity", "$Category`n$Detail", $ico) } catch {}
    }
    # pop the main window to the front on a HIGH alert (it launches minimised)
    if ($Severity -eq 'HIGH' -and $form -and $form.IsHandleCreated) {
        try { $form.Invoke([Action]{ if ($form.WindowState -eq 'Minimized') { $form.WindowState = 'Normal' }; $form.Activate() }) } catch {}
    }
    # interactive, actionable pop-up for IP-bearing HIGH events
    if ($Severity -eq 'HIGH' -and $Ip) {
        Show-InteractiveAlert -Category $Category -Detail $Detail -Ip $Ip -Direction $Direction
        if ($Config.AutoBlockOnHigh) { Disconnect-Ip -ip $Ip }
    }
}

function Show-InteractiveAlert {
    param([string]$Category,[string]$Detail,[string]$Ip,[string]$Direction)
    $info = Get-IpInfo $Ip
    $f = New-Object System.Windows.Forms.Form
    $f.Text = "ALERT: $Category"
    $f.Size = New-Object System.Drawing.Size(560, 360)
    $f.StartPosition = 'CenterScreen'
    $f.TopMost = $true
    $f.BackColor = [System.Drawing.ColorTranslator]::FromHtml($Config.BackColor)

    $lbl = New-Object System.Windows.Forms.Label
    $lbl.ForeColor = [System.Drawing.ColorTranslator]::FromHtml($Config.HighColor)
    $lbl.Font = New-Object System.Drawing.Font($Config.FontName, ($Config.FontSize + 2), [System.Drawing.FontStyle]::Bold)
    $lbl.AutoSize = $true; $lbl.Location = New-Object System.Drawing.Point(16,14)
    $lbl.Text = "! $Category"
    $f.Controls.Add($lbl)

    $dirTxt = if ($Direction) { "Direction: $Direction`n" } else { "" }
    $box = New-Object System.Windows.Forms.TextBox
    $box.Multiline = $true; $box.ReadOnly = $true; $box.BorderStyle = 'None'
    $box.BackColor = [System.Drawing.ColorTranslator]::FromHtml($Config.BackColor)
    $box.ForeColor = [System.Drawing.ColorTranslator]::FromHtml($Config.TextColor)
    $box.Font = New-Object System.Drawing.Font($Config.FontName, $Config.FontSize)
    $box.Location = New-Object System.Drawing.Point(18,56)
    $box.Size = New-Object System.Drawing.Size(510, 200)
    $box.Text = "$Detail`r`n`r`n$dirTxt`r`n$($info.Full -replace "`n", "`r`n")"
    $f.Controls.Add($box)

    $block = New-Object System.Windows.Forms.Button
    $block.Text = "Disconnect & Block"
    $block.Size = New-Object System.Drawing.Size(200,40)
    $block.Location = New-Object System.Drawing.Point(18,268)
    $block.FlatStyle = 'Flat'; $block.ForeColor = [System.Drawing.ColorTranslator]::FromHtml($Config.HighColor)
    $block.Font = New-Object System.Drawing.Font($Config.FontName, ($Config.FontSize-2), [System.Drawing.FontStyle]::Bold)
    $block.Tag = $Ip
    $block.Add_Click({ $frm = $this.FindForm(); Disconnect-Ip -ip ([string]$this.Tag); $frm.Close() })
    if (-not $script:IsAdmin) { $block.Enabled = $false; $block.Text = "Block (needs admin)" }
    $f.Controls.Add($block)

    $dismiss = New-Object System.Windows.Forms.Button
    $dismiss.Text = "Dismiss"; $dismiss.Size = New-Object System.Drawing.Size(140,40)
    $dismiss.Location = New-Object System.Drawing.Point(234,268)
    $dismiss.FlatStyle = 'Flat'; $dismiss.ForeColor = [System.Drawing.ColorTranslator]::FromHtml($Config.TextColor)
    $dismiss.Font = New-Object System.Drawing.Font($Config.FontName, ($Config.FontSize-2))
    $dismiss.Add_Click({ $this.FindForm().Close() })
    $f.Controls.Add($dismiss)

    $f.Show()
}

# -------- detections ----------------------------------------------------------
function Check-Connections {
    $rows = @()
    try {
        $rows = Get-NetTCPConnection -State Established,SynSent -ErrorAction Stop |
                Select-Object RemoteAddress -Unique
    } catch {
        $rows = (netstat -n) 2>$null | Select-String 'ESTABLISHED|SYN_SENT' | ForEach-Object {
            $ip = (($_ -split '\s+' | Where-Object { $_ -match ':\d+$' })[1]) -replace ':\d+$',''
            [pscustomobject]@{ RemoteAddress = $ip }
        } | Select-Object RemoteAddress -Unique
    }
    foreach ($r in $rows) {
        $ip = $r.RemoteAddress
        if ([string]::IsNullOrWhiteSpace($ip)) { continue }
        if ($Indicators.BadIPs -contains $ip) {
            Raise-Alert HIGH 'Known-bad connection' "This PC has a live connection to listed ARTEX infrastructure." "conn-$ip" $ip 'Outbound (this PC -> them)'
        }
    }
}

function Check-DnsCache {
    try { $cache = Get-DnsClientCache -ErrorAction Stop } catch { return }
    foreach ($e in $cache) {
        $name = ("$($e.Entry) $($e.Data)").ToLower()
        foreach ($d in $Indicators.BadDomains) { if ($name -like "*$d*") { Raise-Alert HIGH 'Known-bad DNS' "Resolved '$d' (ARTEX LLM reseller)." "dns-$d" } }
        foreach ($s in $Indicators.BadStrings) { if ($name -like "*$s*") { Raise-Alert MED 'Suspicious DNS string' "DNS entry contains '$s': $($e.Entry)" "dnsstr-$s" } }
        if ($Config.LlmEgressAlert) { foreach ($l in $Indicators.LlmDomains) { if ($name -like "*$l*") { Raise-Alert MED 'LLM egress' "Resolved LLM endpoint: $l" "llm-$l" } } }
    }
}

function Check-Arp {
    if (-not $Config.ArpWatchEnabled) { return }
    try {
        $now = Get-NetNeighbor -AddressFamily IPv4 -ErrorAction Stop |
               Where-Object { $_.State -in 'Reachable','Stale','Permanent' -and $_.IPAddress -notmatch '^(224\.|239\.|255\.)' } |
               Select-Object -ExpandProperty IPAddress -Unique
    } catch { return }
    if ($script:FirstSweep -or -not $script:ArpBaseline) { $script:ArpBaseline = $now; return }
    foreach ($ip in $now) { if ($script:ArpBaseline -notcontains $ip) { Raise-Alert INFO 'New network neighbour' "New device on local segment: $ip" "arp-$ip" } }
    $script:ArpBaseline = $now
}

# -------- incoming connection counter -----------------------------------------
function Test-SkipAddress {
    param([string]$Src,[string]$Dst)
    if (-not $Src -or $Src -eq '-') { return $true }
    if (-not $Config.CountThisPc -and (Get-Origin $Src) -eq 'This PC') { return $true }
    if ($Config.IgnoreBroadcast -and $Dst) {
        if ($Dst -match '^(255\.255\.255\.255|22[4-9]\.|23[0-9]\.|ff[0-9a-f]{2}:)') { return $true }
        if ($Dst -match '\.255$') { return $true }
    }
    return $false
}

function Get-PortsText {
    param($Rec,[int]$Max = 0)
    $items = @($Rec.Ports.GetEnumerator() | Sort-Object -Property Value -Descending)
    if ($Max -gt 0) { $items = @($items | Select-Object -First $Max) }
    $txt = ($items | ForEach-Object { "$($_.Key) x$($_.Value)" }) -join '; '
    if ($Max -gt 0 -and $Rec.Ports.Count -gt $Max) { $txt += "; +$($Rec.Ports.Count - $Max) more" }
    return $txt
}

function Add-Attempt {
    param([string]$Ip,[int]$Port,[string]$Proto,[string]$Action,[string]$Via,[object]$When)
    if (-not $When) { $When = Get-Date }
    if (-not $script:Inbound.ContainsKey($Ip)) {
        $script:Inbound[$Ip] = [pscustomobject]@{
            Ip = $Ip; Origin = (Get-Origin $Ip); Attempts = 0; Dropped = 0; Allowed = 0; Ports = @{}
            First = $When; Last = $When; Recent = (New-Object System.Collections.ArrayList); Alerted = $false
        }
    }
    $r = $script:Inbound[$Ip]
    $r.Attempts = $r.Attempts + 1
    if ($Action -eq 'DROP') { $r.Dropped = $r.Dropped + 1 } else { $r.Allowed = $r.Allowed + 1 }
    $pk = if ($Proto -like 'ICMP*') { 'ICMP' } else { "$Port/$Proto" }
    if ($r.Ports.ContainsKey($pk)) { $r.Ports[$pk] = $r.Ports[$pk] + 1 } else { $r.Ports[$pk] = 1 }
    if ($When -lt $r.First) { $r.First = $When }
    if ($When -gt $r.Last)  { $r.Last  = $When }
    [void]$r.Recent.Add([pscustomobject]@{ T = $When; P = $pk })
    $script:SummaryDirty = $true
    $act = switch ($Action) { 'DROP' { 'refused' } 'ALLOW' { 'allowed' } default { $Action.ToLower() } }
    $portOut = if ($pk -eq 'ICMP') { '' } else { $Port }
    $script:AttemptBuf.Add(('{0:yyyy-MM-dd HH:mm:ss},{1},{2},{3},{4},{5},{6}' -f $When, $Ip, $r.Origin, $portOut, $Proto, $act, $Via))
}

function Read-FirewallNew {
    # returns only the lines added to the firewall log since the last read
    $lines = New-Object System.Collections.Generic.List[string]
    $path = $Config.FwLogPath
    if (-not $path -or -not (Test-Path $path)) { return $lines }
    $fs = $null
    try {
        $fs = [System.IO.File]::Open($path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
        $script:FwReadable = $true
        $len = $fs.Length
        if ($script:FwPos -lt 0) { $script:FwPos = $len; return $lines }      # first read: count from now on
        if ($len -lt $script:FwPos) { $script:FwPos = 0; $script:FwTail = '' } # log rolled over
        if ($len -gt $script:FwPos) {
            [void]$fs.Seek($script:FwPos, [System.IO.SeekOrigin]::Begin)
            $sr = New-Object System.IO.StreamReader($fs, [System.Text.Encoding]::ASCII)
            $text = $script:FwTail + $sr.ReadToEnd()
            $script:FwPos = $fs.Position
            $parts = $text -split "`r?`n"
            $script:FwTail = $parts[$parts.Count - 1]
            for ($i = 0; $i -lt $parts.Count - 1; $i++) { if ($parts[$i]) { $lines.Add($parts[$i]) } }
        }
    } catch {
        $script:FwReadable = $false
    } finally {
        if ($fs) { $fs.Dispose() }
    }
    return $lines
}

function Process-FwLine {
    # fields: date time action protocol src-ip dst-ip src-port dst-port size tcpflags tcpsyn tcpack tcpwin icmptype icmpcode info path [pid]
    param([string]$Line)
    if (-not $Line -or $Line.StartsWith('#')) { return }
    $p = $Line.Trim() -split '\s+'
    if ($p.Count -lt 8) { return }
    $action = $p[2]
    if ($action -ne 'DROP' -and $action -ne 'ALLOW') { return }
    $path = ''
    if ($p.Count -gt 16) { $path = $p[16] }
    if ($path) {
        if ($path -ne 'RECEIVE') { return }        # inbound only
    } elseif ($action -eq 'ALLOW') {
        return                                     # old log format: direction unknown
    }
    $proto = $p[3]; $src = $p[4]; $dst = $p[5]; $dport = $p[7]
    if ($dport -notmatch '^[0-9]+$') {
        if ($proto -like 'ICMP*') { $dport = '0' } else { return }
    }
    if (Test-SkipAddress $src $dst) { return }
    $dt = [datetime]::MinValue
    if (-not [datetime]::TryParse("$($p[0]) $($p[1])", [ref]$dt)) { $dt = Get-Date }
    Add-Attempt -Ip $src -Port ([int]$dport) -Proto $proto -Action $action -Via 'firewall' -When $dt
    return $src
}

function Check-InboundTcp {
    # without admin: count new incoming TCP connections to this PC's listening ports
    param([hashtable]$Touched)
    try {
        $listen = @(Get-NetTCPConnection -State Listen -ErrorAction Stop | Select-Object -ExpandProperty LocalPort -Unique)
        $conns  = @(Get-NetTCPConnection -State Established,SynReceived -ErrorAction SilentlyContinue)
    } catch { return }
    $now = Get-Date
    $live = @{}
    foreach ($c in $conns) {
        if ($listen -notcontains $c.LocalPort) { continue }
        $ra = [string]$c.RemoteAddress
        if (Test-SkipAddress $ra ([string]$c.LocalAddress)) { continue }
        $k = "$ra|$($c.RemotePort)|$($c.LocalPort)"
        $live[$k] = $true
        if (-not $script:TcpSeen.ContainsKey($k)) {
            Add-Attempt -Ip $ra -Port ([int]$c.LocalPort) -Proto 'TCP' -Action 'CONNECTED' -Via 'tcp' -When $now
            $Touched[$ra] = $true
        }
    }
    $script:TcpSeen = $live
}

function Check-Inbound {
    if (-not $Config.TrackInbound) { return }
    $touched = @{}
    foreach ($ln in (Read-FirewallNew)) {
        $ip = Process-FwLine $ln
        if ($ip) { $touched[$ip] = $true }
    }
    if (-not $script:FwReadable -and -not $script:TestMode) { Check-InboundTcp $touched }
    $cutoff = (Get-Date).AddSeconds(-$Config.PortScanWindowSeconds)
    foreach ($ip in @($touched.Keys)) {
        $r = $script:Inbound[$ip]
        for ($i = $r.Recent.Count - 1; $i -ge 0; $i--) { if ($r.Recent[$i].T -lt $cutoff) { $r.Recent.RemoveAt($i) } }

        # apps on this PC never alarm; home network warns (amber) only; internet can alarm (red + pop-up)
        if ($r.Origin -eq 'This PC') { continue }
        if ($r.Origin -eq 'Home network' -and -not $Config.AlertOnHomeNetwork) { continue }
        $sev = if ($r.Origin -eq 'Internet') { 'HIGH' } else { 'MED' }

        $distinct = @($r.Recent | ForEach-Object { $_.P } | Select-Object -Unique).Count
        if ($distinct -ge $Config.PortScanDistinctPorts) {
            Raise-Alert $sev 'Inbound port scan' "$ip ($($r.Origin)) tried $distinct different ports on this PC in $($Config.PortScanWindowSeconds)s ($($r.Attempts) attempts in total)." "scan-$ip" $ip 'Inbound (them -> this PC)'
        }
        if (-not $r.Alerted -and $r.Dropped -ge $Config.DroppedAlertThreshold) {
            $r.Alerted = $true
            Raise-Alert $sev 'Repeated connection attempts' "$ip ($($r.Origin)) has been refused $($r.Dropped) times. Ports: $(Get-PortsText $r 6)" "rep-$ip" $ip 'Inbound (them -> this PC)'
        }
    }
}

function Flush-AttemptLog {
    if ($script:AttemptBuf.Count -eq 0) { return }
    if ($Config.Logging) {
        try {
            if (-not (Test-Path $Config.LogDir)) { New-Item -ItemType Directory -Path $Config.LogDir -Force | Out-Null }
            $f = Join-Path $Config.LogDir ("Connections_{0:yyyyMMdd}.csv" -f (Get-Date))
            if (-not (Test-Path $f)) { Set-Content -Path $f -Value 'Time,SourceIP,From,Port,Protocol,Action,Source' -Encoding UTF8 }
            Add-Content -Path $f -Value $script:AttemptBuf.ToArray() -Encoding UTF8
        } catch { Write-Log "[connections log] $($_.Exception.Message)" }
    }
    $script:AttemptBuf.Clear()
}

function Get-SortedInbound {
    # internet first, then home network, then this PC; busiest first within each
    $rank = @{ 'Internet' = 0; 'Home network' = 1; 'This PC' = 2 }
    return @($script:Inbound.Values | Sort-Object -Property @{ Expression = { $rank[$_.Origin] } }, @{ Expression = { $_.Attempts }; Descending = $true })
}

function Write-Summary {
    if (-not $script:SummaryDirty -or -not $Config.Logging) { return }
    $script:SummaryDirty = $false
    try {
        if (-not (Test-Path $Config.LogDir)) { New-Item -ItemType Directory -Path $Config.LogDir -Force | Out-Null }
        $f = Join-Path $Config.LogDir 'ConnectionSummary.csv'
        $out = New-Object System.Collections.Generic.List[string]
        $out.Add('SourceIP,From,Attempts,Refused,Allowed,DistinctPorts,Ports,FirstSeen,LastSeen')
        foreach ($r in (Get-SortedInbound)) {
            $out.Add(('{0},{1},{2},{3},{4},{5},"{6}",{7:yyyy-MM-dd HH:mm:ss},{8:yyyy-MM-dd HH:mm:ss}' -f $r.Ip, $r.Origin, $r.Attempts, $r.Dropped, $r.Allowed, $r.Ports.Count, (Get-PortsText $r 0), $r.First, $r.Last))
        }
        Set-Content -Path $f -Value $out.ToArray() -Encoding UTF8
    } catch { Write-Log "[summary] $($_.Exception.Message)" }
}

function Update-ConnGrid {
    $g = $script:ConnGrid
    if (-not $g -or $g.IsDisposed) { return }
    $sel = $null
    if ($g.CurrentRow) { $sel = [string]$g.CurrentRow.Cells['Ip'].Value }
    $top = $g.FirstDisplayedScrollingRowIndex
    $sc = $g.SortedColumn; $so = $g.SortOrder
    $pcFg   = [System.Drawing.ColorTranslator]::FromHtml($Config.ThisPcColor)
    $highFg = [System.Drawing.ColorTranslator]::FromHtml($Config.HighColor)
    $g.Rows.Clear()
    $total = 0; $refused = 0; $fromNet = 0
    foreach ($r in (Get-SortedInbound)) {
        $total += $r.Attempts; $refused += $r.Dropped
        if ($r.Origin -eq 'Internet') { $fromNet++ }
        $where = switch ($r.Origin) {
            'This PC'      { 'An app on this PC' }
            'Home network' { 'A device on your home network' }
            default        { if ($script:IpCache.ContainsKey($r.Ip)) { $script:IpCache[$r.Ip].One } else { '(select, then Look up)' } }
        }
        $i = $g.Rows.Add($r.Ip, $r.Origin, [int]$r.Attempts, [int]$r.Dropped, [int]$r.Allowed, [int]$r.Ports.Count, (Get-PortsText $r 0), $r.Last.ToString('dd/MM HH:mm:ss'), $where)
        if ($r.Origin -eq 'This PC') { $g.Rows[$i].DefaultCellStyle.ForeColor = $pcFg }
        elseif ($r.Origin -eq 'Internet' -and $r.Dropped -gt 0) { $g.Rows[$i].DefaultCellStyle.ForeColor = $highFg }
        if ($sel -and $r.Ip -eq $sel) { $g.CurrentCell = $g.Rows[$i].Cells[0] }
    }
    if ($sc) {
        $dir = if ($so -eq 'Ascending') { [System.ComponentModel.ListSortDirection]::Ascending } else { [System.ComponentModel.ListSortDirection]::Descending }
        $g.Sort($sc, $dir)
    }
    if ($top -ge 0 -and $top -lt $g.Rows.Count) { try { $g.FirstDisplayedScrollingRowIndex = $top } catch {} }
    if ($script:ConnLabel) {
        $src = if ($script:FwReadable) { 'firewall log' } else { 'live TCP only (Elevate to count refused attempts)' }
        $script:ConnLabel.Text = "Addresses: $($script:Inbound.Count) ($fromNet from the internet)    Attempts: $total    Refused: $refused    Source: $src    Updated $(Get-Date -Format 'HH:mm:ss')"
    }
}

function Show-Connections {
    if ($script:ConnForm -and -not $script:ConnForm.IsDisposed) {
        $script:ConnForm.WindowState = 'Normal'; $script:ConnForm.Activate(); Update-ConnGrid; return
    }
    $bg   = [System.Drawing.ColorTranslator]::FromHtml($Config.BackColor)
    $fg   = [System.Drawing.ColorTranslator]::FromHtml($Config.TextColor)
    $fnt  = New-Object System.Drawing.Font($Config.FontName, ($Config.FontSize - 2))
    $fntB = New-Object System.Drawing.Font($Config.FontName, ($Config.FontSize - 2), [System.Drawing.FontStyle]::Bold)

    $f = New-Object System.Windows.Forms.Form
    $f.Text = 'Intrusion Monitor - incoming connection attempts'
    $f.Size = New-Object System.Drawing.Size(1400, 700)
    $f.StartPosition = 'CenterScreen'
    $f.BackColor = $bg

    $lbl = New-Object System.Windows.Forms.Label
    $lbl.ForeColor = $fg; $lbl.Font = $fnt; $lbl.AutoSize = $true
    $lbl.Location = New-Object System.Drawing.Point(12, 10)
    $f.Controls.Add($lbl)

    $g = New-Object System.Windows.Forms.DataGridView
    $g.Location = New-Object System.Drawing.Point(12, 40)
    $g.Size = New-Object System.Drawing.Size(1360, 550)
    $g.Anchor = 'Top,Bottom,Left,Right'
    $g.ReadOnly = $true; $g.AllowUserToAddRows = $false; $g.AllowUserToDeleteRows = $false; $g.AllowUserToResizeRows = $false
    $g.RowHeadersVisible = $false; $g.SelectionMode = 'FullRowSelect'; $g.MultiSelect = $false
    $g.AutoSizeColumnsMode = 'Fill'; $g.AutoSizeRowsMode = 'AllCells'
    $g.BackgroundColor = $bg; $g.GridColor = [System.Drawing.Color]::DimGray; $g.BorderStyle = 'None'
    $g.EnableHeadersVisualStyles = $false
    $g.ColumnHeadersDefaultCellStyle.BackColor = $bg
    $g.ColumnHeadersDefaultCellStyle.ForeColor = $fg
    $g.ColumnHeadersDefaultCellStyle.Font = $fntB
    $g.ColumnHeadersHeightSizeMode = 'AutoSize'
    $g.DefaultCellStyle.BackColor = $bg; $g.DefaultCellStyle.ForeColor = $fg; $g.DefaultCellStyle.Font = $fnt
    $g.DefaultCellStyle.SelectionBackColor = $fg; $g.DefaultCellStyle.SelectionForeColor = $bg
    $g.DefaultCellStyle.WrapMode = 'True'
    $cols = @(
        @('Ip', 'Source address', 13, $null),
        @('Origin', 'From', 9, $null),
        @('Attempts', 'Attempts', 7, [int]),
        @('Refused', 'Refused', 7, [int]),
        @('Allowed', 'Let in', 6, [int]),
        @('PortCount', 'Ports', 5, [int]),
        @('Ports', 'Ports tried (port/protocol x count)', 30, $null),
        @('Last', 'Last seen', 10, $null),
        @('Where', 'Where from', 15, $null)
    )
    foreach ($c in $cols) {
        $col = New-Object System.Windows.Forms.DataGridViewTextBoxColumn
        $col.Name = $c[0]; $col.HeaderText = $c[1]; $col.FillWeight = $c[2]
        if ($c[3]) { $col.ValueType = $c[3] }
        [void]$g.Columns.Add($col)
    }
    $f.Controls.Add($g)

    $mk = {
        param($text, $x)
        $b = New-Object System.Windows.Forms.Button
        $b.Text = $text; $b.Location = New-Object System.Drawing.Point($x, 604)
        $b.Size = New-Object System.Drawing.Size(200, 36); $b.Anchor = 'Bottom,Left'
        $b.FlatStyle = 'Flat'; $b.ForeColor = $fg; $b.Font = $fnt
        $b
    }
    $bRefresh = & $mk 'Refresh' 12
    $bLookup  = & $mk 'Look up' 222
    $bBlock   = & $mk 'Block' 432
    $bFolder  = & $mk 'Open logs' 642
    $bClose   = & $mk 'Close' 852
    $bRefresh.Add_Click({ Update-ConnGrid })
    $bLookup.Add_Click({
        $cg = $script:ConnGrid
        if ($cg -and $cg.CurrentRow) { [void](Get-IpInfo ([string]$cg.CurrentRow.Cells['Ip'].Value)); Update-ConnGrid }
    })
    $bBlock.Add_Click({
        $cg = $script:ConnGrid
        if ($cg -and $cg.CurrentRow) { Disconnect-Ip -ip ([string]$cg.CurrentRow.Cells['Ip'].Value) }
    })
    if (-not $script:IsAdmin) { $bBlock.Enabled = $false; $bBlock.Text = 'Block (needs admin)' }
    $bFolder.Add_Click({
        $d = $script:Config.LogDir
        if (-not (Test-Path $d)) { New-Item -ItemType Directory -Path $d -Force | Out-Null }
        Start-Process explorer.exe $d
    })
    $bClose.Add_Click({ $this.FindForm().Close() })
    $f.Controls.AddRange(@($bRefresh, $bLookup, $bBlock, $bFolder, $bClose))

    $script:ConnForm = $f; $script:ConnGrid = $g; $script:ConnLabel = $lbl
    $f.Add_FormClosed({ $script:ConnForm = $null; $script:ConnGrid = $null; $script:ConnLabel = $null })
    Update-ConnGrid
    $f.Show()
}

function Check-CanaryQueue {
    while ($script:CanaryQueue.Count -gt 0) {
        $evt = $script:CanaryQueue.Dequeue()
        Raise-Alert HIGH 'Canary tripped' $evt "canary-$evt"
    }
    if ($Config.CanaryEnabled -and (Test-Path $Config.CanaryDir)) {
        Get-ChildItem -Path $Config.CanaryDir -Filter 'artex_probe_*.txt' -ErrorAction SilentlyContinue | ForEach-Object {
            Raise-Alert HIGH 'Scanner probe file' "A scanner dropped $($_.Name) in the decoy folder." "probe-$($_.Name)"
        }
    }
}

# -------- setup ---------------------------------------------------------------
function Setup-Canary {
    if (-not $Config.CanaryEnabled) { return }
    try {
        if (-not (Test-Path $Config.CanaryDir)) { New-Item -ItemType Directory -Path $Config.CanaryDir -Force | Out-Null }
        $bait = Join-Path $Config.CanaryDir $Config.CanaryBaitName
        if (-not (Test-Path $bait)) { Set-Content -Path $bait -Value "server,username,password`nMAIL01,admin,REDACTED`n" -Encoding UTF8 }
        $fsw = New-Object System.IO.FileSystemWatcher $Config.CanaryDir
        $fsw.IncludeSubdirectories = $true
        $fsw.NotifyFilter = [System.IO.NotifyFilters]'FileName,LastWrite,Size,LastAccess'
        $fsw.EnableRaisingEvents = $true
        $action = { $Event.MessageData.Enqueue(("{0} on {1}" -f $Event.SourceEventArgs.ChangeType, $Event.SourceEventArgs.Name)) }
        foreach ($ev in 'Changed','Created','Deleted','Renamed') { Register-ObjectEvent -InputObject $fsw -EventName $ev -Action $action -MessageData $script:CanaryQueue | Out-Null }
        $script:Fsw = $fsw
        Write-Log "[init] Canary armed at $($Config.CanaryDir)"
    } catch { Write-Log "[init] Canary setup failed: $($_.Exception.Message)" }
}

function Setup-ElevatedExtras {
    if (-not $script:IsAdmin) { return }
    if ($Config.AutoEnableFwLogging) {
        try {
            netsh advfirewall set allprofiles logging droppedconnections enable | Out-Null
            if ($Config.LogAllowedInbound) { netsh advfirewall set allprofiles logging allowedconnections enable | Out-Null }
            netsh advfirewall set allprofiles logging maxfilesize $Config.FwLogMaxKB | Out-Null
            $what = if ($Config.LogAllowedInbound) { 'refused + allowed' } else { 'refused' }
            Write-Log "[init] Firewall connection logging enabled ($what)."
        } catch { Write-Log "[init] Could not enable firewall logging: $($_.Exception.Message)" }
    }
    if ($Config.ShareDecoyEnabled -and $Config.CanaryEnabled) {
        try {
            if (-not (Get-SmbShare -Name $Config.ShareDecoyName -ErrorAction SilentlyContinue)) {
                New-SmbShare -Name $Config.ShareDecoyName -Path $Config.CanaryDir -ReadAccess 'Everyone' -ErrorAction Stop | Out-Null
                Write-Log "[init] Decoy SMB share '$($Config.ShareDecoyName)' published."
            }
        } catch { Write-Log "[init] Decoy share failed: $($_.Exception.Message)" }
    }
}

# -------- sweep ---------------------------------------------------------------
function Invoke-Sweep {
    if ($script:Paused) { return }
    Check-Connections; Check-DnsCache; Check-Arp; Check-Inbound; Check-CanaryQueue
    Flush-AttemptLog; Write-Summary
    if (-not $script:InboundNoted -and $Config.TrackInbound) {
        $script:InboundNoted = $true
        $how = if ($script:FwReadable) { 'Windows Firewall log (refused + allowed attempts, every port)' } else { 'live TCP connections only - press Elevate to count refused attempts and port scans' }
        Raise-Alert INFO 'Incoming counter' "Counting incoming attempts from: $how. Apps on this PC are listed but never alarm." 'inbound-noted'
    }
    if ($script:ConnForm -and -not $script:ConnForm.IsDisposed) { Update-ConnGrid }
    $script:FirstSweep = $false
    if ($script:Status) {
        $mode = if ($script:IsAdmin) { 'ELEVATED' } else { 'not elevated' }
        $state = if ($script:Paused) { 'PAUSED' } else { 'watching' }
        $script:Status.Invoke([Action]{ $script:Status.Text = "Mode: $mode   |   Last sweep: $(Get-Date -Format 'HH:mm:ss')   |   $state" })
    }
}

# -------- self-test (no main window) ------------------------------------------
if ($TestFirewallLog) {
    $Config.LogDir    = Join-Path $PSScriptRoot 'logs\test'
    if (Test-Path $Config.LogDir) { Remove-Item -Path $Config.LogDir -Recurse -Force -ErrorAction SilentlyContinue }
    $Config.FwLogPath = $TestFirewallLog
    $script:FwPos     = 0
    Build-AllowList
    Check-Inbound
    Flush-AttemptLog; Write-Summary
    "Addresses: $($script:Inbound.Count)"
    foreach ($r in (Get-SortedInbound)) {
        '{0} [{1}]  attempts={2} refused={3} allowed={4}  ports: {5}' -f $r.Ip, $r.Origin, $r.Attempts, $r.Dropped, $r.Allowed, (Get-PortsText $r 0)
    }
    if ($ShowConnections) {
        Show-Connections
        [System.Windows.Forms.Application]::Run($script:ConnForm)
    }
    return
}

# -------- main window ---------------------------------------------------------
Build-AllowList

$form = New-Object System.Windows.Forms.Form
$form.Text = "Intrusion Monitor"
$form.Size = New-Object System.Drawing.Size(900, 560)
$form.StartPosition = 'CenterScreen'
$form.BackColor = [System.Drawing.ColorTranslator]::FromHtml($Config.BackColor)

$header = New-Object System.Windows.Forms.Label
$header.Text = "INTRUSION MONITOR"
$header.ForeColor = [System.Drawing.ColorTranslator]::FromHtml($Config.TextColor)
$header.Font = New-Object System.Drawing.Font($Config.FontName, ($Config.FontSize + 6), [System.Drawing.FontStyle]::Bold)
$header.AutoSize = $true; $header.Location = New-Object System.Drawing.Point(14, 10)
$form.Controls.Add($header)

$script:Status = New-Object System.Windows.Forms.Label
$script:Status.ForeColor = [System.Drawing.ColorTranslator]::FromHtml($Config.TextColor)
$script:Status.Font = New-Object System.Drawing.Font($Config.FontName, ($Config.FontSize - 3))
$script:Status.AutoSize = $true; $script:Status.Location = New-Object System.Drawing.Point(16, 54)
$form.Controls.Add($script:Status)

$script:LogBox = New-Object System.Windows.Forms.RichTextBox
$script:LogBox.ReadOnly = $true; $script:LogBox.BorderStyle = 'None'
$script:LogBox.BackColor = [System.Drawing.ColorTranslator]::FromHtml($Config.BackColor)
$script:LogBox.ForeColor = [System.Drawing.ColorTranslator]::FromHtml($Config.TextColor)
$script:LogBox.Font = New-Object System.Drawing.Font($Config.FontName, $Config.FontSize)
$script:LogBox.Location = New-Object System.Drawing.Point(16, 86)
$script:LogBox.Size = New-Object System.Drawing.Size(854, 390)
$script:LogBox.Anchor = 'Top,Bottom,Left,Right'
$form.Controls.Add($script:LogBox)

function New-Btn($text,$x) {
    $b = New-Object System.Windows.Forms.Button
    $b.Text = $text; $b.Location = New-Object System.Drawing.Point($x, 486)
    $b.Size = New-Object System.Drawing.Size(150, 34); $b.Anchor = 'Bottom,Left'
    $b.ForeColor = [System.Drawing.ColorTranslator]::FromHtml($Config.TextColor)
    $b.FlatStyle = 'Flat'; $b.Font = New-Object System.Drawing.Font($Config.FontName, ($Config.FontSize - 3))
    return $b
}
$btnPause = New-Btn 'Pause' 16
$btnClear = New-Btn 'Clear log' 176
$ctxText = if ($script:IsAdmin) { 'Clear blocks' } else { 'Elevate' }
$btnContext = New-Btn $ctxText 336
$btnConn  = New-Btn 'Connections' 496
$btnStop  = New-Btn 'Stop'  656
$btnPause.Add_Click({ $script:Paused = -not $script:Paused; $btnPause.Text = if ($script:Paused) {'Resume'} else {'Pause'} })
$btnClear.Add_Click({ $script:LogBox.Clear() })
if ($script:IsAdmin) { $btnContext.Add_Click({ Clear-Blocks }) } else { $btnContext.Add_Click({ Invoke-Elevate }) }
$btnConn.Add_Click({ Show-Connections })
$btnStop.Add_Click({ $form.Close() })
$form.Controls.AddRange(@($btnPause,$btnClear,$btnContext,$btnConn,$btnStop))

$script:Tray = New-Object System.Windows.Forms.NotifyIcon
$script:Tray.Icon = [System.Drawing.SystemIcons]::Shield
$script:Tray.Text = "Intrusion Monitor"; $script:Tray.Visible = $true

$timer = New-Object System.Windows.Forms.Timer
$timer.Interval = $Config.ScanIntervalSeconds * 1000
$timer.Add_Tick({ try { Invoke-Sweep } catch { Write-Log "[sweep error] $($_.Exception.Message)" } })

$form.Add_Shown({
    if (-not $script:IsAdmin -and $Config.AutoElevate) { Invoke-Elevate; return }
    $mode = if ($script:IsAdmin) { 'ELEVATED (full feature set + blocking)' } else { 'not elevated (detect + alert only - click Elevate to enable blocking)' }
    Raise-Alert INFO 'Started' "Intrusion Monitor running - $mode."
    Setup-Canary; Setup-ElevatedExtras; Invoke-Sweep; $timer.Start()
    if ($Config.StartMinimized) { $form.WindowState = 'Minimized' }
})
$form.Add_FormClosing({
    $timer.Stop()
    try { Get-EventSubscriber | Where-Object { $_.SourceObject -is [System.IO.FileSystemWatcher] } | Unregister-Event -ErrorAction SilentlyContinue } catch {}
    if ($script:Fsw) { $script:Fsw.EnableRaisingEvents = $false; $script:Fsw.Dispose() }
    if ($script:Tray) { $script:Tray.Visible = $false; $script:Tray.Dispose() }
    Flush-AttemptLog; Write-Summary
    if ($script:ConnForm -and -not $script:ConnForm.IsDisposed) { $script:ConnForm.Close() }
    Write-Log "[stop] Intrusion Monitor closed."
})

[void][System.Windows.Forms.Application]::EnableVisualStyles()
[System.Windows.Forms.Application]::Run($form)
