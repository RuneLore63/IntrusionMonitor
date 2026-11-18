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
                   ARP neighbours (informational).
   Elevated adds : firewall dropped-inbound log -> port-scan detection; a decoy
                   SMB share; and the Disconnect & Block action.

 USAGE
   Run-IntrusionMonitor.cmd         standard user (detect + alert; no blocking)
   Run-IntrusionMonitor-Admin.cmd   elevated (adds port-scan + decoy + blocking)
   Close the window, or press Stop, to end it.
================================================================================
#>

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
    PortScanDistinctPorts = 15
    PortScanWindowSeconds = 60
    ShareDecoyEnabled     = $true
    ShareDecoyName        = "Backups"

    # appearance (high contrast / low glare)
    BackColor             = "#101010"
    TextColor             = "#FFD400"
    HighColor             = "#FF4C4C"
    MedColor              = "#FFB000"
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

$script:LastAlert   = @{}
$script:ArpBaseline = $null
$script:FwSeen      = New-Object System.Collections.Generic.HashSet[string]
$script:CanaryQueue = [System.Collections.Queue]::Synchronized((New-Object System.Collections.Queue))
$script:FirstSweep  = $true
$script:Paused      = $false
$script:IpCache     = @{}
$script:AllowList   = @()   # IPs we must never block (self, gateway, loopback)

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
    return ($ip -match '^(10\.|127\.|169\.254\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[0-1])\.)')
}

function Build-AllowList {
    $list = @('127.0.0.1','::1')
    try { $list += (Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue | Select-Object -ExpandProperty NextHop) } catch {}
    try { $list += (Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue | Select-Object -ExpandProperty IPAddress) } catch {}
    $script:AllowList = $list | Where-Object { $_ } | Select-Object -Unique
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
                    One  = "$ip  -  $($j.country) / $($j.isp)"
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
        [System.Windows.Forms.MessageBox]::Show("Blocking needs the elevated launcher (Run-IntrusionMonitor-Admin.cmd).","Intrusion Monitor") | Out-Null
        return
    }
    if ($script:AllowList -contains $ip) {
        [System.Windows.Forms.MessageBox]::Show("$ip is your own gateway/host - not blocking it (that would cut you off).","Intrusion Monitor") | Out-Null
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
    if ($Ip) {
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
    $box.Text = "$Detail`n`n$dirTxt`n$($info.Full)"
    $f.Controls.Add($box)

    $block = New-Object System.Windows.Forms.Button
    $block.Text = "Disconnect & Block"
    $block.Size = New-Object System.Drawing.Size(200,40)
    $block.Location = New-Object System.Drawing.Point(18,268)
    $block.FlatStyle = 'Flat'; $block.ForeColor = [System.Drawing.ColorTranslator]::FromHtml($Config.HighColor)
    $block.Font = New-Object System.Drawing.Font($Config.FontName, ($Config.FontSize-2), [System.Drawing.FontStyle]::Bold)
    $block.Add_Click({ Disconnect-Ip -ip $Ip; $f.Close() }.GetNewClosure())
    if (-not $script:IsAdmin) { $block.Enabled = $false; $block.Text = "Block (needs admin)" }
    $f.Controls.Add($block)

    $dismiss = New-Object System.Windows.Forms.Button
    $dismiss.Text = "Dismiss"; $dismiss.Size = New-Object System.Drawing.Size(140,40)
    $dismiss.Location = New-Object System.Drawing.Point(234,268)
    $dismiss.FlatStyle = 'Flat'; $dismiss.ForeColor = [System.Drawing.ColorTranslator]::FromHtml($Config.TextColor)
    $dismiss.Font = New-Object System.Drawing.Font($Config.FontName, ($Config.FontSize-2))
    $dismiss.Add_Click({ $f.Close() }.GetNewClosure())
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

function Check-FirewallLog {
    if (-not $script:IsAdmin) { return }
    if (-not (Test-Path $Config.FwLogPath)) { return }
    $cutoff = (Get-Date).AddSeconds(-$Config.PortScanWindowSeconds)
    $recent = @{}
    try { $lines = Get-Content -Path $Config.FwLogPath -Tail 800 -ErrorAction Stop } catch { return }
    foreach ($ln in $lines) {
        if ($ln.StartsWith('#') -or [string]::IsNullOrWhiteSpace($ln)) { continue }
        if (-not $script:FwSeen.Add($ln)) { continue }
        $p = $ln -split '\s+'
        if ($p.Count -lt 8 -or $p[2] -ne 'DROP') { continue }
        $dt = $null; [void][DateTime]::TryParse("$($p[0]) $($p[1])", [ref]$dt)
        if ($dt -and $dt -lt $cutoff) { continue }
        $src = $p[4]; $dport = $p[7]
        if ($src -match '^\d+\.\d+\.\d+\.\d+$' -and $dport -match '^\d+$') {
            if (-not $recent.ContainsKey($src)) { $recent[$src] = New-Object System.Collections.Generic.HashSet[string] }
            [void]$recent[$src].Add($dport)
        }
    }
    foreach ($src in $recent.Keys) {
        if ($recent[$src].Count -ge $Config.PortScanDistinctPorts) {
            Raise-Alert HIGH 'Inbound port scan' "$src probed $($recent[$src].Count) ports on this PC in $($Config.PortScanWindowSeconds)s." "scan-$src" $src 'Inbound (them -> this PC)'
        }
    }
    if ($script:FwSeen.Count -gt 5000) { $script:FwSeen.Clear() }
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
        try { netsh advfirewall set allprofiles logging droppedconnections enable | Out-Null; Write-Log "[init] Firewall dropped-connection logging enabled." }
        catch { Write-Log "[init] Could not enable firewall logging: $($_.Exception.Message)" }
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
    Check-Connections; Check-DnsCache; Check-Arp; Check-FirewallLog; Check-CanaryQueue
    $script:FirstSweep = $false
    if ($script:Status) {
        $mode = if ($script:IsAdmin) { 'ELEVATED' } else { 'not elevated' }
        $state = if ($script:Paused) { 'PAUSED' } else { 'watching' }
        $script:Status.Invoke([Action]{ $script:Status.Text = "Mode: $mode   |   Last sweep: $(Get-Date -Format 'HH:mm:ss')   |   $state" })
    }
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
$btnStop  = New-Btn 'Stop'  496
$btnPause.Add_Click({ $script:Paused = -not $script:Paused; $btnPause.Text = if ($script:Paused) {'Resume'} else {'Pause'} })
$btnClear.Add_Click({ $script:LogBox.Clear() })
if ($script:IsAdmin) { $btnContext.Add_Click({ Clear-Blocks }) } else { $btnContext.Add_Click({ Invoke-Elevate }) }
$btnStop.Add_Click({ $form.Close() })
$form.Controls.AddRange(@($btnPause,$btnClear,$btnContext,$btnStop))

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
    Write-Log "[stop] Intrusion Monitor closed."
})

[void][System.Windows.Forms.Application]::EnableVisualStyles()
[System.Windows.Forms.Application]::Run($form)
