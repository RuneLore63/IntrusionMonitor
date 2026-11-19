#requires -version 5.1
<#
================================================================================
 INTRUSION MONITOR  v2.0  (forensic edition)
 A host-based early-warning sensor for autonomous-scanner / ARTEX-style activity.

 WHAT IT IS
   A single PowerShell script. No install. Runs as a normal user (does more if
   elevated). Watches THIS PC only - what your own machine can legitimately see
   - and raises a large, high-contrast alert the moment something looks wrong.
   Serious alerts pop an interactive window showing where the connection comes
   from (country / ISP / owner / abuse contact) with a "Disconnect & Block" button.

 WHAT IT CANNOT DO
   On a switched / Wi-Fi network your PC does not see traffic between OTHER
   machines. This detects activity against *this host*, plus this host talking
   to known-bad infrastructure. It is a host sensor, not a network tap.
   It never attacks back. Lookups are public registry / DNS queries and a
   standard traceroute - the same as any network engineer would run.

 DETECTIONS
   Not elevated : own outbound connections vs known-bad IPs; DNS cache vs
                  known-bad domains / "artex" strings; canary tripwire; new
                  ARP neighbours (informational); incoming TCP connections
                  counted per source address.
   Elevated adds: firewall log -> every refused (and allowed) inbound attempt
                  counted per source address and port, port-scan detection,
                  repeated-attempt alerts; a decoy SMB share; Disconnect & Block.

 WHERE A CONNECTION COMES FROM
   This PC       127.0.0.1, ::1 and this PC's own addresses. Listed, never alarmed.
   Home network  192.168.x.x, 10.x.x.x, 172.16-31.x.x etc. Amber warning only.
   Internet      everything else. Can raise the red alarm and the pop-up.

 EVIDENCE (logs folder)
   Evidence_YYYYMMDD.jsonl   tamper-evident journal (UTC day). Every record has
                             UTC + local time, a sequence number and a SHA-256
                             hash chained to the record before it, so any edit,
                             deletion or reordering shows up when verified.
                             Raw firewall lines are kept word for word.
   Evidence_YYYYMMDD.seal.txt  written at the end of each day: the file's SHA-256.
                             The day's journal is then made read-only.
   Seals.txt                 running list of every day's seal.
   Connections_YYYYMMDD.csv  one line per incoming attempt (spreadsheet-friendly).
   ConnectionSummary.csv     one line per source address, with who/where/abuse.
   export\EvidencePack_*.zip everything above + firewall log + incident summary
                             + MANIFEST of SHA-256 hashes, ready to hand over.

 RECORDED ABOUT EACH SOURCE
   Time (UTC and local), source address and port, which of this PC's addresses
   and network adapters received it, which app on this PC owned the port,
   the sender's MAC address and maker (home network only - internet traffic
   arrives via your router), reverse DNS name, registry owner (RDAP/WHOIS),
   network range, abuse contact, country/ISP/ASN, and for internet attackers
   an automatic traceroute. Clock accuracy and the network you were on are
   recorded too, so the timestamps can be relied on.

 USAGE
   IntrusionMonitor.vbs             starts silently, minimised (recommended)
   Run-IntrusionMonitor.cmd         not elevated (detect + alert; no blocking)
   Run-IntrusionMonitor-Admin.cmd   elevated (adds port-scan + decoy + blocking)
   Close the window, or press Stop, to end it.

 TEST / CHECK FROM A COMMAND LINE
   -TestFirewallLog <file>   process a saved firewall log into logs\test
   -ShowConnections          (with the above) open the Connections window
   -TestExport               (with the above) also build an evidence pack
   -VerifyDir <folder>       check the evidence journal in a folder and report
================================================================================
#>

param(
    [string]$TestFirewallLog,
    [switch]$ShowConnections,
    [switch]$TestExport,
    [string]$VerifyDir
)

# ---------------------------------------------------------------------------
# CONFIG  - safe to edit
# ---------------------------------------------------------------------------
$Config = [ordered]@{
    ScanIntervalSeconds   = 10
    AlertCooldownSeconds  = 300
    Logging               = $true
    LogDir                = "$PSScriptRoot\logs"
    DataDir               = "$PSScriptRoot\data"

    CanaryEnabled         = $true
    CanaryDir             = "$env:USERPROFILE\Documents\_IntrusionMonitor_DoNotTouch"
    CanaryBaitName        = "ACCOUNTS_BACKUP.txt"

    ArpWatchEnabled       = $true
    LlmEgressAlert        = $false

    # geo / owner lookup for source IPs (needs internet; free tier, rate-limited)
    IpLookupEnabled       = $true
    IpLookupUrl           = 'http://ip-api.com/json/{0}?fields=status,message,country,regionName,city,isp,org,as,query'
    IpLookupTimeoutSec    = 4
    RdapUrl               = 'https://rdap.org/ip/{0}'

    # forensic evidence
    EvidenceEnabled       = $true     # hash-chained evidence journal
    EvidenceIncludeThisPc = $true     # also journal this PC's own apps talking to each other
    AutoIdentify          = $true     # look up who/where for every new home or internet address
    AutoTraceroute        = $true     # traceroute an internet address when it raises a red alert
    TraceMaxHops          = 30
    TraceWaitMs           = 750
    LookupsPerSweep       = 4         # stays inside the free lookup service's rate limit
    ClockCheckMinutes     = 60        # compare the PC clock with internet time this often
    ClockWarnSeconds      = 120       # warn if the PC clock is out by more than this
    NetContextSeconds     = 60        # re-check which network / Wi-Fi this PC is on
    VendorRefreshDays     = 180       # refresh the MAC-maker list this often

    # active response (elevated only)
    AutoBlockOnHigh       = $false
    BlockBothDirections   = $true
    FirewallGroup         = 'IntrusionMonitor'
    AutoElevate           = $false

    # elevated firewall log / port scan
    AutoEnableFwLogging   = $true
    FwLogPath             = "$env:windir\system32\LogFiles\Firewall\pfirewall.log"
    FwLogMaxKB            = 16384
    PortScanDistinctPorts = 15
    PortScanWindowSeconds = 60
    ShareDecoyEnabled     = $true
    ShareDecoyName        = "Backups"

    # incoming connection counter
    TrackInbound          = $true
    LogAllowedInbound     = $true
    IgnoreBroadcast       = $true
    CountThisPc           = $true
    AlertOnHomeNetwork    = $true
    DroppedAlertThreshold = 25

    # appearance (high contrast / low glare)
    BackColor             = "#101010"
    TextColor             = "#FFD400"
    HighColor             = "#FF4C4C"
    MedColor              = "#FFB000"
    ThisPcColor           = "#C8C8C8"
    FontName              = "Consolas"
    FontSize              = 14
    AlertBalloons         = $true
    StartMinimized        = $true
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

$script:Version    = '2.0'
$script:Inv        = [System.Globalization.CultureInfo]::InvariantCulture
$script:Utf8NoBom  = New-Object System.Text.UTF8Encoding($false)
$script:IsAdmin = ([Security.Principal.WindowsPrincipal] `
    [Security.Principal.WindowsIdentity]::GetCurrent()
    ).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
$script:ScriptPath = $PSCommandPath
$script:ScriptHash = ''
try { $script:ScriptHash = (Get-FileHash -LiteralPath $PSCommandPath -Algorithm SHA256).Hash } catch {}

$script:LastAlert    = @{}
$script:ArpBaseline  = $null
$script:FwPos        = -1
$script:FwTail       = ''
$script:FwReadable   = $false
$script:Inbound      = @{}
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
$script:AllowList    = @()

# forensic state
$script:EvSeq        = [long]0
$script:EvPrev       = ('0' * 64)
$script:EvDay        = ''
$script:EvFile       = ''
$script:EvBuf        = New-Object System.Collections.Generic.List[string]
$script:IdentityCache = @{}
$script:IdPending    = @{}
$script:IdQueue      = New-Object System.Collections.Queue
$script:TraceDone    = @{}
$script:TraceResults = New-Object System.Collections.ArrayList
$script:AlertHistory = New-Object System.Collections.ArrayList
$script:Jobs         = New-Object System.Collections.ArrayList
$script:Pool         = $null
$script:Vendors      = @{}
$script:OuiTried     = $false
$script:NeighborMap  = @{}
$script:ListenTcp    = @{}
$script:ListenUdp    = @{}
$script:LocalTcpPort = @{}
$script:ProcCache    = @{}
$script:LocalIfaceMap = @{}
$script:NetSig       = ''
$script:NetContext   = $null
$script:LastNet      = [datetime]::MinValue
$script:LastClock    = [datetime]::MinValue
$script:LastClockInfo = $null

function Write-Log {
    param([string]$Line)
    if (-not $Config.Logging) { return }
    try {
        if (-not (Test-Path $Config.LogDir)) { New-Item -ItemType Directory -Path $Config.LogDir -Force | Out-Null }
        $f = Join-Path $Config.LogDir ("IntrusionMonitor_{0:yyyyMMdd}.log" -f (Get-Date))
        Add-Content -Path $f -Value $Line -Encoding UTF8
    } catch { }
}

function CsvQ {
    param($Value)
    $s = [string]$Value
    return '"' + ($s -replace '"', '""') + '"'
}

function Get-Sha256Hex {
    param([string]$Text)
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        return ([BitConverter]::ToString($sha.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($Text))) -replace '-', '').ToLowerInvariant()
    } finally { $sha.Dispose() }
}

function Format-Utc {
    param([datetime]$When)
    return $When.ToUniversalTime().ToString("yyyy-MM-dd'T'HH:mm:ss.fff'Z'", $script:Inv)
}

function Format-Local {
    param([datetime]$When)
    return $When.ToLocalTime().ToString('yyyy-MM-dd HH:mm:ss.fff zzz', $script:Inv)
}

function Test-PrivateIp {
    param([string]$ip)
    return ($ip -match '^(10\.|127\.|169\.254\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[0-1])\.|fe[89ab][0-9a-f]:|f[cd][0-9a-f]{2}:)')
}

function Get-Origin {
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
    $script:SelfIps = @()
    $script:LocalIfaceMap = @{}
    try {
        foreach ($a in (Get-NetIPAddress -ErrorAction SilentlyContinue)) {
            $ipa = ([string]$a.IPAddress) -replace '%.*$', ''
            $script:SelfIps += $ipa
            $script:LocalIfaceMap[$ipa] = [string]$a.InterfaceAlias
        }
    } catch { }
}

# ===========================================================================
#   EVIDENCE JOURNAL  (SHA-256 hash chain)
# ===========================================================================
function New-EvidenceLine {
    param([string]$Type, $Data, [datetime]$UtcNow)
    $script:EvSeq = $script:EvSeq + 1
    $rec = [ordered]@{
        seq   = $script:EvSeq
        utc   = Format-Utc $UtcNow
        local = Format-Local $UtcNow
        type  = $Type
        data  = $Data
        prev  = $script:EvPrev
    }
    $body = $rec | ConvertTo-Json -Compress -Depth 8
    $h = Get-Sha256Hex $body
    $script:EvPrev = $h
    return $body.Substring(0, $body.Length - 1) + ',"hash":"' + $h + '"}'
}

function Flush-Evidence {
    if ($script:EvBuf.Count -eq 0 -or -not $script:EvFile) { return }
    try {
        if (-not (Test-Path $Config.LogDir)) { New-Item -ItemType Directory -Path $Config.LogDir -Force | Out-Null }
        [System.IO.File]::AppendAllLines($script:EvFile, [string[]]$script:EvBuf.ToArray(), $script:Utf8NoBom)
        $script:EvBuf.Clear()
    } catch { Write-Log "[evidence write] $($_.Exception.Message)" }
}

function Seal-EvidenceFile {
    param([string]$Path)
    try {
        if (-not (Test-Path -LiteralPath $Path)) { return }
        $fi = Get-Item -LiteralPath $Path
        if ($fi.IsReadOnly) { return }
        $leaf = $fi.Name
        $line = New-EvidenceLine 'SEAL' ([ordered]@{
            file = $leaf
            lastSeq = $script:EvSeq
            note = 'End of day. This file is now closed and read-only. Its SHA-256 is in the matching .seal.txt file and in Seals.txt.'
        }) ([datetime]::UtcNow)
        [System.IO.File]::AppendAllLines($Path, [string[]]@($line), $script:Utf8NoBom)
        $hash = (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash
        $sealed = Format-Utc ([datetime]::UtcNow)
        $sealPath = Join-Path $fi.DirectoryName ($fi.BaseName + '.seal.txt')
        $txt = @(
            "File:              $leaf",
            "SHA-256:           $hash",
            "Sealed (UTC):      $sealed",
            "Last record seq:   $($script:EvSeq)",
            "Last record hash:  $($script:EvPrev)",
            "Computer:          $env:COMPUTERNAME",
            "",
            "To check: open PowerShell and run",
            "  Get-FileHash -Algorithm SHA256 '$leaf'",
            "The answer must match the SHA-256 above exactly."
        )
        Set-Content -LiteralPath $sealPath -Value $txt -Encoding UTF8
        Add-Content -LiteralPath (Join-Path $fi.DirectoryName 'Seals.txt') -Value "$sealed  $hash  $leaf" -Encoding UTF8
        (Get-Item -LiteralPath $Path).IsReadOnly = $true
        Write-Log "[evidence] Sealed $leaf  SHA-256 $hash"
    } catch { Write-Log "[evidence seal] $($_.Exception.Message)" }
}

function Switch-EvidenceDay {
    param([string]$Day)
    if ($script:EvFile) {
        Flush-Evidence
        Seal-EvidenceFile $script:EvFile
    }
    $script:EvDay  = $Day
    $script:EvFile = Join-Path $Config.LogDir "Evidence_$Day.jsonl"
}

function Write-Evidence {
    param([string]$Type, $Data)
    if (-not $Config.EvidenceEnabled) { return }
    try {
        $u = [datetime]::UtcNow
        $day = $u.ToString('yyyyMMdd', $script:Inv)
        if ($script:EvDay -ne $day) { Switch-EvidenceDay $day }
        $script:EvBuf.Add((New-EvidenceLine $Type $Data $u))
        if ($script:EvBuf.Count -ge 500) { Flush-Evidence }
    } catch { Write-Log "[evidence] $($_.Exception.Message)" }
}

function Init-Evidence {
    if (-not $Config.EvidenceEnabled) { return }
    $script:EvSeq = [long]0; $script:EvPrev = ('0' * 64); $script:EvDay = ''; $script:EvFile = ''
    $restart = $null
    try {
        if (-not (Test-Path $Config.LogDir)) { New-Item -ItemType Directory -Path $Config.LogDir -Force | Out-Null }
        $files = @(Get-ChildItem -LiteralPath $Config.LogDir -Filter 'Evidence_*.jsonl' -File -ErrorAction SilentlyContinue | Sort-Object Name)
        if ($files.Count -gt 0) {
            $last = $files[$files.Count - 1]
            try {
                $tl = Get-Content -LiteralPath $last.FullName -Tail 1 -Encoding UTF8
                $o = $tl | ConvertFrom-Json
                $h = [string]$o.hash
                if ($h.Length -ne 64) { throw 'last record has no valid hash' }
                $script:EvSeq = [long]$o.seq
                $script:EvPrev = $h
            } catch {
                $restart = "Could not read the last record of $($last.Name): $($_.Exception.Message)"
                $script:EvSeq = [long]0; $script:EvPrev = ('0' * 64)
            }
            $script:EvDay  = $last.BaseName -replace '^Evidence_', ''
            $script:EvFile = $last.FullName
            $today = [datetime]::UtcNow.ToString('yyyyMMdd', $script:Inv)
            if ($script:EvDay -ne $today -and -not $last.IsReadOnly) { Seal-EvidenceFile $last.FullName }
        }
    } catch { Write-Log "[evidence init] $($_.Exception.Message)" }
    if ($restart) { Write-Evidence 'CHAIN-RESTART' ([ordered]@{ reason = $restart }) }
}

function Test-EvidenceChain {
    param([string]$Dir)
    $problems = New-Object System.Collections.Generic.List[string]
    $warn     = New-Object System.Collections.Generic.List[string]
    $records  = 0
    $zero     = ('0' * 64)
    $files = @(Get-ChildItem -LiteralPath $Dir -Filter 'Evidence_*.jsonl' -File -ErrorAction SilentlyContinue | Sort-Object Name)
    $prevHash = $null; $prevSeq = $null
    foreach ($f in $files) {
        $lines = [System.IO.File]::ReadAllLines($f.FullName, $script:Utf8NoBom)
        $n = 0
        foreach ($ln in $lines) {
            $n++
            if (-not $ln.Trim()) { continue }
            $records++
            $where = "$($f.Name) line $n"
            $i = $ln.LastIndexOf(',"hash":"')
            if ($i -lt 0 -or $ln.Length -lt ($i + 9 + 64)) {
                $problems.Add("${where}: has no hash - the record is damaged or was added by hand")
                $prevHash = $null; continue
            }
            $claimed = $ln.Substring($i + 9, 64)
            $body = $ln.Substring(0, $i) + '}'
            if ((Get-Sha256Hex $body) -ne $claimed) {
                $problems.Add("${where}: the contents do not match the record's hash - this record has been ALTERED")
            }
            $o = $null
            try { $o = $body | ConvertFrom-Json } catch {
                $problems.Add("${where}: cannot be read")
                $prevHash = $claimed; continue
            }
            $op = [string]$o.prev
            if ($null -eq $prevHash) {
                if ($records -eq 1 -and $op -ne $zero) { $warn.Add("${where}: the first record links back to earlier records that are not in this folder (older journal files missing or moved)") }
            } elseif ($op -ne $prevHash) {
                if ($o.type -eq 'CHAIN-RESTART' -and $op -eq $zero) { $warn.Add("${where}: chain restarted - $($o.data.reason)") }
                else { $problems.Add("${where}: chain broken - the record before this one is missing, altered or out of order") }
            }
            if ($null -ne $prevSeq -and [long]$o.seq -ne ($prevSeq + 1) -and $o.type -ne 'CHAIN-RESTART') {
                $problems.Add("${where}: sequence jumps from $prevSeq to $($o.seq) - records are missing")
            }
            $prevHash = $claimed; $prevSeq = [long]$o.seq
        }
        $sf = Join-Path $f.DirectoryName ($f.BaseName + '.seal.txt')
        if (Test-Path -LiteralPath $sf) {
            $st = Get-Content -LiteralPath $sf -Raw
            if ($st -match 'SHA-256:\s*([0-9A-Fa-f]{64})') {
                $want = $Matches[1]
                $have = (Get-FileHash -LiteralPath $f.FullName -Algorithm SHA256).Hash
                if ($have -ne $want) { $problems.Add("$($f.Name): the file has CHANGED since it was sealed (seal $want, now $have)") }
            }
        } elseif ($f.FullName -ne $files[$files.Count - 1].FullName) {
            $warn.Add("$($f.Name): not sealed (the monitor was not running at the end of that day)")
        }
    }
    $ok = ($problems.Count -eq 0 -and $records -gt 0)
    $rep = New-Object System.Collections.Generic.List[string]
    $rep.Add('EVIDENCE JOURNAL VERIFICATION')
    $rep.Add("Checked (UTC):  $(Format-Utc ([datetime]::UtcNow))")
    $rep.Add("Folder:         $Dir")
    $rep.Add("Journal files:  $($files.Count)")
    $rep.Add("Records:        $records")
    if ($records -eq 0) { $rep.Add('RESULT:         NO RECORDS FOUND') }
    elseif ($ok) { $rep.Add('RESULT:         PASS - every record is intact, in order and unbroken') }
    else { $rep.Add("RESULT:         FAIL - $($problems.Count) problem(s) found") }
    if ($problems.Count) { $rep.Add(''); $rep.Add('PROBLEMS'); foreach ($p in ($problems | Select-Object -First 50)) { $rep.Add("  $p") } }
    if ($warn.Count)     { $rep.Add(''); $rep.Add('NOTES');    foreach ($w in ($warn | Select-Object -First 50))     { $rep.Add("  $w") } }
    return [pscustomobject]@{ Ok = $ok; Files = $files.Count; Records = $records; Problems = $problems; Warnings = $warn; Report = ($rep -join "`r`n") }
}

# ===========================================================================
#   BACKGROUND JOBS  (lookups, traceroute, clock check - never freeze the UI)
# ===========================================================================
$script:BgCommon = @'
try { [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12 } catch {}
function Get-Url {
    param([string]$Url, [int]$TimeoutMs = 8000, [string]$Accept = '*/*')
    $r = [ordered]@{ Ok = $false; Body = ''; Date = ''; Error = ''; Status = 0 }
    try {
        $req = [System.Net.HttpWebRequest]::Create($Url)
        $req.Timeout = $TimeoutMs; $req.ReadWriteTimeout = $TimeoutMs
        $req.UserAgent = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) IntrusionMonitor/2.0'
        $req.Accept = $Accept
        $req.AllowAutoRedirect = $true
        $req.AutomaticDecompression = [System.Net.DecompressionMethods]'GZip,Deflate'
        $resp = $req.GetResponse()
        try {
            $r.Status = [int]$resp.StatusCode
            $r.Date = [string]$resp.Headers['Date']
            $sr = New-Object System.IO.StreamReader($resp.GetResponseStream(), [System.Text.Encoding]::UTF8)
            $r.Body = $sr.ReadToEnd(); $sr.Dispose()
            $r.Ok = $true
        } finally { $resp.Close() }
    } catch [System.Net.WebException] {
        $r.Error = $_.Exception.Message
        if ($_.Exception.Response) { try { $r.Status = [int]$_.Exception.Response.StatusCode; $r.Date = [string]$_.Exception.Response.Headers['Date'] } catch {} }
    } catch { $r.Error = $_.Exception.Message }
    return [pscustomobject]$r
}
'@

$script:JobIdentity = @'
$o = [ordered]@{
    ip = $a.Ip; origin = $a.Origin; lookedUpUtc = [DateTime]::UtcNow.ToString('o')
    reverseDns = ''; country = ''; region = ''; city = ''; isp = ''; org = ''; asn = ''
    netName = ''; netHandle = ''; netRange = ''; netCountry = ''; registry = ''; registrant = ''
    abuseContact = ''; abuseName = ''; rdapUrl = ''; errors = @()
}
try {
    $t = [System.Net.Dns]::GetHostEntryAsync($a.Ip)
    if ($t.Wait(4000)) { if ($t.Result.HostName -and $t.Result.HostName -ne $a.Ip) { $o.reverseDns = $t.Result.HostName } }
} catch { }
if ($a.Origin -eq 'Internet') {
    $g = Get-Url ($a.GeoUrl -f $a.Ip) 6000
    if ($g.Ok) {
        try {
            $j = $g.Body | ConvertFrom-Json
            if ($j.status -eq 'success') {
                $o.country = [string]$j.country; $o.region = [string]$j.regionName; $o.city = [string]$j.city
                $o.isp = [string]$j.isp; $o.org = [string]$j.org; $o.asn = [string]$j.as
            } else { $o.errors += "geo: $($j.message)" }
        } catch { $o.errors += "geo: $($_.Exception.Message)" }
    } else { $o.errors += "geo: $($g.Error)" }

    $rd = Get-Url ($a.RdapUrl -f $a.Ip) 12000 'application/rdap+json, application/json'
    if ($rd.Ok) {
        try {
            $j = $rd.Body | ConvertFrom-Json
            function Get-Vc($e, $k) { foreach ($p in @($e.vcardArray[1])) { if ($p -and $p[0] -eq $k) { return [string]$p[3] } } return '' }
            function Find-Role($ents, $role, $d) {
                foreach ($e in @($ents)) {
                    if ($null -eq $e) { continue }
                    if (@($e.roles) -contains $role) { return $e }
                    if ($e.entities -and $d -lt 4) { $x = Find-Role $e.entities $role ($d + 1); if ($x) { return $x } }
                }
                return $null
            }
            $o.netName = [string]$j.name; $o.netHandle = [string]$j.handle
            if ($j.startAddress) { $o.netRange = "$($j.startAddress) - $($j.endAddress)" }
            $o.netCountry = [string]$j.country; $o.registry = [string]$j.port43
            foreach ($lk in @($j.links)) { if ($lk -and $lk.rel -eq 'self') { $o.rdapUrl = [string]$lk.href } }
            $ab = Find-Role $j.entities 'abuse' 0
            if ($ab) { $o.abuseContact = Get-Vc $ab 'email'; $o.abuseName = Get-Vc $ab 'fn' }
            $rg = Find-Role $j.entities 'registrant' 0
            if (-not $rg) { $rg = Find-Role $j.entities 'administrative' 0 }
            if ($rg) { $o.registrant = Get-Vc $rg 'fn' }
        } catch { $o.errors += "rdap: $($_.Exception.Message)" }
    } else { $o.errors += "rdap: $($rd.Error)" }
}
[pscustomobject]$o
'@

$script:JobTrace = @'
$st = [DateTime]::UtcNow
$raw = @(& tracert.exe -d -h $a.Hops -w $a.WaitMs $a.Ip 2>&1 | ForEach-Object { "$_" })
$hops = @($raw | Where-Object { $_ -match '^\s*\d+\s' } | ForEach-Object { ($_ -replace '\s+', ' ').Trim() })
[pscustomobject]@{
    ip = $a.Ip; reason = $a.Reason
    startedUtc = $st.ToString('o'); finishedUtc = [DateTime]::UtcNow.ToString('o')
    command = "tracert -d -h $($a.Hops) -w $($a.WaitMs) $($a.Ip)"
    hops = $hops
    raw = @($raw | Where-Object { $_.Trim() })
}
'@

$script:JobClock = @'
$o = [ordered]@{ checkedUtc = [DateTime]::UtcNow.ToString('o'); pcClockUtc = ''; internetTimeUtc = ''; internetTimeSource = 'https://www.google.com/generate_204 (HTTP Date header)'
                 offsetSeconds = $null; windowsTimeSource = ''; w32tm = @(); publicIp = ''; errors = @() }
try {
    $w = @(& w32tm.exe /query /status 2>&1 | ForEach-Object { "$_".Trim() } | Where-Object { $_ })
    $o.w32tm = $w
    foreach ($l in $w) { if ($l -match '^Source:\s*(.+)$') { $o.windowsTimeSource = $Matches[1] } }
} catch { $o.errors += "w32tm: $($_.Exception.Message)" }
$t0 = [DateTime]::UtcNow
$g = Get-Url 'https://www.google.com/generate_204' 6000
$t1 = [DateTime]::UtcNow
if ($g.Date) {
    try {
        $wd = [DateTime]::Parse($g.Date, [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]'AdjustToUniversal,AssumeUniversal')
        $mid = $t0.AddTicks([long](($t1 - $t0).Ticks / 2))
        $o.internetTimeUtc = $wd.ToString('o'); $o.pcClockUtc = $mid.ToString('o')
        $o.offsetSeconds = [math]::Round(($mid - $wd).TotalSeconds, 1)
    } catch { $o.errors += "date: $($_.Exception.Message)" }
} else { $o.errors += "internet time: $($g.Error)" }
$p = Get-Url 'https://api.ipify.org' 6000
if ($p.Ok) { $o.publicIp = $p.Body.Trim() } else { $o.errors += "public ip: $($p.Error)" }
[pscustomobject]$o
'@

$script:JobOui = @'
$lines = New-Object System.Collections.Generic.List[string]
$src = ''; $err = ''
$r = Get-Url 'https://standards-oui.ieee.org/oui/oui.csv' 90000
if ($r.Ok -and $r.Body -match 'Registry,Assignment') {
    $src = 'IEEE oui.csv'
    foreach ($row in ($r.Body | ConvertFrom-Csv)) {
        if ($row.Registry -eq 'MA-L' -and $row.Assignment -match '^[0-9A-Fa-f]{6}$') { $lines.Add($row.Assignment.ToUpper() + "`t" + ([string]$row.'Organization Name').Trim()) }
    }
} else { $err = "IEEE: $($r.Error)" }
if ($lines.Count -lt 1000) {
    $lines.Clear()
    $r = Get-Url 'https://www.wireshark.org/download/automated/data/manuf' 90000
    if ($r.Ok) {
        $src = 'Wireshark manuf'
        foreach ($l in ($r.Body -split "`n")) {
            if ($l -match '^([0-9A-Fa-f]{2}):([0-9A-Fa-f]{2}):([0-9A-Fa-f]{2})\t([^\t\r]+)(?:\t([^\r]+))?') {
                $nm = if ($Matches[5]) { $Matches[5] } else { $Matches[4] }
                $lines.Add(($Matches[1] + $Matches[2] + $Matches[3]).ToUpper() + "`t" + $nm.Trim())
            }
        }
    } else { $err += "; Wireshark: $($r.Error)" }
}
if ($lines.Count -ge 1000) {
    $dir = Split-Path $a.Path -Parent
    if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    [System.IO.File]::WriteAllLines($a.Path, [string[]]$lines.ToArray(), (New-Object System.Text.UTF8Encoding($false)))
}
[pscustomobject]@{ count = $lines.Count; source = $src; error = $err }
'@

function Init-Bg {
    if ($script:Pool) { return }
    try {
        $script:Pool = [runspacefactory]::CreateRunspacePool(1, 3)
        $script:Pool.Open()
    } catch { Write-Log "[background] $($_.Exception.Message)"; $script:Pool = $null }
}

function Close-Bg {
    foreach ($j in @($script:Jobs)) { try { $j.PS.Stop(); $j.PS.Dispose() } catch {} }
    $script:Jobs.Clear()
    if ($script:Pool) { try { $script:Pool.Close(); $script:Pool.Dispose() } catch {}; $script:Pool = $null }
}

function Start-BgJob {
    param([string]$Kind, [string]$Key, [string]$Body, $Arg)
    if (-not $script:Pool) { return }
    try {
        $ps = [powershell]::Create()
        $ps.RunspacePool = $script:Pool
        [void]$ps.AddScript("param(`$a)`n" + $script:BgCommon + "`n" + $Body).AddArgument($Arg)
        $h = $ps.BeginInvoke()
        [void]$script:Jobs.Add([pscustomobject]@{ Kind = $Kind; Key = $Key; PS = $ps; H = $h; Start = (Get-Date) })
    } catch { Write-Log "[background start] $Kind ${Key}: $($_.Exception.Message)" }
}

function Receive-BgJobs {
    for ($i = $script:Jobs.Count - 1; $i -ge 0; $i--) {
        $j = $script:Jobs[$i]
        $done = $j.H.IsCompleted
        if (-not $done -and ((Get-Date) - $j.Start).TotalSeconds -gt 240) {
            try { $j.PS.Stop() } catch {}
            Write-Log "[background] $($j.Kind) $($j.Key) timed out"
            if ($j.Kind -eq 'identity') { $script:IdPending.Remove($j.Key) }
            try { $j.PS.Dispose() } catch {}
            $script:Jobs.RemoveAt($i); continue
        }
        if (-not $done) { continue }
        $out = $null
        try { $res = $j.PS.EndInvoke($j.H); if ($res -and $res.Count -gt 0) { $out = $res[0] } } catch { Write-Log "[background] $($j.Kind) $($j.Key): $($_.Exception.Message)" }
        try { $j.PS.Dispose() } catch {}
        $script:Jobs.RemoveAt($i)
        try {
            switch ($j.Kind) {
                'identity' { Complete-Identity $j.Key $out }
                'trace'    { Complete-Trace $j.Key $out }
                'clock'    { Complete-Clock $out }
                'oui'      { Complete-Oui $out }
            }
        } catch { Write-Log "[background result] $($j.Kind) $($j.Key): $($_.Exception.Message)" }
    }
}

function Wait-BgJobs {
    param([int]$TimeoutSec = 120)
    $end = (Get-Date).AddSeconds($TimeoutSec)
    while ((Get-Date) -lt $end -and ($script:Jobs.Count -gt 0 -or $script:IdQueue.Count -gt 0)) {
        Pump-Jobs
        Start-Sleep -Milliseconds 300
    }
    Receive-BgJobs
}

# -------- identity (who is this address?) -----------------------------------
function Queue-Identity {
    param([string]$Ip, [switch]$Force)
    if (-not $Ip) { return }
    if ((Get-Origin $Ip) -eq 'This PC') { return }
    if (-not $Force -and -not $Config.AutoIdentify) { return }
    if (-not $Force -and $script:IdentityCache.ContainsKey($Ip)) { return }
    if ($script:IdPending.ContainsKey($Ip)) { return }
    if ($Force) { Start-IdentityJob $Ip; return }
    if (-not $script:IdQueue.Contains($Ip)) { $script:IdQueue.Enqueue($Ip) }
}

function Start-IdentityJob {
    param([string]$Ip)
    $script:IdPending[$Ip] = $true
    Start-BgJob 'identity' $Ip $script:JobIdentity @{ Ip = $Ip; Origin = (Get-Origin $Ip); GeoUrl = $Config.IpLookupUrl; RdapUrl = $Config.RdapUrl }
}

function Complete-Identity {
    param([string]$Ip, $Out)
    $script:IdPending.Remove($Ip)
    if (-not $Out) { return }
    $d = [ordered]@{}
    foreach ($pp in $Out.PSObject.Properties) { $d[$pp.Name] = $pp.Value }
    $mac = ''
    if ((Get-Origin $Ip) -eq 'Home network' -and $script:NeighborMap.ContainsKey($Ip)) { $mac = $script:NeighborMap[$Ip] }
    $d['mac'] = $mac
    $d['macMaker'] = Get-MacMaker $mac
    $obj = [pscustomobject]$d
    $script:IdentityCache[$Ip] = $obj
    $script:IpCache.Remove($Ip)
    $script:SummaryDirty = $true
    Write-Evidence 'IDENTITY' $d
    $bits = @($obj.reverseDns, $obj.country, $obj.isp, $obj.asn, $obj.netName, $obj.abuseContact, $obj.macMaker) | Where-Object { $_ }
    Write-Log ("[identity] $Ip -> " + ($bits -join ' | '))
}

function Format-Identity {
    param([string]$Ip)
    $d = $script:IdentityCache[$Ip]
    $loc = (@($d.city, $d.region, $d.country) | Where-Object { $_ }) -join ', '
    $one = if ($d.country -or $d.isp) { "$($d.country) / $($d.isp)" }
           elseif ($d.netName) { "$($d.netName) $($d.netCountry)".Trim() }
           elseif ($d.reverseDns) { $d.reverseDns }
           else { "$Ip (no details found)" }
    $L = New-Object System.Collections.Generic.List[string]
    $L.Add("IP:       $Ip")
    if ($d.reverseDns)   { $L.Add("Name:     $($d.reverseDns)") }
    if ($loc)            { $L.Add("Where:    $loc") }
    if ($d.isp)          { $L.Add("ISP:      $($d.isp)") }
    if ($d.org)          { $L.Add("Owner:    $($d.org)") }
    if ($d.asn)          { $L.Add("AS:       $($d.asn)") }
    if ($d.netName)      { $L.Add("Network:  $($d.netName) $($d.netRange)") }
    if ($d.registrant)   { $L.Add("Holder:   $($d.registrant)") }
    if ($d.abuseContact) { $L.Add("Abuse:    $($d.abuseContact)") }
    return [pscustomobject]@{ One = $one; Full = ($L -join "`n") }
}

# -------- traceroute ----------------------------------------------------------
function Queue-Trace {
    param([string]$Ip, [string]$Reason, [switch]$Force)
    if (-not $Ip) { return }
    if (-not $Force) {
        if (-not $Config.AutoTraceroute) { return }
        if ((Get-Origin $Ip) -ne 'Internet') { return }
        if ($script:TraceDone.ContainsKey($Ip)) { return }
    }
    if ((Get-Origin $Ip) -eq 'This PC') { return }
    $script:TraceDone[$Ip] = $true
    Write-Evidence 'TRACEROUTE-START' ([ordered]@{ ip = $Ip; reason = $Reason; maxHops = $Config.TraceMaxHops })
    Start-BgJob 'trace' $Ip $script:JobTrace @{ Ip = $Ip; Hops = $Config.TraceMaxHops; WaitMs = $Config.TraceWaitMs; Reason = $Reason }
    Write-Log "[trace] Traceroute to $Ip started ($Reason)"
}

function Complete-Trace {
    param([string]$Ip, $Out)
    if (-not $Out) { Write-Evidence 'TRACEROUTE' ([ordered]@{ ip = $Ip; error = 'traceroute produced no result' }); return }
    $d = [ordered]@{}
    foreach ($pp in $Out.PSObject.Properties) { $d[$pp.Name] = $pp.Value }
    Write-Evidence 'TRACEROUTE' $d
    [void]$script:TraceResults.Add($Out)
    $n = @($Out.hops).Count
    $answered = @($Out.hops | Where-Object { $_ -match '\d+\.\d+\.\d+\.\d+|[0-9a-f]*:[0-9a-f:]+' }).Count
    Raise-Alert INFO 'Traceroute recorded' "$Ip - $n hops tried, $answered answered. Saved in the evidence journal." "trace-$Ip-$(Get-Date -Format HHmmss)"
}

# -------- clock check -------------------------------------------------------
function Start-ClockJob {
    $script:LastClock = Get-Date
    Start-BgJob 'clock' 'clock' $script:JobClock @{}
}

function Complete-Clock {
    param($Out)
    if (-not $Out) { return }
    $d = [ordered]@{}
    foreach ($pp in $Out.PSObject.Properties) { $d[$pp.Name] = $pp.Value }
    $script:LastClockInfo = $Out
    Write-Evidence 'CLOCK' $d
    if ($null -ne $Out.offsetSeconds) {
        Write-Log "[clock] PC clock offset vs internet time: $($Out.offsetSeconds)s (positive = PC ahead). Public IP $($Out.publicIp)"
        if ([math]::Abs([double]$Out.offsetSeconds) -gt $Config.ClockWarnSeconds) {
            Raise-Alert MED 'Clock wrong' "This PC's clock is $($Out.offsetSeconds) seconds out from internet time. Logged times can be corrected by this amount." 'clock-wrong'
        }
    }
}

# -------- MAC makers ----------------------------------------------------------
function Load-Vendors {
    $p = Join-Path $Config.DataDir 'vendors.txt'
    $fresh = $false
    if (Test-Path -LiteralPath $p) {
        try {
            $v = @{}
            foreach ($l in [System.IO.File]::ReadAllLines($p, $script:Utf8NoBom)) {
                $t = $l.IndexOf("`t")
                if ($t -eq 6) { $v[$l.Substring(0, 6)] = $l.Substring(7) }
            }
            if ($v.Count -gt 0) { $script:Vendors = $v }
            $fresh = ((Get-Date) - (Get-Item -LiteralPath $p).LastWriteTime).TotalDays -lt $Config.VendorRefreshDays
        } catch { Write-Log "[vendors] $($_.Exception.Message)" }
    }
    if (-not $fresh -and -not $script:OuiTried) {
        $script:OuiTried = $true
        Start-BgJob 'oui' 'oui' $script:JobOui @{ Path = $p }
    }
}

function Complete-Oui {
    param($Out)
    if ($Out -and $Out.count -ge 1000) {
        Write-Log "[vendors] MAC maker list downloaded: $($Out.count) makers from $($Out.source)"
        Load-Vendors
    } elseif ($Out) { Write-Log "[vendors] MAC maker list not downloaded: $($Out.error)" }
}

function Get-MacMaker {
    param([string]$Mac)
    if (-not $Mac) { return '' }
    $h = ($Mac -replace '[^0-9A-Fa-f]', '').ToUpper()
    if ($h.Length -lt 6) { return '' }
    $b0 = [Convert]::ToInt32($h.Substring(0, 2), 16)
    if ($b0 -band 2) { return 'Private/randomised MAC (maker hidden)' }
    $k = $h.Substring(0, 6)
    if ($script:Vendors.ContainsKey($k)) { return $script:Vendors[$k] }
    if ($script:Vendors.Count -eq 0) { return '(maker list not loaded yet)' }
    return 'Unknown maker'
}

# -------- snapshots of this PC's sockets / neighbours / processes ------------
function Update-Snapshots {
    $nm = @{}
    try {
        foreach ($n in (Get-NetNeighbor -ErrorAction Stop)) {
            $m = [string]$n.LinkLayerAddress
            if ($m -and $m -ne '00-00-00-00-00-00' -and [string]$n.State -ne 'Unreachable') { $nm[[string]$n.IPAddress] = $m }
        }
    } catch { }
    $script:NeighborMap = $nm
    $lt = @{}; $lu = @{}; $lp = @{}
    try {
        foreach ($c in (Get-NetTCPConnection -ErrorAction Stop)) {
            if ([string]$c.State -eq 'Listen') { $lt[[int]$c.LocalPort] = [int]$c.OwningProcess } else { $lp[[int]$c.LocalPort] = [int]$c.OwningProcess }
        }
    } catch { }
    try { foreach ($u in (Get-NetUDPEndpoint -ErrorAction Stop)) { $lu[[int]$u.LocalPort] = [int]$u.OwningProcess } } catch { }
    $script:ListenTcp = $lt; $script:ListenUdp = $lu; $script:LocalTcpPort = $lp
    $pc = @{}
    try { foreach ($p in (Get-Process -ErrorAction SilentlyContinue)) { $pc[[int]$p.Id] = [string]$p.ProcessName } } catch { }
    $script:ProcCache = $pc
}

function Get-ProcName {
    param([int]$ProcId)
    if ($ProcId -le 0) { return '' }
    if ($ProcId -eq 4) { return 'System' }
    if ($script:ProcCache.ContainsKey($ProcId)) { return "$($script:ProcCache[$ProcId]) (pid $ProcId)" }
    return "pid $ProcId"
}

# -------- network context ----------------------------------------------------
function Get-NetContext {
    $ifs = @()
    try {
        foreach ($c in (Get-NetIPConfiguration -ErrorAction Stop)) {
            if ($c.NetAdapter -and [string]$c.NetAdapter.Status -ne 'Up') { continue }
            $gw = @()
            $gw += @($c.IPv4DefaultGateway | ForEach-Object { [string]$_.NextHop })
            $gw += @($c.IPv6DefaultGateway | ForEach-Object { [string]$_.NextHop })
            $gwMac = @($gw | Where-Object { $script:NeighborMap.ContainsKey($_) } | ForEach-Object { "$_ = $($script:NeighborMap[$_])" })
            $ifs += [ordered]@{
                alias       = [string]$c.InterfaceAlias
                index       = [int]$c.InterfaceIndex
                description = [string]$c.InterfaceDescription
                mac         = [string]$c.NetAdapter.MacAddress
                ipv4        = @($c.IPv4Address | ForEach-Object { "$($_.IPAddress)/$($_.PrefixLength)" })
                ipv6        = @($c.IPv6Address | ForEach-Object { "$($_.IPAddress)/$($_.PrefixLength)" })
                gateway     = $gw
                gatewayMac  = $gwMac
                dns         = @($c.DNSServer | ForEach-Object { $_.ServerAddresses })
                profile     = [string]$c.NetProfile.Name
                category    = [string]$c.NetProfile.NetworkCategory
            }
        }
    } catch { }
    $wifi = @()
    try {
        $cur = $null
        foreach ($l in (& netsh.exe wlan show interfaces 2>$null)) {
            if ($l -match '^\s*(Name|SSID|AP BSSID|BSSID|Radio type|Authentication|Cipher|Channel|State)\s*:\s*(.*)$') {
                $k = $Matches[1]; $v = $Matches[2].Trim()
                if ($k -eq 'Name') { if ($cur) { $wifi += $cur }; $cur = [ordered]@{} }
                if ($cur) { $cur[$k] = $v }
            }
        }
        if ($cur) { $wifi += $cur }
    } catch { }
    return [ordered]@{ computer = $env:COMPUTERNAME; interfaces = $ifs; wifi = $wifi }
}

function Update-NetContext {
    param([switch]$Force)
    if (-not $Force -and ((Get-Date) - $script:LastNet).TotalSeconds -lt $Config.NetContextSeconds) { return }
    $script:LastNet = Get-Date
    $ctx = Get-NetContext
    $sig = $ctx | ConvertTo-Json -Compress -Depth 8
    if ($sig -ne $script:NetSig) {
        $first = -not $script:NetSig
        $script:NetSig = $sig
        $script:NetContext = $ctx
        Build-AllowList
        Write-Evidence 'NETWORK' $ctx
        if (-not $first) { Write-Log '[network] Network connection changed - new details recorded in the evidence journal.' }
    }
}

# ===========================================================================
#   LOOKUPS / ACTIONS
# ===========================================================================
function Get-IpInfo {
    param([string]$ip)
    if ($script:IdentityCache.ContainsKey($ip) -and (Get-Origin $ip) -eq 'Internet') { return (Format-Identity $ip) }
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
                    Full = "IP:       $ip`nWhere:    $loc`nISP:      $($j.isp)`nOwner:    $($j.org)`nAS:       $($j.as)"
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
        $rules = @(Get-NetFirewallRule -Group $Config.FirewallGroup -ErrorAction SilentlyContinue)
        $names = @($rules | ForEach-Object { [string]$_.DisplayName })
        $rules | Remove-NetFirewallRule -ErrorAction SilentlyContinue
        Write-Evidence 'UNBLOCK' ([ordered]@{ rulesRemoved = $names })
        Raise-Alert INFO 'Blocks cleared' "All Intrusion Monitor firewall blocks removed ($($names.Count) rules)."
    } catch { Write-Log "[unblock] $($_.Exception.Message)" }
}

function Invoke-Elevate {
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
        $made = @("IM-Block-IN-$ip-$ts")
        New-NetFirewallRule -DisplayName "IM-Block-IN-$ip-$ts" -Group $Config.FirewallGroup -Direction Inbound  -RemoteAddress $ip -Action Block -Profile Any -ErrorAction Stop | Out-Null
        if ($Config.BlockBothDirections) {
            New-NetFirewallRule -DisplayName "IM-Block-OUT-$ip-$ts" -Group $Config.FirewallGroup -Direction Outbound -RemoteAddress $ip -Action Block -Profile Any -ErrorAction Stop | Out-Null
            $made += "IM-Block-OUT-$ip-$ts"
        }
        Write-Evidence 'BLOCK' ([ordered]@{ ip = $ip; rules = $made; bothDirections = [bool]$Config.BlockBothDirections })
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
    Write-Evidence 'ALERT' ([ordered]@{ severity = $Severity; category = $Category; detail = $Detail; ip = $Ip; direction = $Direction })
    [void]$script:AlertHistory.Add([pscustomobject]@{ Utc = (Format-Utc $now); Severity = $Severity; Category = $Category; Detail = $Detail; Ip = $Ip })

    # internet attacker: find out who they are and trace the route (recorded as evidence)
    if ($Ip -and $Severity -eq 'HIGH' -and (Get-Origin $Ip) -eq 'Internet' -and $Category -ne 'Blocked') {
        Queue-Identity $Ip
        Queue-Trace $Ip "automatic: $Category"
    }
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
    if ($Severity -eq 'HIGH' -and $form -and $form.IsHandleCreated) {
        try { $form.Invoke([Action]{ if ($form.WindowState -eq 'Minimized') { $form.WindowState = 'Normal' }; $form.Activate() }) } catch {}
    }
    if ($Severity -eq 'HIGH' -and $Ip -and $Category -ne 'Blocked') {
        Show-InteractiveAlert -Category $Category -Detail $Detail -Ip $Ip -Direction $Direction
        if ($Config.AutoBlockOnHigh) { Disconnect-Ip -ip $Ip }
    }
}

function Show-InteractiveAlert {
    param([string]$Category,[string]$Detail,[string]$Ip,[string]$Direction)
    $info = Get-IpInfo $Ip
    $f = New-Object System.Windows.Forms.Form
    $f.Text = "ALERT: $Category"
    $f.Size = New-Object System.Drawing.Size(640, 460)
    $f.StartPosition = 'CenterScreen'
    $f.TopMost = $true
    $f.BackColor = [System.Drawing.ColorTranslator]::FromHtml($Config.BackColor)

    $lbl = New-Object System.Windows.Forms.Label
    $lbl.ForeColor = [System.Drawing.ColorTranslator]::FromHtml($Config.HighColor)
    $lbl.Font = New-Object System.Drawing.Font($Config.FontName, ($Config.FontSize + 2), [System.Drawing.FontStyle]::Bold)
    $lbl.AutoSize = $true; $lbl.Location = New-Object System.Drawing.Point(16,14)
    $lbl.Text = "! $Category"
    $f.Controls.Add($lbl)

    $dirTxt = if ($Direction) { "Direction: $Direction`r`n" } else { "" }
    $evTxt = if ((Get-Origin $Ip) -eq 'Internet') { "`r`n`r`nWho-is details and a traceroute are being recorded in the evidence journal." } else { "" }
    $box = New-Object System.Windows.Forms.TextBox
    $box.Multiline = $true; $box.ReadOnly = $true; $box.BorderStyle = 'None'; $box.ScrollBars = 'Vertical'
    $box.BackColor = [System.Drawing.ColorTranslator]::FromHtml($Config.BackColor)
    $box.ForeColor = [System.Drawing.ColorTranslator]::FromHtml($Config.TextColor)
    $box.Font = New-Object System.Drawing.Font($Config.FontName, ($Config.FontSize - 1))
    $box.Location = New-Object System.Drawing.Point(18,56)
    $box.Size = New-Object System.Drawing.Size(590, 280)
    $box.Text = "$Detail`r`n`r`n$dirTxt`r`n$($info.Full -replace "`n", "`r`n")$evTxt"
    $f.Controls.Add($box)

    $block = New-Object System.Windows.Forms.Button
    $block.Text = "Disconnect & Block"
    $block.Size = New-Object System.Drawing.Size(220,40)
    $block.Location = New-Object System.Drawing.Point(18,352)
    $block.FlatStyle = 'Flat'; $block.ForeColor = [System.Drawing.ColorTranslator]::FromHtml($Config.HighColor)
    $block.Font = New-Object System.Drawing.Font($Config.FontName, ($Config.FontSize-2), [System.Drawing.FontStyle]::Bold)
    $block.Tag = $Ip
    $block.Add_Click({ $frm = $this.FindForm(); Disconnect-Ip -ip ([string]$this.Tag); $frm.Close() })
    if (-not $script:IsAdmin) { $block.Enabled = $false; $block.Text = "Block (needs admin)" }
    $f.Controls.Add($block)

    $dismiss = New-Object System.Windows.Forms.Button
    $dismiss.Text = "Dismiss"; $dismiss.Size = New-Object System.Drawing.Size(140,40)
    $dismiss.Location = New-Object System.Drawing.Point(254,352)
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
               Select-Object IPAddress, LinkLayerAddress
    } catch { return }
    $ips = @($now | ForEach-Object { [string]$_.IPAddress } | Select-Object -Unique)
    if ($script:FirstSweep -or -not $script:ArpBaseline) { $script:ArpBaseline = $ips; return }
    foreach ($n in $now) {
        $ip = [string]$n.IPAddress
        if ($script:ArpBaseline -notcontains $ip) {
            $mac = [string]$n.LinkLayerAddress
            $mk = Get-MacMaker $mac
            Write-Evidence 'NEIGHBOUR' ([ordered]@{ ip = $ip; mac = $mac; macMaker = $mk })
            Raise-Alert INFO 'New network neighbour' "New device on local segment: $ip  MAC $mac  ($mk)" "arp-$ip"
        }
    }
    $script:ArpBaseline = $ips
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

function Get-CountText {
    param([hashtable]$H, [int]$Max = 4)
    $items = @($H.GetEnumerator() | Sort-Object -Property Value -Descending | Select-Object -First $Max)
    return (($items | ForEach-Object { "$($_.Key) x$($_.Value)" }) -join '; ')
}

function Add-Attempt {
    param([string]$Ip,[int]$Port,[string]$Proto,[string]$Action,[string]$Via,[object]$When,[hashtable]$Extra)
    if (-not $When) { $When = Get-Date }
    if (-not $Extra) { $Extra = @{} }
    $isNew = -not $script:Inbound.ContainsKey($Ip)
    if ($isNew) {
        $script:Inbound[$Ip] = [pscustomobject]@{
            Ip = $Ip; Origin = (Get-Origin $Ip); Attempts = 0; Dropped = 0; Allowed = 0; Ports = @{}
            First = $When; Last = $When; Recent = (New-Object System.Collections.ArrayList); Alerted = $false
            Mac = ''; Maker = ''; Apps = @{}; Senders = @{}
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

    # --- forensic enrichment ---
    $dstIp   = [string]$Extra.DstIp
    $srcPort = [string]$Extra.SrcPort
    $iface   = if ($dstIp -and $script:LocalIfaceMap.ContainsKey($dstIp)) { $script:LocalIfaceMap[$dstIp] } else { '' }
    $mac = ''
    if ($r.Origin -eq 'Home network' -and $script:NeighborMap.ContainsKey($Ip)) { $mac = $script:NeighborMap[$Ip] }
    if ($mac -and $mac -ne $r.Mac) { $r.Mac = $mac; $r.Maker = Get-MacMaker $mac }
    $procId = 0
    if ($Extra.Pid) { [void][int]::TryParse([string]$Extra.Pid, [ref]$procId) }
    if ($procId -le 0) {
        if ($Proto -eq 'TCP' -and $script:ListenTcp.ContainsKey($Port)) { $procId = $script:ListenTcp[$Port] }
        elseif ($Proto -eq 'UDP' -and $script:ListenUdp.ContainsKey($Port)) { $procId = $script:ListenUdp[$Port] }
    }
    $recvBy = if ($pk -eq 'ICMP') { 'Windows (ping)' } elseif ($procId -gt 0) { Get-ProcName $procId } else { 'nothing listening' }
    if ($r.Apps.ContainsKey($recvBy)) { $r.Apps[$recvBy] = $r.Apps[$recvBy] + 1 } else { $r.Apps[$recvBy] = 1 }
    $sender = ''
    if ($r.Origin -eq 'This PC' -and $srcPort -match '^\d+$' -and $script:LocalTcpPort.ContainsKey([int]$srcPort)) {
        $sender = Get-ProcName $script:LocalTcpPort[[int]$srcPort]
        if ($r.Senders.ContainsKey($sender)) { $r.Senders[$sender] = $r.Senders[$sender] + 1 } else { $r.Senders[$sender] = 1 }
    }

    $act = switch ($Action) { 'DROP' { 'refused' } 'ALLOW' { 'allowed' } default { $Action.ToLower() } }
    $portOut = if ($pk -eq 'ICMP') { '' } else { $Port }
    $utcS = Format-Utc $When; $locS = Format-Local $When
    $script:AttemptBuf.Add((@(
        $utcS, $locS, $Ip, $r.Origin, $portOut, $Proto, $act, (CsvQ $recvBy), $dstIp, (CsvQ $iface),
        $r.Mac, (CsvQ $r.Maker), (CsvQ $sender), $Via, (CsvQ $Extra.Raw)) -join ','))

    if ($r.Origin -ne 'This PC' -or $Config.EvidenceIncludeThisPc) {
        Write-Evidence 'ATTEMPT' ([ordered]@{
            eventUtc = $utcS; eventLocal = $locS
            sourceIp = $Ip; sourcePort = $srcPort; from = $r.Origin
            destIp = $dstIp; destPort = $portOut; protocol = $Proto; action = $act
            receivedBy = $recvBy; interface = $iface
            sourceMac = $r.Mac; sourceMacMaker = $r.Maker; senderApp = $sender
            via = $Via; raw = [string]$Extra.Raw
        })
    }
    if ($isNew -and $r.Origin -ne 'This PC') { Queue-Identity $Ip }
}

function Read-FirewallNew {
    $lines = New-Object System.Collections.Generic.List[string]
    $path = $Config.FwLogPath
    if (-not $path -or -not (Test-Path $path)) { return ,$lines }
    $fs = $null
    try {
        $fs = [System.IO.File]::Open($path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
        $script:FwReadable = $true
        $len = $fs.Length
        if ($script:FwPos -lt 0) { $script:FwPos = $len; return ,$lines }
        if ($len -lt $script:FwPos) { $script:FwPos = 0; $script:FwTail = '' }
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
    return ,$lines
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
        if ($path -ne 'RECEIVE') { return }
    } elseif ($action -eq 'ALLOW') {
        return
    }
    $proto = $p[3]; $src = $p[4]; $dst = $p[5]; $sport = $p[6]; $dport = $p[7]
    if ($dport -notmatch '^[0-9]+$') {
        if ($proto -like 'ICMP*') { $dport = '0' } else { return }
    }
    if (Test-SkipAddress $src $dst) { return }
    $dt = [datetime]::MinValue
    if (-not [datetime]::TryParse("$($p[0]) $($p[1])", [ref]$dt)) { $dt = Get-Date }
    $fwPid = ''
    if ($p.Count -gt 17 -and $p[17] -match '^\d+$') { $fwPid = $p[17] }
    Add-Attempt -Ip $src -Port ([int]$dport) -Proto $proto -Action $action -Via 'firewall' -When $dt -Extra @{
        SrcPort = $sport; DstIp = $dst; Pid = $fwPid; Raw = $Line.Trim()
    }
    return $src
}

function Check-InboundTcp {
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
            Add-Attempt -Ip $ra -Port ([int]$c.LocalPort) -Proto 'TCP' -Action 'CONNECTED' -Via 'tcp' -When $now -Extra @{
                SrcPort = [string]$c.RemotePort; DstIp = [string]$c.LocalAddress; Pid = [string]$c.OwningProcess
                Raw = "TCP $($c.State) $($c.RemoteAddress):$($c.RemotePort) -> $($c.LocalAddress):$($c.LocalPort) pid $($c.OwningProcess)"
            }
            $Touched[$ra] = $true
        }
    }
    $script:TcpSeen = $live
}

function Check-Inbound {
    if (-not $Config.TrackInbound) { return }
    $touched = @{}
    $new = Read-FirewallNew
    if ($new.Count -gt 0 -or (-not $script:FwReadable -and -not $script:TestMode)) { Update-Snapshots }
    foreach ($ln in $new) {
        $ip = Process-FwLine $ln
        if ($ip) { $touched[$ip] = $true }
    }
    if (-not $script:FwReadable -and -not $script:TestMode) { Check-InboundTcp $touched }
    $cutoff = (Get-Date).AddSeconds(-$Config.PortScanWindowSeconds)
    foreach ($ip in @($touched.Keys)) {
        $r = $script:Inbound[$ip]
        for ($i = $r.Recent.Count - 1; $i -ge 0; $i--) { if ($r.Recent[$i].T -lt $cutoff) { $r.Recent.RemoveAt($i) } }
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
            $f = Join-Path $Config.LogDir ("Connections_{0}.csv" -f [datetime]::UtcNow.ToString('yyyyMMdd', $script:Inv))
            if (-not (Test-Path $f)) {
                Set-Content -Path $f -Value 'TimeUTC,TimeLocal,SourceIP,From,Port,Protocol,Action,ReceivedBy,LocalAddress,Interface,SourceMAC,Maker,SenderApp,Source,RawFirewallLine' -Encoding UTF8
            }
            Add-Content -Path $f -Value $script:AttemptBuf.ToArray() -Encoding UTF8
        } catch { Write-Log "[connections log] $($_.Exception.Message)" }
    }
    $script:AttemptBuf.Clear()
}

function Get-SortedInbound {
    $rank = @{ 'Internet' = 0; 'Home network' = 1; 'This PC' = 2 }
    return @($script:Inbound.Values | Sort-Object -Property @{ Expression = { $rank[$_.Origin] } }, @{ Expression = { $_.Attempts }; Descending = $true })
}

function Get-Who {
    param($Rec)
    $id = $null
    if ($script:IdentityCache.ContainsKey($Rec.Ip)) { $id = $script:IdentityCache[$Rec.Ip] }
    switch ($Rec.Origin) {
        'This PC' {
            $s = Get-CountText $Rec.Senders 3
            if ($s) { return "sent by $s" } else { return 'an app on this PC' }
        }
        'Home network' {
            $bits = @()
            if ($id -and $id.reverseDns) { $bits += $id.reverseDns }
            if ($Rec.Maker) { $bits += $Rec.Maker }
            if ($Rec.Mac) { $bits += $Rec.Mac }
            if ($bits.Count) { return ($bits -join ' | ') } else { return 'a device on your home network' }
        }
        default {
            if ($id -and $id.reverseDns) { return $id.reverseDns }
            if ($id) { return '(no reverse DNS name)' }
            if ($script:IdPending.ContainsKey($Rec.Ip) -or $script:IdQueue.Contains($Rec.Ip)) { return '(looking up...)' }
            return ''
        }
    }
}

function Write-Summary {
    if (-not $script:SummaryDirty -or -not $Config.Logging) { return }
    $script:SummaryDirty = $false
    try {
        if (-not (Test-Path $Config.LogDir)) { New-Item -ItemType Directory -Path $Config.LogDir -Force | Out-Null }
        $f = Join-Path $Config.LogDir 'ConnectionSummary.csv'
        $out = New-Object System.Collections.Generic.List[string]
        $out.Add('SourceIP,From,Who,MAC,Maker,Attempts,Refused,Allowed,DistinctPorts,Ports,ReceivedBy,Country,ISP,Owner,ASN,NetworkName,NetworkRange,AbuseContact,FirstSeenUTC,LastSeenUTC,FirstSeenLocal,LastSeenLocal')
        foreach ($r in (Get-SortedInbound)) {
            $id = $null
            if ($script:IdentityCache.ContainsKey($r.Ip)) { $id = $script:IdentityCache[$r.Ip] }
            $out.Add((@(
                $r.Ip, $r.Origin, (CsvQ (Get-Who $r)), $r.Mac, (CsvQ $r.Maker),
                $r.Attempts, $r.Dropped, $r.Allowed, $r.Ports.Count, (CsvQ (Get-PortsText $r 0)), (CsvQ (Get-CountText $r.Apps 5)),
                (CsvQ $id.country), (CsvQ $id.isp), (CsvQ $id.org), (CsvQ $id.asn), (CsvQ $id.netName), (CsvQ $id.netRange), (CsvQ $id.abuseContact),
                (Format-Utc $r.First), (Format-Utc $r.Last), (CsvQ (Format-Local $r.First)), (CsvQ (Format-Local $r.Last))) -join ','))
        }
        Set-Content -Path $f -Value $out.ToArray() -Encoding UTF8
    } catch { Write-Log "[summary] $($_.Exception.Message)" }
}

# ===========================================================================
#   EVIDENCE PACK
# ===========================================================================
function New-IncidentSummary {
    param([string]$Stamp, [string]$FwNote, $Verify)
    $L = New-Object System.Collections.Generic.List[string]
    $nowU = [datetime]::UtcNow
    $tz = [TimeZoneInfo]::Local
    $L.Add('INTRUSION MONITOR - INCIDENT SUMMARY')
    $L.Add('====================================')
    $L.Add("Evidence pack:      EvidencePack_$Stamp.zip")
    $L.Add("Generated (UTC):    $(Format-Utc $nowU)")
    $L.Add("Generated (local):  $(Format-Local $nowU)   time zone: $($tz.Id)")
    $L.Add("Computer:           $env:COMPUTERNAME")
    $L.Add("Windows:            $([Environment]::OSVersion.VersionString)")
    $L.Add("Tool:               Intrusion Monitor $($script:Version)   script SHA-256: $($script:ScriptHash)")
    $L.Add("Running as admin:   $($script:IsAdmin)")
    $L.Add("Journal check:      $(if ($Verify.Ok) { 'PASS' } else { 'FAIL - see Verification.txt' })   ($($Verify.Records) records in $($Verify.Files) files)")
    $L.Add("Firewall log:       $FwNote")
    $L.Add('')
    $L.Add('CLOCK')
    if ($script:LastClockInfo -and $null -ne $script:LastClockInfo.offsetSeconds) {
        $c = $script:LastClockInfo
        $L.Add("  Checked (UTC):          $($c.checkedUtc)")
        $L.Add("  PC clock vs internet:   $($c.offsetSeconds) seconds (positive = PC was ahead)")
        $L.Add("  Windows time source:    $($c.windowsTimeSource)")
        $L.Add("  Public IP of this PC:   $($c.publicIp)")
    } else { $L.Add('  Not checked (no internet at the time, or not yet run).') }
    $L.Add('')
    $L.Add('NETWORK THIS PC WAS ON')
    if ($script:NetContext) {
        foreach ($i in @($script:NetContext.interfaces)) {
            $L.Add("  $($i.alias)  ($($i.description))  MAC $($i.mac)")
            $L.Add("     addresses: $(@($i.ipv4) + @($i.ipv6) -join ', ')")
            $L.Add("     gateway:   $(@($i.gateway) -join ', ')   gateway MAC: $(@($i.gatewayMac) -join ', ')")
            $L.Add("     DNS:       $(@($i.dns) -join ', ')   network: $($i.profile) ($($i.category))")
        }
        foreach ($w in @($script:NetContext.wifi)) {
            $L.Add("  Wi-Fi: SSID $($w['SSID'])  BSSID $($w['AP BSSID'])$($w['BSSID'])  $($w['Radio type'])  $($w['Authentication'])  channel $($w['Channel'])")
        }
    } else { $L.Add('  Not recorded.') }
    $L.Add('')
    $L.Add('SOURCES OF INCOMING CONNECTIONS (internet first)')
    $pcCount = 0; $pcAttempts = 0
    foreach ($r in (Get-SortedInbound)) {
        if ($r.Origin -eq 'This PC') { $pcCount++; $pcAttempts += $r.Attempts; continue }
        $id = $null
        if ($script:IdentityCache.ContainsKey($r.Ip)) { $id = $script:IdentityCache[$r.Ip] }
        $L.Add('')
        $L.Add("  $($r.Ip)   [$($r.Origin)]")
        $L.Add("     attempts $($r.Attempts)  refused $($r.Dropped)  let in $($r.Allowed)")
        $L.Add("     first seen  $(Format-Utc $r.First)   ($(Format-Local $r.First))")
        $L.Add("     last seen   $(Format-Utc $r.Last)   ($(Format-Local $r.Last))")
        $L.Add("     ports       $(Get-PortsText $r 0)")
        $L.Add("     received by $(Get-CountText $r.Apps 5)")
        if ($r.Mac) { $L.Add("     MAC         $($r.Mac)  ($($r.Maker))") }
        if ($id) {
            if ($id.reverseDns)   { $L.Add("     name        $($id.reverseDns)") }
            if ($id.country)      { $L.Add("     location    $((@($id.city, $id.region, $id.country) | Where-Object { $_ }) -join ', ')") }
            if ($id.isp)          { $L.Add("     ISP         $($id.isp)   owner: $($id.org)   $($id.asn)") }
            if ($id.netName)      { $L.Add("     network     $($id.netName)  $($id.netRange)  ($($id.netCountry))  registry: $($id.registry)") }
            if ($id.registrant)   { $L.Add("     holder      $($id.registrant)") }
            if ($id.abuseContact) { $L.Add("     ABUSE       $($id.abuseContact)   <- report the attack here") }
        }
    }
    $L.Add('')
    $L.Add("  Apps on this PC talking to each other: $pcCount addresses, $pcAttempts attempts (listed in the CSV files; not a threat).")
    $L.Add('')
    $L.Add('ALERTS')
    if ($script:AlertHistory.Count -eq 0) { $L.Add('  None this session.') }
    foreach ($a in $script:AlertHistory) { if ($a.Severity -ne 'INFO') { $L.Add("  $($a.Utc)  $($a.Severity)  $($a.Category): $($a.Detail)") } }
    $L.Add('')
    $L.Add('TRACEROUTES')
    if ($script:TraceResults.Count -eq 0) { $L.Add('  None this session (full detail of any earlier ones is in the journal).') }
    foreach ($t in $script:TraceResults) {
        $L.Add("  $($t.ip)  started $($t.startedUtc)  ($($t.reason))")
        foreach ($h in @($t.hops)) { $L.Add("     $h") }
    }
    $L.Add('')
    $L.Add('HOW TO CHECK THIS PACK')
    $L.Add('  1. MANIFEST.txt lists the SHA-256 of every file in the pack. Re-hash any file with')
    $L.Add("     PowerShell:  Get-FileHash -Algorithm SHA256 <file>   - it must match.")
    $L.Add('  2. The SHA-256 of the whole zip is in the matching .sha256.txt file next to it,')
    $L.Add('     taken the moment the pack was made. Note it down or send it separately.')
    $L.Add('  3. Evidence_*.jsonl: every record carries a hash of itself and of the record before')
    $L.Add('     it. Changing, removing or reordering any record breaks the chain. Verification.txt')
    $L.Add('     is the result of checking the chain when this pack was made. To re-check, run:')
    $L.Add('     powershell -ExecutionPolicy Bypass -File IntrusionMonitor.ps1 -VerifyDir <folder>')
    $L.Add('     (IntrusionMonitor.ps1.txt in this pack is the exact tool that recorded it - rename to .ps1.)')
    $L.Add('')
    $L.Add('NOTES')
    $L.Add('  Times are recorded in UTC and in local time. Windows Firewall log times are local time.')
    $L.Add('  Registry (RDAP/WHOIS), reverse DNS and location data describe who an address is')
    $L.Add('  registered to. They point to the network responsible, not necessarily the person.')
    $L.Add('  Nothing was sent to the source except standard lookups and a traceroute.')
    return $L.ToArray()
}

function Export-EvidencePack {
    try {
        Flush-AttemptLog; Write-Summary; Flush-Evidence
        $u = [datetime]::UtcNow
        $stamp = $u.ToString('yyyyMMdd-HHmmss', $script:Inv) + 'Z'
        $expDir = Join-Path $Config.LogDir 'export'
        $stage = Join-Path $expDir "_stage_$stamp"
        New-Item -ItemType Directory -Path $stage -Force | Out-Null
        Write-Evidence 'EXPORT' ([ordered]@{ pack = "EvidencePack_$stamp.zip"; note = 'Evidence pack being created. This record is the last one inside the pack.' })
        Flush-Evidence

        foreach ($pat in @('Evidence_*.jsonl','Evidence_*.seal.txt','Seals.txt','Connections_*.csv','ConnectionSummary.csv','IntrusionMonitor_*.log')) {
            Get-ChildItem -LiteralPath $Config.LogDir -Filter $pat -File -ErrorAction SilentlyContinue | ForEach-Object {
                Copy-Item -LiteralPath $_.FullName -Destination $stage -Force
            }
        }
        $fwNote = 'not copied'
        foreach ($fp in @($Config.FwLogPath, "$($Config.FwLogPath).old")) {
            if (-not $fp -or -not (Test-Path -LiteralPath $fp)) { continue }
            $src = $null; $dst = $null
            try {
                $src = [System.IO.File]::Open($fp, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
                $dst = [System.IO.File]::Create((Join-Path $stage ('Firewall_' + (Split-Path $fp -Leaf))))
                $src.CopyTo($dst)
                $fwNote = "copied from $($Config.FwLogPath)"
            } catch {
                if ($fwNote -eq 'not copied') { $fwNote = "not copied - $($_.Exception.Message) (press Elevate, then export again)" }
            } finally { if ($dst) { $dst.Dispose() }; if ($src) { $src.Dispose() } }
        }
        if ($script:ScriptPath) { Copy-Item -LiteralPath $script:ScriptPath -Destination (Join-Path $stage 'IntrusionMonitor.ps1.txt') -Force }

        $v = Test-EvidenceChain $Config.LogDir
        Set-Content -LiteralPath (Join-Path $stage 'Verification.txt') -Value $v.Report -Encoding UTF8
        Set-Content -LiteralPath (Join-Path $stage 'Incident_Summary.txt') -Value (New-IncidentSummary $stamp $fwNote $v) -Encoding UTF8

        $m = New-Object System.Collections.Generic.List[string]
        $m.Add("MANIFEST - EvidencePack_$stamp.zip")
        $m.Add("Created (UTC): $(Format-Utc $u)   Computer: $env:COMPUTERNAME")
        $m.Add('')
        $m.Add('SHA-256                                                           Bytes  File')
        foreach ($fi in (Get-ChildItem -LiteralPath $stage -File | Sort-Object Name)) {
            $fh = (Get-FileHash -LiteralPath $fi.FullName -Algorithm SHA256).Hash
            $m.Add(('{0}  {1,12}  {2}' -f $fh, $fi.Length, $fi.Name))
        }
        Set-Content -LiteralPath (Join-Path $stage 'MANIFEST.txt') -Value $m.ToArray() -Encoding UTF8

        $zip = Join-Path $expDir "EvidencePack_$stamp.zip"
        Compress-Archive -Path (Join-Path $stage '*') -DestinationPath $zip -CompressionLevel Optimal -Force
        $zh = (Get-FileHash -LiteralPath $zip -Algorithm SHA256).Hash
        Set-Content -LiteralPath "$zip.sha256.txt" -Value "$zh  EvidencePack_$stamp.zip" -Encoding ASCII
        $count = @(Get-ChildItem -LiteralPath $stage -File).Count
        Remove-Item -LiteralPath $stage -Recurse -Force -ErrorAction SilentlyContinue

        Write-Evidence 'EXPORT-DONE' ([ordered]@{ pack = "EvidencePack_$stamp.zip"; sha256 = $zh; files = $count; journalCheck = $(if ($v.Ok) { 'PASS' } else { 'FAIL' }) })
        Flush-Evidence
        Write-Log "[export] $zip  SHA-256 $zh"
        return [pscustomobject]@{ Zip = $zip; Sha256 = $zh; Verified = $v.Ok; Files = $count }
    } catch {
        Write-Log "[export] $($_.Exception.Message)"
        return $null
    }
}

# ===========================================================================
#   CONNECTIONS WINDOW
# ===========================================================================
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
        $where = ''; $abuse = ''
        switch ($r.Origin) {
            'This PC'      { $where = 'This computer' }
            'Home network' { $where = 'Your home network' }
            default {
                if ($script:IdentityCache.ContainsKey($r.Ip)) {
                    $where = (Format-Identity $r.Ip).One
                    $abuse = [string]$script:IdentityCache[$r.Ip].abuseContact
                } elseif ($script:IpCache.ContainsKey($r.Ip)) { $where = $script:IpCache[$r.Ip].One }
                else { $where = '(select, then Look up)' }
            }
        }
        $i = $g.Rows.Add($r.Ip, $r.Origin, (Get-Who $r), [int]$r.Attempts, [int]$r.Dropped, [int]$r.Allowed, [int]$r.Ports.Count,
                         (Get-PortsText $r 0), (Get-CountText $r.Apps 3), $r.Last.ToString('dd/MM HH:mm:ss'), $where, $abuse)
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
        $bg = if ($script:Jobs.Count) { "    Lookups running: $($script:Jobs.Count)" } else { '' }
        $script:ConnLabel.Text = "Addresses: $($script:Inbound.Count) ($fromNet from the internet)    Attempts: $total    Refused: $refused    Source: $src    Updated $(Get-Date -Format 'HH:mm:ss')$bg"
    }
}

function Show-Connections {
    if ($script:ConnForm -and -not $script:ConnForm.IsDisposed) {
        $script:ConnForm.WindowState = 'Normal'; $script:ConnForm.Activate(); Update-ConnGrid; return
    }
    $bg   = [System.Drawing.ColorTranslator]::FromHtml($Config.BackColor)
    $fg   = [System.Drawing.ColorTranslator]::FromHtml($Config.TextColor)
    $fnt  = New-Object System.Drawing.Font($Config.FontName, ($Config.FontSize - 3))
    $fntB = New-Object System.Drawing.Font($Config.FontName, ($Config.FontSize - 3), [System.Drawing.FontStyle]::Bold)

    $f = New-Object System.Windows.Forms.Form
    $f.Text = 'Intrusion Monitor - incoming connection attempts'
    $f.Size = New-Object System.Drawing.Size(1560, 760)
    $f.StartPosition = 'CenterScreen'
    $f.BackColor = $bg

    $lbl = New-Object System.Windows.Forms.Label
    $lbl.ForeColor = $fg; $lbl.Font = $fnt; $lbl.AutoSize = $true
    $lbl.Location = New-Object System.Drawing.Point(12, 10)
    $f.Controls.Add($lbl)

    $g = New-Object System.Windows.Forms.DataGridView
    $g.Location = New-Object System.Drawing.Point(12, 40)
    $g.Size = New-Object System.Drawing.Size(1520, 600)
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
        @('Ip', 'Source address', 11, $null),
        @('Origin', 'From', 7, $null),
        @('Who', 'Who (name / device)', 14, $null),
        @('Attempts', 'Attempts', 6, [int]),
        @('Refused', 'Refused', 6, [int]),
        @('Allowed', 'Let in', 5, [int]),
        @('PortCount', 'Ports', 4, [int]),
        @('Ports', 'Ports tried (port/protocol x count)', 18, $null),
        @('ReceivedBy', 'Received by (app on this PC)', 12, $null),
        @('Last', 'Last seen', 8, $null),
        @('Where', 'Where from', 12, $null),
        @('Abuse', 'Abuse contact', 12, $null)
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
        $b.Text = $text; $b.Location = New-Object System.Drawing.Point($x, 656)
        $b.Size = New-Object System.Drawing.Size(178, 36); $b.Anchor = 'Bottom,Left'
        $b.FlatStyle = 'Flat'; $b.ForeColor = $fg; $b.Font = $fnt
        $b
    }
    $bRefresh = & $mk 'Refresh' 12
    $bLookup  = & $mk 'Look up' 200
    $bTrace   = & $mk 'Trace route' 388
    $bBlock   = & $mk 'Block' 576
    $bExport  = & $mk 'Export evidence' 764
    $bVerify  = & $mk 'Verify logs' 952
    $bFolder  = & $mk 'Open logs' 1140
    $bClose   = & $mk 'Close' 1328
    $bRefresh.Add_Click({ Receive-BgJobs; Update-ConnGrid })
    $bLookup.Add_Click({
        $cg = $script:ConnGrid
        if ($cg -and $cg.CurrentRow) {
            $sip = [string]$cg.CurrentRow.Cells['Ip'].Value
            if ((Get-Origin $sip) -eq 'This PC') { return }
            Queue-Identity $sip -Force
            Update-ConnGrid
        }
    })
    $bTrace.Add_Click({
        $cg = $script:ConnGrid
        if ($cg -and $cg.CurrentRow) {
            $sip = [string]$cg.CurrentRow.Cells['Ip'].Value
            if ((Get-Origin $sip) -eq 'This PC') { return }
            Queue-Trace $sip 'manual: Trace route button' -Force
            [System.Windows.Forms.MessageBox]::Show("Traceroute to $sip started in the background. It can take up to a minute; the result goes into the evidence journal.","Intrusion Monitor") | Out-Null
        }
    })
    $bBlock.Add_Click({
        $cg = $script:ConnGrid
        if ($cg -and $cg.CurrentRow) { Disconnect-Ip -ip ([string]$cg.CurrentRow.Cells['Ip'].Value) }
    })
    if (-not $script:IsAdmin) { $bBlock.Enabled = $false; $bBlock.Text = 'Block (needs admin)' }
    $bExport.Add_Click({
        $this.Enabled = $false
        $res = Export-EvidencePack
        $this.Enabled = $true
        if ($res) {
            try { [System.Windows.Forms.Clipboard]::SetText($res.Sha256) } catch {}
            $chk = if ($res.Verified) { 'Journal check: PASS' } else { 'Journal check: FAIL - see Verification.txt inside the pack' }
            [System.Windows.Forms.MessageBox]::Show("Evidence pack saved:`n$($res.Zip)`n`nSHA-256 (copied to clipboard):`n$($res.Sha256)`n`n$chk`n`nKeep a note of the SHA-256 somewhere separate - it proves the pack has not been changed since now.","Intrusion Monitor") | Out-Null
            Start-Process explorer.exe "/select,`"$($res.Zip)`""
        } else {
            [System.Windows.Forms.MessageBox]::Show("Export failed - see the IntrusionMonitor log for the reason.","Intrusion Monitor") | Out-Null
        }
    })
    $bVerify.Add_Click({
        Flush-Evidence
        $v = Test-EvidenceChain $Config.LogDir
        Write-Evidence 'VERIFY' ([ordered]@{ result = $(if ($v.Ok) { 'PASS' } else { 'FAIL' }); files = $v.Files; records = $v.Records; problems = @($v.Problems | Select-Object -First 20) })
        Flush-Evidence
        $icon = if ($v.Ok) { [System.Windows.Forms.MessageBoxIcon]::Information } else { [System.Windows.Forms.MessageBoxIcon]::Warning }
        $txt = $v.Report
        if ($txt.Length -gt 3000) { $txt = $txt.Substring(0, 3000) + "`r`n..." }
        [System.Windows.Forms.MessageBox]::Show($txt, 'Intrusion Monitor - evidence check', [System.Windows.Forms.MessageBoxButtons]::OK, $icon) | Out-Null
    })
    $bFolder.Add_Click({
        $d = $Config.LogDir
        if (-not (Test-Path $d)) { New-Item -ItemType Directory -Path $d -Force | Out-Null }
        Start-Process explorer.exe $d
    })
    $bClose.Add_Click({ $this.FindForm().Close() })
    $f.Controls.AddRange(@($bRefresh, $bLookup, $bTrace, $bBlock, $bExport, $bVerify, $bFolder, $bClose))

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

function Write-StartRecord {
    $tz = [TimeZoneInfo]::Local
    Write-Evidence 'START' ([ordered]@{
        tool = 'Intrusion Monitor'; version = $script:Version; scriptSha256 = $script:ScriptHash
        computer = $env:COMPUTERNAME; windows = [Environment]::OSVersion.VersionString
        timeZone = $tz.Id; utcOffset = $tz.GetUtcOffset([datetime]::Now).ToString()
        elevated = [bool]$script:IsAdmin; testMode = [bool]$script:TestMode
        firewallLog = $Config.FwLogPath
        settings = [ordered]@{
            scanIntervalSeconds = $Config.ScanIntervalSeconds; trackInbound = $Config.TrackInbound
            logAllowedInbound = $Config.LogAllowedInbound; autoIdentify = $Config.AutoIdentify
            autoTraceroute = $Config.AutoTraceroute; autoBlockOnHigh = $Config.AutoBlockOnHigh
        }
    })
}

# -------- background pump ----------------------------------------------------
function Pump-Jobs {
    Receive-BgJobs
    $running = @($script:Jobs | Where-Object { $_.Kind -eq 'identity' }).Count
    $n = 0
    while ($script:IdQueue.Count -gt 0 -and $n -lt $Config.LookupsPerSweep -and $running -lt 3) {
        $ip = [string]$script:IdQueue.Dequeue()
        if ($script:IdentityCache.ContainsKey($ip) -or $script:IdPending.ContainsKey($ip)) { continue }
        Start-IdentityJob $ip
        $n++; $running++
    }
    if ($Config.ClockCheckMinutes -gt 0 -and ((Get-Date) - $script:LastClock).TotalMinutes -ge $Config.ClockCheckMinutes) { Start-ClockJob }
}

# -------- sweep ---------------------------------------------------------------
function Invoke-Sweep {
    if ($script:Paused) { return }
    Update-NetContext
    Check-Connections; Check-DnsCache; Check-Arp; Check-Inbound; Check-CanaryQueue
    Pump-Jobs
    Flush-AttemptLog; Write-Summary; Flush-Evidence
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
        $bgTxt = if ($script:Jobs.Count) { "   |   lookups running: $($script:Jobs.Count)" } else { '' }
        $script:Status.Invoke([Action]{ $script:Status.Text = "Mode: $mode   |   Last sweep: $(Get-Date -Format 'HH:mm:ss')   |   $state   |   evidence record #$($script:EvSeq)$bgTxt" })
    }
}

# -------- verify only (no window) ---------------------------------------------
if ($VerifyDir) {
    $v = Test-EvidenceChain $VerifyDir
    $v.Report
    return
}

# -------- self-test (no main window) ------------------------------------------
if ($TestFirewallLog) {
    $Config.LogDir    = Join-Path $PSScriptRoot 'logs\test'
    if (Test-Path $Config.LogDir) {
        Get-ChildItem -LiteralPath $Config.LogDir -Recurse -File -ErrorAction SilentlyContinue | ForEach-Object { $_.IsReadOnly = $false }
        Remove-Item -Path $Config.LogDir -Recurse -Force -ErrorAction SilentlyContinue
    }
    $Config.FwLogPath    = $TestFirewallLog
    $Config.TraceMaxHops = 6
    $script:FwPos        = 0
    Build-AllowList
    Init-Bg
    Init-Evidence
    Load-Vendors
    Write-StartRecord
    Update-Snapshots
    Update-NetContext -Force
    Start-ClockJob
    Check-Inbound
    Wait-BgJobs 150
    Flush-AttemptLog; $script:SummaryDirty = $true; Write-Summary
    Write-Evidence 'STOP' ([ordered]@{ reason = 'self-test finished' })
    Flush-Evidence
    "Addresses: $($script:Inbound.Count)"
    foreach ($r in (Get-SortedInbound)) {
        '{0} [{1}]  attempts={2} refused={3} allowed={4}  ports: {5}' -f $r.Ip, $r.Origin, $r.Attempts, $r.Dropped, $r.Allowed, (Get-PortsText $r 0)
        '    who: {0}   received by: {1}' -f (Get-Who $r), (Get-CountText $r.Apps 3)
        if ($script:IdentityCache.ContainsKey($r.Ip)) {
            $id = $script:IdentityCache[$r.Ip]
            '    identity: rdns={0} country={1} isp={2} asn={3} net={4} range={5} abuse={6} errors={7}' -f $id.reverseDns, $id.country, $id.isp, $id.asn, $id.netName, $id.netRange, $id.abuseContact, (@($id.errors) -join ' / ')
        }
    }
    foreach ($t in $script:TraceResults) { "Traceroute $($t.ip): $(@($t.hops).Count) hops" }
    if ($script:LastClockInfo) { "Clock offset: $($script:LastClockInfo.offsetSeconds)s  source: $($script:LastClockInfo.windowsTimeSource)  public IP recorded: $([bool]$script:LastClockInfo.publicIp)" }
    "Vendors loaded: $($script:Vendors.Count)"
    "Evidence records: $($script:EvSeq)"
    (Test-EvidenceChain $Config.LogDir).Report
    if ($TestExport) {
        $res = Export-EvidencePack
        if ($res) { "Export: $($res.Zip)  files=$($res.Files)  verified=$($res.Verified)  sha256=$($res.Sha256)" } else { 'Export FAILED' }
    }
    if ($ShowConnections) {
        Show-Connections
        [System.Windows.Forms.Application]::Run($script:ConnForm)
    }
    Close-Bg
    return
}

# -------- main window ---------------------------------------------------------
Build-AllowList
Init-Bg
Init-Evidence
Load-Vendors
Write-StartRecord

$form = New-Object System.Windows.Forms.Form
$form.Text = "Intrusion Monitor"
$form.Size = New-Object System.Drawing.Size(980, 560)
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
$script:Status.Font = New-Object System.Drawing.Font($Config.FontName, ($Config.FontSize - 4))
$script:Status.AutoSize = $true; $script:Status.Location = New-Object System.Drawing.Point(16, 54)
$form.Controls.Add($script:Status)

$script:LogBox = New-Object System.Windows.Forms.RichTextBox
$script:LogBox.ReadOnly = $true; $script:LogBox.BorderStyle = 'None'
$script:LogBox.BackColor = [System.Drawing.ColorTranslator]::FromHtml($Config.BackColor)
$script:LogBox.ForeColor = [System.Drawing.ColorTranslator]::FromHtml($Config.TextColor)
$script:LogBox.Font = New-Object System.Drawing.Font($Config.FontName, $Config.FontSize)
$script:LogBox.Location = New-Object System.Drawing.Point(16, 86)
$script:LogBox.Size = New-Object System.Drawing.Size(934, 390)
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
$btnClear = New-Btn 'Clear screen' 176
$ctxText = if ($script:IsAdmin) { 'Clear blocks' } else { 'Elevate' }
$btnContext = New-Btn $ctxText 336
$btnConn  = New-Btn 'Connections' 496
$btnStop  = New-Btn 'Stop'  656
$btnPause.Add_Click({
    $script:Paused = -not $script:Paused
    $this.Text = if ($script:Paused) {'Resume'} else {'Pause'}
    Write-Evidence $(if ($script:Paused) { 'PAUSE' } else { 'RESUME' }) ([ordered]@{ by = 'user' })
})
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
    Raise-Alert INFO 'Started' "Intrusion Monitor running - $mode. Evidence journal record #$($script:EvSeq)."
    Update-Snapshots
    Update-NetContext -Force
    Setup-Canary; Setup-ElevatedExtras; Invoke-Sweep; $timer.Start()
    if ($Config.StartMinimized) { $form.WindowState = 'Minimized' }
})
$form.Add_FormClosing({
    $timer.Stop()
    try { Get-EventSubscriber | Where-Object { $_.SourceObject -is [System.IO.FileSystemWatcher] } | Unregister-Event -ErrorAction SilentlyContinue } catch {}
    if ($script:Fsw) { $script:Fsw.EnableRaisingEvents = $false; $script:Fsw.Dispose() }
    if ($script:Tray) { $script:Tray.Visible = $false; $script:Tray.Dispose() }
    try { Receive-BgJobs } catch {}
    Flush-AttemptLog; Write-Summary
    Write-Evidence 'STOP' ([ordered]@{ reason = 'monitor closed'; pendingBackgroundJobs = $script:Jobs.Count })
    Flush-Evidence
    Close-Bg
    if ($script:ConnForm -and -not $script:ConnForm.IsDisposed) { $script:ConnForm.Close() }
    Write-Log "[stop] Intrusion Monitor closed."
})

[void][System.Windows.Forms.Application]::EnableVisualStyles()
[System.Windows.Forms.Application]::Run($form)
