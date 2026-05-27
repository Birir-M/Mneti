#Requires -Version 5.1
<#
.SYNOPSIS
    Mneti Agent — UDP Discovery Listener
.DESCRIPTION
    Lightweight, high-performance event-driven listener. Binds to UDP 5000 and waits silently.
    On receiving a valid HMAC-signed discovery broadcast from the IT server:
      1. Validates the HMAC-SHA256 signature — drops the packet on mismatch
      2. Checks whether this machine is the search target (targeted mode)
         or responds unconditionally (full mode)
      3. POSTs device info (hostname, MAC, IP, user, building, room) to server
      4. If this machine hosts a Windows hotspot, performs dual-mode discovery:
         a) Managed hotspot-connected clients: Relays discovery to them and collects
            their reports using a temporary HTTP Listener, then forwards them with relay metadata.
         b) Unmanaged hotspot-connected clients: Discovers them via ARP, hosts.ics, and 
            asynchronous ping sweeps, then forwards them with parent location details.
    Runs until stopped. Designed to be installed as a persistent background service via
    Install-MnetiService.ps1.
.NOTES
    Requires config.json at C:\ProgramData\Locator\config.json
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = 'SilentlyContinue'   # Network errors are non-fatal

# ── Constants ─────────────────────────────────────────────────────────────────
$CONFIG_FILE    = 'C:\ProgramData\Locator\config.json'
$LOG_FILE       = 'C:\ProgramData\Locator\agent.log'
$UDP_PORT       = 5000
$BUFFER_SIZE    = 4096
$POST_TIMEOUT   = 8          # seconds
$CACHE_TTL      = 60         # seconds — deduplicate request IDs
$MAX_LOG_BYTES  = 5MB

# ── Logging ───────────────────────────────────────────────────────────────────
$script:LogLock = New-Object System.Threading.Mutex($false, 'MnetiLogMutex')

function Write-AgentLog {
    param([string]$Level, [string]$Message)
    $line = "{0} [{1}] {2}" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Level.ToUpper(), $Message
    Write-Host $line

    try {
        if ($script:LogLock.WaitOne(500)) {
            if ((Test-Path $LOG_FILE) -and (Get-Item $LOG_FILE).Length -gt $MAX_LOG_BYTES) {
                Move-Item $LOG_FILE "$LOG_FILE.bak" -Force
            }
            Add-Content -Path $LOG_FILE -Value $line -Encoding UTF8 -Force
        }
    } catch {
        # Log write errors are ignored to ensure agent never crashes
    } finally {
        try { $script:LogLock.ReleaseMutex() } catch {}
    }
}

function Write-Info  { param([string]$m) Write-AgentLog 'INFO'  $m }
function Write-Warn  { param([string]$m) Write-AgentLog 'WARN'  $m }
function Write-Err   { param([string]$m) Write-AgentLog 'ERROR' $m }
function Write-Debug2{ param([string]$m) Write-AgentLog 'DEBUG' $m }

# ── Config loading ────────────────────────────────────────────────────────────
function Get-AgentConfig {
    if (-not (Test-Path $CONFIG_FILE)) {
        Write-Err "Config file not found: $CONFIG_FILE"
        Write-Err "Run Setup-Mneti.ps1 first."
        exit 1
    }
    try {
        $cfg = Get-Content $CONFIG_FILE -Raw -Encoding UTF8 | ConvertFrom-Json
        foreach ($field in @('building','room','token')) {
            if (-not $cfg.$field) {
                Write-Err "Config missing required field: $field"
                exit 1
            }
        }
        return $cfg
    } catch {
        Write-Err "Failed to parse config.json: $_"
        exit 1
    }
}

# ── HMAC-SHA256 ───────────────────────────────────────────────────────────────
function Get-HmacSha256 {
    param([string]$Secret, [string]$Message)
    $keyBytes  = [System.Text.Encoding]::UTF8.GetBytes($Secret)
    $msgBytes  = [System.Text.Encoding]::UTF8.GetBytes($Message)
    $hmac      = New-Object System.Security.Cryptography.HMACSHA256
    $hmac.Key  = $keyBytes
    $hashBytes = $hmac.ComputeHash($msgBytes)
    return ($hashBytes | ForEach-Object { $_.ToString('x2') }) -join ''
}

function Test-ConstantTimeEqual {
    param([string]$A, [string]$B)
    if ($A.Length -ne $B.Length) { return $false }
    $diff = 0
    for ($i = 0; $i -lt $A.Length; $i++) {
        $diff = $diff -bor ([int][char]$A[$i] -bxor [int][char]$B[$i])
    }
    return $diff -eq 0
}

# ── Request dedup cache ───────────────────────────────────────────────────────
$script:SeenIds  = @{}
$script:CacheLock = New-Object System.Threading.Mutex($false, 'MnetiCacheMutex')

function Test-AlreadySeen {
    param([string]$RequestId)
    try {
        if ($script:CacheLock.WaitOne(200)) {
            $now = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
            # Evict expired entries
            $expired = @()
            foreach ($key in $script:SeenIds.Keys) {
                if (($now - $script:SeenIds[$key]) -gt $CACHE_TTL) {
                    $expired += $key
                }
            }
            foreach ($key in $expired) {
                $script:SeenIds.Remove($key)
            }

            if ($script:SeenIds.ContainsKey($RequestId)) { return $true }
            $script:SeenIds[$RequestId] = $now
            return $false
        }
        return $false
    } finally {
        try { $script:CacheLock.ReleaseMutex() } catch {}
    }
}

# ── Network info ──────────────────────────────────────────────────────────────
function Get-NetworkAdapters {
    $adapters = @()
    try {
        Get-NetAdapter | Where-Object { $_.Status -eq 'Up' } | ForEach-Object {
            $adapter = $_
            $addrs = Get-NetIPAddress -InterfaceIndex $adapter.InterfaceIndex `
                                      -AddressFamily IPv4 -ErrorAction SilentlyContinue
            foreach ($addr in $addrs) {
                $ip = $addr.IPAddress
                if ($ip -like '127.*' -or $ip -like '169.254.*' -or $ip -like '192.168.137.*') { continue }
                $mac = ($adapter.MacAddress -replace '-', ':').ToUpper()
                $adapters += [pscustomobject]@{
                    Name = $adapter.Name
                    MAC  = $mac
                    IP   = $ip
                }
            }
        }
    } catch {
        Write-Warn "Adapter enumeration error: $_"
    }
    return $adapters
}

function Get-LoggedInUser {
    try {
        $session = query user 2>$null | Select-Object -Skip 1 | Where-Object { $_ -match 'Active' }
        if ($session) {
            return ($session -split '\s+')[1].TrimStart('>')
        }
    } catch {}
    return $env:USERNAME
}

function Get-MacVendor {
    param([string]$MAC)
    $oui = @{
        '00:50:56'='VMware';  '00:0C:29'='VMware';  '00:15:5D'='Hyper-V'
        '08:00:27'='VirtualBox'; '52:54:00'='QEMU'
        'B8:27:EB'='Raspberry Pi'; 'DC:A6:32'='Raspberry Pi'
        '00:1A:11'='Google';  'A4:C3:F0'='Google'
        'AC:BC:32'='Apple';   '3C:22:FB'='Apple';   '00:17:F2'='Apple'
        '00:1B:21'='Intel';   '14:18:77'='Dell';    'B4:B6:86'='HP'
        '3C:D9:2B'='HP';      '00:23:AE'='Dell';    '18:B4:30'='Nest'
    }
    if ($MAC.Length -ge 8) {
        $prefix = $MAC.Substring(0, 8).ToUpper()
        if ($oui.ContainsKey($prefix)) { return $oui[$prefix] }
    }
    return ''
}

# ── Packet validation ─────────────────────────────────────────────────────────
function Test-Packet {
    param([byte[]]$Bytes, [string]$Token)

    try {
        $json = [System.Text.Encoding]::UTF8.GetString($Bytes)

        if ($json.Length -gt $BUFFER_SIZE) {
            Write-Warn "Oversized packet - dropped"
            return $null
        }

        $envelope = $json | ConvertFrom-Json
    } catch {
        Write-Warn "Malformed packet (not JSON) - dropped"
        return $null
    }

    if (-not $envelope.payload -or -not $envelope.sig) {
        Write-Warn "Packet missing payload or sig - dropped"
        return $null
    }

    $p = $envelope.payload

    # Verify inner token first (fast reject)
    if (-not (Test-ConstantTimeEqual $p.token $Token)) {
        Write-Warn "Token mismatch inside payload - dropped"
        return $null
    }

    # Re-serialize the payload to JSON in the same key order Python used,
    # then HMAC that — avoids all format-string injection issues
    $payloadJson = '{"request_id":"' + $p.request_id + '","mode":"' + $p.mode + '","target":"' + $p.target + '","token":"' + $p.token + '","callback_url":"' + $p.callback_url + '","timestamp":"' + $p.timestamp + '"}'

    $expectedSig = Get-HmacSha256 -Secret $Token -Message $payloadJson

    if (-not (Test-ConstantTimeEqual $expectedSig $envelope.sig)) {
        Write-Warn "HMAC mismatch"
        return $null
    }

    return $p
}

# ── Target matching ───────────────────────────────────────────────────────────
function Test-IsTarget {
    param(
        [object[]]$Adapters,
        [string]  $Mode,    # targeted_mac | targeted_ip
        [string]  $Target
    )
    $Target = $Target.Trim().ToUpper()
    foreach ($a in $Adapters) {
        if ($Mode -eq 'targeted_mac') {
            $mac = $a.MAC.ToUpper() -replace '-', ':'
            if ($mac -eq ($Target -replace '-', ':')) { return $true }
        } elseif ($Mode -eq 'targeted_ip') {
            if ($a.IP -eq $Target) { return $true }
        }
    }
    return $false
}

# ── HTTP POST report ──────────────────────────────────────────────────────────
function Send-Report {
    param([string]$CallbackUrl, [hashtable]$Report, [string]$Token)
    try {
        $body    = $Report | ConvertTo-Json -Compress
        $bodyBytes = [System.Text.Encoding]::UTF8.GetBytes($body)
        $sig     = Get-HmacSha256 -Secret $Token -Message $body

        $req = [System.Net.HttpWebRequest]::Create($CallbackUrl)
        $req.Method        = 'POST'
        $req.ContentType   = 'application/json'
        $req.Timeout       = $POST_TIMEOUT * 1000
        $req.Headers.Add('X-Signature', $sig)

        $stream = $req.GetRequestStream()
        $stream.Write($bodyBytes, 0, $bodyBytes.Length)
        $stream.Close()

        $resp = $req.GetResponse()
        $status = [int]$resp.StatusCode
        $resp.Close()

        Write-Info "Report posted → $CallbackUrl [HTTP $status] for $($Report.hostname) ($($Report.type))"
    } catch {
        Write-Err "Failed to post report to $CallbackUrl : $_"
    }
}

# ── Hotspot detection and discovery ───────────────────────────────────────────
function Get-HotspotAdapter {
    # Check if hosting Windows mobile hotspot (typically assigned 192.168.137.1)
    try {
        $adapters = Get-NetAdapter | Where-Object { $_.Status -eq 'Up' }
        foreach ($adapter in $adapters) {
            $addrs = Get-NetIPAddress -InterfaceIndex $adapter.InterfaceIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue
            foreach ($addr in $addrs) {
                if ($addr.IPAddress -like "192.168.137.*") {
                    return [pscustomobject]@{
                        InterfaceIndex = $adapter.InterfaceIndex
                        Name           = $adapter.Name
                        IPAddress      = $addr.IPAddress
                        Subnet         = "192.168.137.0/24"
                    }
                }
            }
        }
    } catch {
        Write-Warn "Failed to query hotspot adapters: $_"
    }
    return $null
}

function Resolve-DeviceHostname {
    param([string]$IP)
    try {
        return [System.Net.Dns]::GetHostEntry($IP).HostName
    } catch {
        return ''
    }
}

function Invoke-HotspotDiscovery {
    param(
        [object]$Packet,
        [object]$Config,
        [string]$MyHostname,
        [string]$MyBuilding,
        [string]$MyRoom,
        [object]$Hotspot
    )

    Write-Info "Activating hotspot discovery relay on adapter: $($Hotspot.Name) (${script:MyIpAddress})"

    # 1. Start the temporary HttpListener to capture responses from managed clients behind NAT
    $httpPort = 5002
    $localCallbackUrl = "http://$($Hotspot.IPAddress):$httpPort/api/report"
    
    $listener = New-Object System.Net.HttpListener
    $listener.Prefixes.Add("http://+:$httpPort/api/report/")
    
    $listenerStarted = $false
    try {
        $listener.Start()
        $listenerStarted = $true
        Write-Info "Temporary HTTP Listener started at $localCallbackUrl"
    } catch {
        Write-Warn "Could not start temporary HttpListener: $_"
    }

    # 2. Broadcast the discovery request to the hotspot subnet on UDP port 5000
    try {
        $relayPacket = @{
            request_id   = $Packet.request_id
            mode         = $Packet.mode
            target       = $Packet.target
            token        = $Config.token
            callback_url = $localCallbackUrl
            timestamp    = $Packet.timestamp
        }
        $payload = $relayPacket | ConvertTo-Json -Compress
        $sig = Get-HmacSha256 -Secret $Config.token -Message $payload
        $envelope = @{
            payload = $relayPacket
            sig     = $sig
        }
        $envelopeJson = $envelope | ConvertTo-Json -Compress
        $envelopeBytes = [System.Text.Encoding]::UTF8.GetBytes($envelopeJson)

        $udpClient = New-Object System.Net.Sockets.UdpClient
        $udpClient.EnableBroadcast = $true
        # Broadcast on the hotspot subnet broadcast address
        $udpClient.Send($envelopeBytes, $envelopeBytes.Length, "192.168.137.255", 5000)
        $udpClient.Close()
        Write-Info "Discovery broadcast sent to hotspot subnet (192.168.137.255:5000)"
    } catch {
        Write-Warn "UDP broadcast on hotspot network failed: $_"
    }

    # 3. Parallel asynchronous .NET Ping sweep to quickly populate the system ARP cache
    Write-Info "Triggering fast parallel .NET ping sweep on hotspot subnet..."
    for ($i = 2; $i -le 254; $i++) {
        $ip = "192.168.137.$i"
        if ($ip -eq $Hotspot.IPAddress) { continue }
        $ping = New-Object System.Net.NetworkInformation.Ping
        try {
            $ping.SendAsync($ip, 150, $null) | Out-Null
        } catch {}
    }

    # 4. Listen for incoming HTTP POSTs from managed clients on the hotspot network
    $managedReports = @()
    if ($listenerStarted) {
        $timeout = [DateTime]::Now.AddSeconds(4)
        while ([DateTime]::Now -lt $timeout) {
            if ($listener.IsListening) {
                try {
                    $context = $listener.GetContext()
                    $request = $context.Request
                    $response = $context.Response

                    # Read POST body
                    $reader = New-Object System.IO.StreamReader($request.InputStream, [System.Text.Encoding]::UTF8)
                    $body = $reader.ReadToEnd()
                    $reader.Close()

                    # Respond with 200 OK
                    $buf = [System.Text.Encoding]::UTF8.GetBytes('{"status":"ok"}')
                    $response.ContentLength64 = $buf.Length
                    $response.OutputStream.Write($buf, 0, $buf.Length)
                    $response.OutputStream.Close()

                    # Parse report
                    $report = $body | ConvertFrom-Json
                    
                    # Validate the signature of the reported client payload
                    $clientHmac = $request.Headers.Get('X-Signature')
                    $expectedClientHmac = Get-HmacSha256 -Secret $Config.token -Message $body
                    if ($clientHmac -eq $expectedClientHmac -and $report.token -eq $Config.token) {
                        $managedReports += $report
                        Write-Info "Received valid relayed report from managed client behind hotspot: $($report.hostname)"
                    } else {
                        Write-Warn "Received invalid signature from hotspot client report"
                    }
                } catch {
                    Write-Warn "Error handling relayed client POST: $_"
                }
            } else {
                Start-Sleep -Milliseconds 100
            }
        }
        $listener.Stop()
        $listener.Close()
        Write-Info "Temporary HTTP Listener stopped. Collected $($managedReports.Count) managed device(s)."
    }

    # 5. Extract MAC & IP from ARP table and hosts.ics for unmanaged client detection
    $discoveredClients = @{} # MAC -> IP
    $clientHostnames = @{}   # MAC -> Hostname

    # Check hosts.ics (most reliable source of Hostname, IP, MAC for Windows Hotspot)
    $hostsIcsPath = "C:\Windows\System32\drivers\etc\hosts.ics"
    if (Test-Path $hostsIcsPath) {
        try {
            $lines = Get-Content $hostsIcsPath -ErrorAction SilentlyContinue
            foreach ($line in $lines) {
                if ($line -match '^\s*(192\.168\.137\.\d+)\s+([^\s#]+)\s*#\s*([\da-fA-F:-]+)') {
                    $ip = $Matches[1]
                    $hostName = $Matches[2].Split('.')[0] # Get short hostname
                    $mac = $Matches[3].ToUpper() -replace '-', ':'
                    if ($ip -ne $Hotspot.IPAddress) {
                        $discoveredClients[$mac] = $ip
                        $clientHostnames[$mac] = $hostName
                    }
                }
            }
        } catch {
            Write-Warn "Failed to parse hosts.ics: $_"
        }
    }

    # Also parse 'arp -a' to capture any other active devices
    $arp = arp -a 2>$null
    foreach ($line in $arp) {
        if ($line -match '(192\.168\.137\.\d{1,3})\s+([\da-fA-F]{2}(?:[:\-][\da-fA-F]{2}){5})\s+dynamic') {
            $ip  = $Matches[1]
            $mac = $Matches[2].ToUpper() -replace '-', ':'
            if ($ip -ne $Hotspot.IPAddress) {
                if (-not $discoveredClients.ContainsKey($mac)) {
                    $discoveredClients[$mac] = $ip
                }
            }
        }
    }

    Write-Info "ARP/Hosts.ics scan found $($discoveredClients.Count) active IP/MAC mapping(s) on hotspot."

    # 6. Forward reports to the primary server
    $managedMacs = @{}
    
    # 6a. Forward the Managed (Relayed) Clients
    foreach ($mr in $managedReports) {
        $mac = $mr.mac.ToUpper() -replace '-', ':'
        $managedMacs[$mac] = $true

        # Construct and send relayed report
        $relayReport = @{
            token          = $Config.token
            request_id     = $Packet.request_id
            hostname       = $mr.hostname
            mac            = $mr.mac
            ip             = $mr.ip
            username       = $mr.username
            building       = $mr.building
            room           = $mr.room
            timestamp      = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
            type           = 'relayed'
            relay_host     = $MyHostname
            relay_building = $MyBuilding
            relay_room     = $MyRoom
            vendor         = $mr.vendor
        }

        Send-Report -CallbackUrl $Packet.callback_url -Report $relayReport -Token $Config.token
    }

    # 6b. Forward the Unmanaged Clients
    foreach ($mac in $discoveredClients.Keys) {
        if ($managedMacs.ContainsKey($mac)) {
            continue # Already handled as managed relayed client
        }

        $ip = $discoveredClients[$mac]
        
        # Get hostname from hosts.ics, or fallback to DNS lookup
        $hostname = ""
        if ($clientHostnames.ContainsKey($mac)) {
            $hostname = $clientHostnames[$mac]
        } else {
            $hostname = Resolve-DeviceHostname -IP $ip
        }
        if (-not $hostname) {
            $hostname = "Unmanaged-Device"
        }

        $vendor = Get-MacVendor -MAC $mac

        $unmanagedReport = @{
            token          = $Config.token
            request_id     = $Packet.request_id
            hostname       = $hostname
            mac            = $mac
            ip             = $ip
            username       = ''
            building       = $MyBuilding # Inherit location from parent host
            room           = $MyRoom
            timestamp      = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
            type           = 'unmanaged'
            relay_host     = $MyHostname
            relay_building = $MyBuilding
            relay_room     = $MyRoom
            vendor         = $vendor
        }

        Send-Report -CallbackUrl $Packet.callback_url -Report $unmanagedReport -Token $Config.token
    }
}

# ── Main packet handler ───────────────────────────────────────────────────────
function Invoke-PacketHandler {
    param([byte[]]$Data, [string]$SenderIP, [object]$Config)

    $payload = Test-Packet -Bytes $Data -Token $Config.token
    if ($null -eq $payload) { return }

    $requestId   = $payload.request_id
    $mode        = $payload.mode
    $target      = $payload.target
    $callbackUrl = $payload.callback_url

    if (-not $requestId -or -not $callbackUrl) {
        Write-Warn "Packet missing request_id or callback_url — dropped"
        return
    }

    if (Test-AlreadySeen -RequestId $requestId) {
        Write-Debug2 "Duplicate request_id $requestId — ignored"
        return
    }

    Write-Info "Processing discovery request: mode=$mode id=$requestId from=$SenderIP"

    $adapters    = Get-NetworkAdapters
    $myHostname  = $env:COMPUTERNAME
    $myBuilding  = $Config.building
    $myRoom      = $Config.room

    # Check if this machine is target
    $shouldRespond = $false
    if ($mode -eq 'full') {
        $shouldRespond = $true
    } elseif ($mode -in @('targeted_mac','targeted_ip')) {
        $shouldRespond = Test-IsTarget -Adapters $adapters -Mode $mode -Target $target
        if (-not $shouldRespond) {
            Write-Debug2 "Not the target ($target) — not responding"
        }
    }

    if ($shouldRespond) {
        # Pick primary active adapter
        $primary = $adapters | Select-Object -First 1

        $report = @{
            token          = $Config.token
            request_id     = $requestId
            hostname       = $myHostname
            mac            = if ($primary) { $primary.MAC } else { '' }
            ip             = if ($primary) { $primary.IP  } else { '' }
            username       = Get-LoggedInUser
            building       = $myBuilding
            room           = $myRoom
            timestamp      = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
            type           = 'managed'
            relay_host     = ''
            relay_building = ''
            relay_room     = ''
            vendor         = if ($primary) { Get-MacVendor -MAC $primary.MAC } else { '' }
        }

        # Send report to the server
        Send-Report -CallbackUrl $callbackUrl -Report $report -Token $Config.token
    }

    # Hotspot Relay check
    $hotspot = Get-HotspotAdapter
    if ($null -ne $hotspot) {
        Invoke-HotspotDiscovery -Packet $payload -Config $Config `
                               -MyHostname $myHostname -MyBuilding $myBuilding `
                               -MyRoom $myRoom -Hotspot $hotspot
    }
}

# ── UDP listener loop ─────────────────────────────────────────────────────────
function Start-AgentListener {
    $config = Get-AgentConfig

    Write-Info "Mneti Agent starting - UDP listener on port $UDP_PORT"
    Write-Info "Building: $($config.building) | Room: $($config.room)"
    Write-Info "Token length: $($config.token.Length) chars"

    $endpoint  = New-Object System.Net.IPEndPoint([System.Net.IPAddress]::Any, $UDP_PORT)
    $udpClient = New-Object System.Net.Sockets.UdpClient

    try {
        $udpClient.Client.SetSocketOption(
            [System.Net.Sockets.SocketOptionLevel]::Socket,
            [System.Net.Sockets.SocketOptionName]::ReuseAddress, $true)
        $udpClient.Client.Bind($endpoint)
        $udpClient.EnableBroadcast = $true
        Write-Info "Bound to UDP :$UDP_PORT - waiting for broadcasts..."
    } catch {
        Write-Err "Cannot bind to UDP port $UDP_PORT : $_"
        exit 1
    }

    $udpClient.Client.ReceiveTimeout = 1000
    $script:Running = $true

    try {
        while ($script:Running) {
            try {
                $remote   = New-Object System.Net.IPEndPoint([System.Net.IPAddress]::Any, 0)
                $data     = $udpClient.Receive([ref]$remote)
                $senderIP = $remote.Address.ToString()

                if ($data.Length -gt $BUFFER_SIZE) {
                    Write-Warn "Oversized packet ($($data.Length) bytes) from $senderIP - dropped"
                    continue
                }

                Invoke-PacketHandler -Data $data -SenderIP $senderIP -Config $config

            } catch [System.Net.Sockets.SocketException] {
                continue
            } catch {
                if ($script:Running) { Write-Err "UDP receive error: $_" }
            }
        }
    } finally {
        $udpClient.Close()
        Write-Info "Mneti Agent stopped."
    }
}

# Entry point — only execute when run directly (not dot-sourced/imported)
if ($MyInvocation.InvocationName -ne '.') {
    Start-AgentListener
}