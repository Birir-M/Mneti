#Requires -Version 5.1
<#
.SYNOPSIS
    Mneti Agent - UDP Discovery Listener
.DESCRIPTION
    Lightweight, high-performance event-driven listener. Binds to UDP 5000 and waits silently.
    On receiving a valid HMAC-signed discovery broadcast from the IT server:
      1. Validates the HMAC-SHA256 signature - drops the packet on mismatch
      2. Checks whether this machine is the search target (targeted mode)
         or responds unconditionally (full mode)
      3. POSTs device info (hostname, MAC, IP, user, building, room) to server
      4. Detects ALL secondary private IPv4 subnets attached to this host and
         relays discovery into each one (multi-homed relay architecture):
         a) Managed clients: relayed via UDP + temporary HTTP listener
         b) Unmanaged clients: discovered via ARP + async ping sweep
      5. Relay depth tracking prevents rebroadcast storms (max depth = 1)
.NOTES
    Requires config.json at C:\ProgramData\Locator\config.json
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = 'SilentlyContinue'

# ── Constants ─────────────────────────────────────────────────────────────────
$CONFIG_FILE   = 'C:\ProgramData\Locator\config.json'
$LOG_FILE      = 'C:\ProgramData\Locator\agent.log'
$UDP_PORT      = 5000
$RELAY_HTTP_PORT = 5002
$BUFFER_SIZE   = 4096
$POST_TIMEOUT  = 8
$CACHE_TTL     = 60
$MAX_LOG_BYTES = 5MB
$MAX_RELAY_DEPTH = 1

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
    } finally {
        try { $script:LogLock.ReleaseMutex() } catch {}
    }
}

function Write-Info   { param([string]$m) Write-AgentLog 'INFO'  $m }
function Write-Warn   { param([string]$m) Write-AgentLog 'WARN'  $m }
function Write-Err    { param([string]$m) Write-AgentLog 'ERROR' $m }
function Write-Debug2 { param([string]$m) Write-AgentLog 'DEBUG' $m }

# ── Config loading ────────────────────────────────────────────────────────────
function Get-AgentConfig {
    if (-not (Test-Path $CONFIG_FILE)) {
        Write-Err "Config file not found: $CONFIG_FILE. Run Setup-Mneti.ps1 first."
        exit 1
    }
    try {
        $cfg = Get-Content $CONFIG_FILE -Raw -Encoding UTF8 | ConvertFrom-Json
        foreach ($field in @('building', 'room', 'token')) {
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
$script:SeenIds   = @{}
$script:CacheLock = New-Object System.Threading.Mutex($false, 'MnetiCacheMutex')

function Test-AlreadySeen {
    param([string]$RequestId)
    try {
        if ($script:CacheLock.WaitOne(200)) {
            $now     = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
            $expired = @()
            foreach ($key in $script:SeenIds.Keys) {
                if (($now - $script:SeenIds[$key]) -gt $CACHE_TTL) { $expired += $key }
            }
            foreach ($key in $expired) { $script:SeenIds.Remove($key) }
            if ($script:SeenIds.ContainsKey($RequestId)) { return $true }
            $script:SeenIds[$RequestId] = $now
            return $false
        }
        return $false
    } finally {
        try { $script:CacheLock.ReleaseMutex() } catch {}
    }
}

# ── Network helpers ───────────────────────────────────────────────────────────

function Get-NetworkAdapters {
    # Returns adapters whose IPs are NOT loopback, APIPA, or link-local.
    # Used for self-reporting (picks the primary adapter).
    $adapters = @()
    try {
        Get-NetAdapter | Where-Object { $_.Status -eq 'Up' } | ForEach-Object {
            $adapter = $_
            $addrs = Get-NetIPAddress -InterfaceIndex $adapter.InterfaceIndex `
                                      -AddressFamily IPv4 -ErrorAction SilentlyContinue
            foreach ($addr in $addrs) {
                $ip = $addr.IPAddress
                if ($ip -like '127.*' -or $ip -like '169.254.*') { continue }
                $mac = ($adapter.MacAddress -replace '-', ':').ToUpper()
                $adapters += [pscustomobject]@{
                    Name           = $adapter.Name
                    MAC            = $mac
                    IP             = $ip
                    InterfaceIndex = $adapter.InterfaceIndex
                    PrefixLength   = $addr.PrefixLength
                }
            }
        }
    } catch {
        Write-Warn "Adapter enumeration error: $_"
    }
    return $adapters
}

function Get-SubnetBroadcast {
    param([string]$IP, [int]$PrefixLength)
    try {
        $ipBytes   = ([System.Net.IPAddress]$IP).GetAddressBytes()
        $maskBits  = [uint32]([System.Math]::Pow(2, 32) - [System.Math]::Pow(2, 32 - $PrefixLength))
        $ipInt     = [System.BitConverter]::ToUInt32($ipBytes[3..0], 0)
        $netInt    = $ipInt -band $maskBits
        $bcastInt  = $netInt -bor (-bnot [int]$maskBits -band 0xFFFFFFFF)
        $bcastBytes = [System.BitConverter]::GetBytes([uint32]$bcastInt)
        return ([System.Net.IPAddress][byte[]]($bcastBytes[3], $bcastBytes[2], $bcastBytes[1], $bcastBytes[0])).ToString()
    } catch {
        # Fallback: replace last octet with 255
        $parts    = $IP -split '\.'
        $parts[3] = '255'
        return $parts -join '.'
    }
}

function Test-IsPrivateIP {
    param([string]$IP)
    return ($IP -like '10.*' -or
            ($IP -like '172.*' -and [int]($IP -split '\.')[1] -ge 16 -and [int]($IP -split '\.')[1] -le 31) -or
            $IP -like '192.168.*')
}

function Get-RelayNetworks {
    param([string]$SenderIP)

    $relayNets = @()
    $seen      = @{}

    try {
        Get-NetAdapter | Where-Object { $_.Status -eq 'Up' } | ForEach-Object {

            $adapter = $_

            $addrs = Get-NetIPAddress `
                -InterfaceIndex $adapter.InterfaceIndex `
                -AddressFamily IPv4 `
                -ErrorAction SilentlyContinue

            foreach ($addr in $addrs) {

                $ip     = $addr.IPAddress
                $prefix = $addr.PrefixLength

                if ($ip -like '127.*' -or $ip -like '169.254.*') {
                    continue
                }

                if (-not (Test-IsPrivateIP -IP $ip)) {
                    continue
                }

                $myBcast     = Get-SubnetBroadcast -IP $ip -PrefixLength $prefix
                $senderBcast = Get-SubnetBroadcast -IP $SenderIP -PrefixLength $prefix

                if ($myBcast -eq $senderBcast) {
                    Write-Debug2 "Skipping originating subnet for relay: $ip/$prefix"
                    continue
                }

                $dedupKey = "$ip/$prefix"

                if ($seen.ContainsKey($dedupKey)) {
                    Write-Debug2 "Skipping duplicate relay subnet: $dedupKey"
                    continue
                }

                $seen[$dedupKey] = $true

                $broadcast = Get-SubnetBroadcast -IP $ip -PrefixLength $prefix

                $relayNets += [pscustomobject]@{
                    IPAddress   = $ip
                    Broadcast   = $broadcast
                    Prefix      = $prefix
                    Interface   = $adapter.InterfaceIndex
                    AdapterName = $adapter.Name
                }

                Write-Info "Relay subnet detected: $ip/$prefix (broadcast $broadcast) on $($adapter.Name)"
            }
        }
    }
    catch {
        Write-Warn "Relay network enumeration error: $_"
    }

    return $relayNets
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
        '00:50:56' = 'VMware';   '00:0C:29' = 'VMware';   '00:15:5D' = 'Hyper-V'
        '08:00:27' = 'VirtualBox'; '52:54:00' = 'QEMU'
        'B8:27:EB' = 'Raspberry Pi'; 'DC:A6:32' = 'Raspberry Pi'
        '00:1A:11' = 'Google';   'A4:C3:F0' = 'Google'
        'AC:BC:32' = 'Apple';    '3C:22:FB' = 'Apple';    '00:17:F2' = 'Apple'
        '00:1B:21' = 'Intel';    '14:18:77' = 'Dell';     'B4:B6:86' = 'HP'
        '3C:D9:2B' = 'HP';       '00:23:AE' = 'Dell';     '18:B4:30' = 'Nest'
    }
    if ($MAC.Length -ge 8) {
        $prefix = $MAC.Substring(0, 8).ToUpper()
        if ($oui.ContainsKey($prefix)) { return $oui[$prefix] }
    }
    return ''
}

function Resolve-DeviceHostname {
    param([string]$IP)
    try { return [System.Net.Dns]::GetHostEntry($IP).HostName } catch { return '' }
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

    if (-not (Test-ConstantTimeEqual $p.token $Token)) {
        Write-Warn "Token mismatch inside payload - dropped"
        return $null
    }

    # Reconstruct signed string in same key order as Python _build_packet
    $relayDepth = 0
    if ($null -ne $p.relay_depth) {
        $relayDepth = [int]$p.relay_depth
    }

    $payloadJson = '{"request_id":"' + $p.request_id + '","mode":"' + $p.mode + '","target":"' + $p.target + '","token":"' + $p.token + '","callback_url":"' + $p.callback_url + '","timestamp":"' + $p.timestamp + '","relay_depth":' + $relayDepth + '}'

    $expectedSig = Get-HmacSha256 -Secret $Token -Message $payloadJson

    if (-not (Test-ConstantTimeEqual $expectedSig $envelope.sig)) {
        Write-Warn "HMAC mismatch - dropped (possible forgery)"
        return $null
    }

    return $p
}

# ── Target matching ───────────────────────────────────────────────────────────
function Test-IsTarget {
    param([object[]]$Adapters, [string]$Mode, [string]$Target)
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
        $body      = $Report | ConvertTo-Json -Compress
        $bodyBytes = [System.Text.Encoding]::UTF8.GetBytes($body)
        $sig       = Get-HmacSha256 -Secret $Token -Message $body

        $req                = [System.Net.HttpWebRequest]::Create($CallbackUrl)
        $req.Method         = 'POST'
        $req.ContentType    = 'application/json'
        $req.Timeout        = $POST_TIMEOUT * 1000
        $req.Headers.Add('X-Signature', $sig)

        $stream = $req.GetRequestStream()
        $stream.Write($bodyBytes, 0, $bodyBytes.Length)
        $stream.Close()

        $resp   = $req.GetResponse()
        $status = [int]$resp.StatusCode
        $resp.Close()

        Write-Info "Report posted -> $CallbackUrl [HTTP $status] $($Report.hostname) ($($Report.type))"
    } catch {
        Write-Err "Failed to post report to $CallbackUrl : $_"
    }
}

# ── Build a relay broadcast packet ───────────────────────────────────────────
function Build-RelayPacket {
    param(
        [object]$OriginalPayload,
        [string]$LocalCallbackUrl,
        [string]$Token,
        [int]   $RelayDepth
    )
    $relayPayload = [ordered]@{
        request_id   = $OriginalPayload.request_id
        mode         = $OriginalPayload.mode
        target       = $OriginalPayload.target
        token        = $Token
        callback_url = $LocalCallbackUrl
        timestamp    = $OriginalPayload.timestamp
        relay_depth  = $RelayDepth
    }

    # Serialize in the exact key order the HMAC covers
    $payloadJson = '{"request_id":"' + $relayPayload.request_id + '","mode":"' + $relayPayload.mode + '","target":"' + $relayPayload.target + '","token":"' + $relayPayload.token + '","callback_url":"' + $relayPayload.callback_url + '","timestamp":"' + $relayPayload.timestamp + '","relay_depth":' + $relayPayload.relay_depth + '}'
    $sig         = Get-HmacSha256 -Secret $Token -Message $payloadJson

    $envelope = @{
        payload = $relayPayload
        sig     = $sig
    }
    return [System.Text.Encoding]::UTF8.GetBytes(($envelope | ConvertTo-Json -Compress -Depth 5))
}

# ── Subnet relay (generalised, replaces Invoke-HotspotDiscovery) ──────────────
function Invoke-SubnetRelay {
    param(
        [object]$Packet,
        [object]$Config,
        [string]$MyHostname,
        [string]$MyBuilding,
        [string]$MyRoom,
        [object]$RelayNet
    )

    $localIP       = $RelayNet.IPAddress
    $broadcastAddr = $RelayNet.Broadcast
    $prefix        = $RelayNet.Prefix
    $newDepth      = [int]$Packet.relay_depth + 1

    Write-Info "Relaying discovery into $localIP/$prefix via $broadcastAddr"

    $listener         = $null
    $listenerStarted  = $false
    $relayPort        = $null
    $localCallbackUrl = $null

    # ------------------------------------------------------------------
    # Start relay HTTP listener using unique high random port
    # ------------------------------------------------------------------

    for ($attempt = 1; $attempt -le 5; $attempt++) {

        try {

            $relayPort = Get-Random -Minimum 5500 -Maximum 65000

            $localCallbackUrl = "http://$($localIP):$relayPort/api/report"

            Write-Info "Attempting relay listener on ${localIP}:$relayPort"

            $listener = New-Object System.Net.HttpListener

            # Bind ONLY to relay interface IP
            $listener.Prefixes.Add("http://$($localIP):$relayPort/api/report/")

            $listener.Start()

            $listenerStarted = $true

            Write-Info "Relay HTTP listener started on ${localIP}:$relayPort"

            break
        }
        catch {

            Write-Warn "Relay listener attempt $attempt failed on port $relayPort : $_"

            try {
                if ($listener) {
                    $listener.Close()
                }
            } catch {}

            $listener = $null
        }
    }

    if (-not $listenerStarted) {
        Write-Warn "Failed to start relay listener for subnet $localIP/$prefix"
        return
    }

    try {

        # --------------------------------------------------------------
        # Broadcast relay discovery packet
        # --------------------------------------------------------------

        try {

            $packetBytes = Build-RelayPacket `
                -OriginalPayload $Packet `
                -LocalCallbackUrl $localCallbackUrl `
                -Token $Config.token `
                -RelayDepth $newDepth

            $udpSock = New-Object System.Net.Sockets.UdpClient

            try {

                $udpSock.EnableBroadcast = $true

                $udpSock.Send(
                    $packetBytes,
                    $packetBytes.Length,
                    $broadcastAddr,
                    $UDP_PORT
                ) | Out-Null

                Write-Info "Rebroadcasting discovery to ${broadcastAddr}:$UDP_PORT (depth $newDepth)"
            }
            finally {
                $udpSock.Close()
            }
        }
        catch {
            Write-Warn "UDP rebroadcast to $broadcastAddr failed: $_"
        }

        

        # --------------------------------------------------------------
        # Collect managed client responses
        # --------------------------------------------------------------

        $managedReports = @()

        $deadline = [DateTime]::Now.AddSeconds(30)

        while ([DateTime]::Now -lt $deadline) {

            try {

                if (-not $listener.IsListening) {
                    break
                }

                $asyncResult = $listener.BeginGetContext($null, $null)

                $signaled = $asyncResult.AsyncWaitHandle.WaitOne(250)

                if (-not $signaled) {
                    continue
                }

                $ctx = $listener.EndGetContext($asyncResult)

                $req = $ctx.Request
                $res = $ctx.Response

                $reader = New-Object System.IO.StreamReader(
                    $req.InputStream,
                    [System.Text.Encoding]::UTF8
                )

                $body = $reader.ReadToEnd()

                $reader.Close()

                $buf = [System.Text.Encoding]::UTF8.GetBytes('{"status":"ok"}')

                $res.ContentLength64 = $buf.Length
                $res.OutputStream.Write($buf, 0, $buf.Length)
                $res.OutputStream.Close()

                $report       = $body | ConvertFrom-Json
                $clientHmac   = $req.Headers.Get('X-Signature')
                $expectedHmac = Get-HmacSha256 -Secret $Config.token -Message $body

                if (
                    (Test-ConstantTimeEqual $clientHmac $expectedHmac) -and
                    (Test-ConstantTimeEqual $report.token $Config.token)
                ) {

                    $managedReports += $report

                    Write-Info "Managed client responded via relay: $($report.hostname) ($($report.ip))"
                }
                else {
                    Write-Warn "Invalid signature on relay response - discarded"
                }
            }
            catch {
                Write-Warn "Error reading relay response: $_"
            }
        }

        Write-Info "Relay listener completed. Managed responses: $(@($managedReports).Count)"

        # --------------------------------------------------------------
        # Generate subnet-aware host range
        # --------------------------------------------------------------

        Write-Info "Ping sweep on $localIP/$prefix ..."

        try {

            $ipObj    = [System.Net.IPAddress]::Parse($localIP)
            $ipBytes  = $ipObj.GetAddressBytes()

            [array]::Reverse($ipBytes)

            $ipInt = [BitConverter]::ToUInt32($ipBytes, 0)

            $mask = [uint32]0

            for ($i = 0; $i -lt $prefix; $i++) {
                $mask = $mask -bor (1 -shl (31 - $i))
            }

            $network   = $ipInt -band $mask
            $broadcast = $network -bor (-bnot $mask)

            for ($host = ($network + 1); $host -lt $broadcast; $host++) {

                $hostBytes = [BitConverter]::GetBytes([uint32]$host)

                [array]::Reverse($hostBytes)

                $targetIP = ([System.Net.IPAddress]$hostBytes).ToString()

                if ($targetIP -eq $localIP) {
                    continue
                }

                try {
                    $ping = New-Object System.Net.NetworkInformation.Ping
                    $ping.SendAsync($targetIP, 150, $null) | Out-Null
                }
                catch {}
            }
        }
        catch {
            Write-Warn "Subnet-aware ping sweep failed on $localIP/$prefix : $_"
        }

        # --------------------------------------------------------------
        # ARP discovery
        # --------------------------------------------------------------

        $discoveredClients = @{}
        $managedMacs       = @{}

        $arpOutput = arp -a 2>$null

        foreach ($line in $arpOutput) {

            if (
                $line -match '(\d{1,3}(?:\.\d{1,3}){3})\s+([\da-fA-F]{2}(?:[:\-][\da-fA-F]{2}){5})\s+dynamic'
            ) {

                $arpIP  = $Matches[1]
                $arpMac = $Matches[2].ToUpper() -replace '-', ':'

                try {

                    $arpObj   = [System.Net.IPAddress]::Parse($arpIP)
                    $arpBytes = $arpObj.GetAddressBytes()

                    [array]::Reverse($arpBytes)

                    $arpInt = [BitConverter]::ToUInt32($arpBytes, 0)

                    if (($arpInt -band $mask) -ne $network) {
                        continue
                    }

                    if ($arpIP -eq $localIP) {
                        continue
                    }

                    if (-not $discoveredClients.ContainsKey($arpMac)) {
                        $discoveredClients[$arpMac] = $arpIP
                    }
                }
                catch {}
            }
        }

        Write-Info "ARP scan found $(@($discoveredClients.Keys).Count) unmanaged device(s) in $localIP/$prefix"

        # --------------------------------------------------------------
        # Forward managed relay reports
        # --------------------------------------------------------------

        foreach ($mr in $managedReports) {

            $mac = $mr.mac.ToUpper() -replace '-', ':'

            $managedMacs[$mac] = $true

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

            Send-Report `
                -CallbackUrl $Packet.callback_url `
                -Report $relayReport `
                -Token $Config.token
        }

        # --------------------------------------------------------------
        # Forward unmanaged reports
        # --------------------------------------------------------------

                foreach ($mac in $discoveredClients.Keys) {
 
            if ($managedMacs.ContainsKey($mac)) {
                continue
            }
 
            $ip       = $discoveredClients[$mac]
            $hostname = Resolve-DeviceHostname -IP $ip
 
            if (-not $hostname) {
                $hostname = "Unmanaged-$ip"
            }
 
            $vendor = Get-MacVendor -MAC $mac
 
            Write-Info "Unmanaged device discovered: $ip ($mac) $vendor"
 
            $unmanagedReport = @{
                token           = $Config.token
                request_id      = $Packet.request_id
                hostname        = $hostname
                mac             = $mac
                ip              = $ip
                username        = ''
                # Location is intentionally blank for unmanaged ARP-discovered
                # devices. They are peers on a directly-attached subnet, not
                # hotspot clients, so their physical location is unknown.
                # Only managed clients (with the agent installed) report their
                # own building/room, and relayed clients inherit from the
                # hotspot host in the "managed relay reports" block above.
                building        = ''
                room            = ''
                timestamp       = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
                type            = 'unmanaged'
                relay_host      = ''
                relay_building  = ''
                relay_room      = ''
                vendor          = $vendor
            }
 
            Send-Report `
                -CallbackUrl $Packet.callback_url `
                -Report $unmanagedReport `
                -Token $Config.token
        }

    }
    finally {

        if ($listener) {

            try {
                if ($listener.IsListening) {
                    $listener.Stop()
                }
            } catch {}

            try {
                $listener.Close()
            } catch {}

            Write-Info "Relay listener cleaned up on ${localIP}:$relayPort"
        }
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
    $relayDepth  = [int]$payload.relay_depth

    if (-not $requestId -or -not $callbackUrl) {
        Write-Warn "Packet missing request_id or callback_url - dropped"
        return
    }

    if (Test-AlreadySeen -RequestId $requestId) {
        Write-Debug2 "Duplicate request_id $requestId - ignored"
        return
    }

    Write-Info "Discovery request: mode=$mode depth=$relayDepth id=$requestId from=$SenderIP"

    $adapters   = Get-NetworkAdapters
    $myHostname = $env:COMPUTERNAME
    $myBuilding = $Config.building
    $myRoom     = $Config.room

    # Self-report
    $shouldRespond = $false
    if ($mode -eq 'full') {
        $shouldRespond = $true
    } elseif ($mode -in @('targeted_mac', 'targeted_ip')) {
        $shouldRespond = Test-IsTarget -Adapters $adapters -Mode $mode -Target $target
        if (-not $shouldRespond) {
            Write-Debug2 "Not the target ($target) - not responding"
        }
    }

    if ($shouldRespond) {
        $primary = $adapters | Select-Object -First 1
        $report  = @{
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
        Send-Report -CallbackUrl $callbackUrl -Report $report -Token $Config.token
    }

    # Relay into secondary subnets if depth allows
    if ($relayDepth -ge $MAX_RELAY_DEPTH) {
        Write-Warn "Relay depth $relayDepth >= $MAX_RELAY_DEPTH - skipping rebroadcast"
        return
    }

    $relayNets = Get-RelayNetworks -SenderIP $SenderIP
    if (@($relayNets).Count -eq 0) {
        Write-Debug2 "No secondary relay subnets detected"
        return
    }

    Write-Info "Relaying into $(@($relayNets).Count) secondary subnet(s)"
    foreach ($net in @($relayNets)) {
        Invoke-SubnetRelay -Packet $payload -Config $Config `
                           -MyHostname $myHostname -MyBuilding $myBuilding `
                           -MyRoom $myRoom -RelayNet $net
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
                if ($script:Running) { 
                    Write-Err ("UDP receive error:`n" + ($_ | Out-String))
                    Write-Err ("Stack:`n" + $_.ScriptStackTrace)
                 }
            }
        }
    } finally {
        $udpClient.Close()
        Write-Info "Mneti Agent stopped."
    }
}

# Entry point
if ($MyInvocation.InvocationName -ne '.') {
    Start-AgentListener
}