#Requires -Version 5.1
<#
.SYNOPSIS
    Mneti Agent - UDP Discovery Listener
.DESCRIPTION
    Lightweight, high-performance event-driven listener. Binds to UDP 5000 and waits silently.
    On receiving a valid HMAC-signed discovery broadcast from the IT server:
      1. Validates the HMAC-SHA256 signature - drops the packet on mismatch
      2. Drops packets that originated from one of THIS machine's own IP
         addresses (broadcast loopback of our own relay rebroadcasts)
      3. Checks whether this machine is the search target (targeted mode)
         or responds unconditionally (full mode)
      4. POSTs device info (hostname, MAC, IP, user, building, room) to server
      5. Detects ALL secondary private IPv4 subnets attached to this host and
         relays discovery into each one (multi-homed relay architecture):
         a) Managed clients: unicast UDP to ARP-known hosts + subnet broadcast
         b) Unmanaged clients: discovered via ARP + async ping sweep
      6. Relay depth tracking prevents rebroadcast storms (max depth = 1)

.FIXES (vs original)
    FIX 1 - Duplicate processing storm
        The server sends one broadcast per local interface (Python _broadcast_all
        runs one thread per interface). Each arrives as a separate UDP packet with
        the same request_id but from the same sender IP, so the self-loopback
        guard doesn't help and all three reach Test-AlreadySeen at nearly the
        same time — before any of them has finished inserting into the cache —
        causing all three to pass the dedup check and spawn parallel
        Invoke-SubnetRelay calls that then fight over ports 5002/5003/5004.

        Fix: move Test-AlreadySeen to run BEFORE Get-NetworkAdapters and the
        self-report block so the first packet wins immediately and all subsequent
        duplicates are dropped before any expensive work starts.

    FIX 2 - $host reserved variable crash in ping sweep
        PowerShell's $host is a read-only automatic variable. Using it as a
        for-loop counter throws "Cannot overwrite variable Host" and aborts the
        entire sweep silently. Fix: use $hostNum throughout.

    FIX 3 - Wrong callback URL in relay packet
        $localCallbackUrl was assigned before the listener port was confirmed,
        always defaulting to :5002 even when that port was occupied and the
        listener actually started on :5003 or :5004. Agents on the hotspot
        subnet would POST to a dead port.
        Fix: only assign $localCallbackUrl after $listener.Start() succeeds.

    FIX 4 - ARP-first targeted unicast delivery
        Instead of only broadcasting into the relay subnet, the agent now reads
        the ARP table BEFORE broadcasting (seeded by an early ping sweep) and
        sends a direct UDP unicast to each known host. This guarantees agents on
        hotspot-connected devices receive a packet with the correct, live
        callback URL immediately without depending on broadcast delivery.

    FIX 5 - Unmanaged device POST destination
        Unmanaged devices were reported to $localCallbackUrl (the relay listener
        port, which tears down after 30s). They are now POSTed directly to
        $Packet.callback_url (the Flask server's real URL) via the hotspot host.

.NOTES
    Requires config.json at C:\ProgramData\Locator\config.json
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = 'SilentlyContinue'

# ── Constants ─────────────────────────────────────────────────────────────────
$CONFIG_FILE     = 'C:\ProgramData\Locator\config.json'
$LOG_FILE        = 'C:\ProgramData\Locator\agent.log'
$UDP_PORT        = 5000
$RELAY_HTTP_PORT = 5002
$BUFFER_SIZE     = 4096
$POST_TIMEOUT    = 8
$CACHE_TTL       = 60
$MAX_LOG_BYTES   = 5MB
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
# Use ConcurrentDictionary so TryAdd() is atomic with no mutex / timeout risk.
# Four packets with the same request_id arriving within milliseconds all call
# TryAdd() simultaneously — exactly one returns $true (the winner), the rest
# return $false immediately. No WaitOne() timeout means no race window.
$script:SeenIds = New-Object 'System.Collections.Concurrent.ConcurrentDictionary[string,long]'

function Test-AlreadySeen {
    param([string]$RequestId)
    $now = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()

    # Attempt atomic insert. TryAdd returns $true only for the FIRST caller.
    # All subsequent callers with the same key get $false → already seen.
    if (-not $script:SeenIds.TryAdd($RequestId, $now)) {
        return $true   # duplicate
    }

    # We won the race — this is the first time we've seen this request_id.
    # Opportunistically evict entries older than CACHE_TTL to keep memory bounded.
    foreach ($key in @($script:SeenIds.Keys)) {
        $ts = 0L
        if ($script:SeenIds.TryGetValue($key, [ref]$ts)) {
            if (($now - $ts) -gt $CACHE_TTL) {
                $script:SeenIds.TryRemove($key, [ref]$ts) | Out-Null
            }
        }
    }
    return $false   # first time seen
}

# ── Network helpers ───────────────────────────────────────────────────────────
function Get-NetworkAdapters {
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

    # Virtual/loopback adapter name patterns to always skip
    $skipPatterns = @('*WSL*', '*Loopback*', '*Bluetooth*', '*vEthernet*', 
                      '*Virtual*', '*Hyper-V*', '*Tunnel*', '*isatap*', '*Teredo*')

    try {
        Get-NetAdapter | Where-Object { $_.Status -eq 'Up' } | ForEach-Object {
            $adapter = $_

            # FIX 1: Skip virtual/software adapters (WSL, Hyper-V, etc.)
            $adapterName = $adapter.Name
            $isVirtual = $false
            foreach ($pattern in $skipPatterns) {
                if ($adapterName -like $pattern -or $adapter.InterfaceDescription -like $pattern) {
                    $isVirtual = $true
                    break
                }
            }
            if ($isVirtual) {
                Write-Info "Skipping virtual adapter: $adapterName"
                return
            }

            $addrs = Get-NetIPAddress -InterfaceIndex $adapter.InterfaceIndex `
                                      -AddressFamily IPv4 -ErrorAction SilentlyContinue
            foreach ($addr in $addrs) {
                $ip     = $addr.IPAddress
                $prefix = $addr.PrefixLength
                if ($ip -like '127.*' -or $ip -like '169.254.*') { continue }
                if (-not (Test-IsPrivateIP -IP $ip)) { continue }

                # FIX 2: Check if this adapter's IP is in the same subnet as the sender
                # using THIS adapter's own prefix length. Also check with common prefix
                # lengths (/22, /23, /24) to catch misconfigured adapters on the same
                # physical network segment.
                $skipThisAdapter = $false
                foreach ($testPrefix in @($prefix, 22, 23, 24)) {
                    $myBcast     = Get-SubnetBroadcast -IP $ip     -PrefixLength $testPrefix
                    $senderBcast = Get-SubnetBroadcast -IP $SenderIP -PrefixLength $testPrefix
                    if ($myBcast -eq $senderBcast) {
                        Write-Info "Skipping subnet same as originator (prefix /$testPrefix match): $ip/$prefix"
                        $skipThisAdapter = $true
                        break
                    }
                }
                if ($skipThisAdapter) { continue }

                $dedupKey = "$ip/$prefix"
                if ($seen.ContainsKey($dedupKey)) { continue }
                $seen[$dedupKey] = $true

                $broadcast = Get-SubnetBroadcast -IP $ip -PrefixLength $prefix
                $relayNets += [pscustomobject]@{
                    IPAddress   = $ip
                    Broadcast   = $broadcast
                    Prefix      = $prefix
                    Interface   = $adapter.InterfaceIndex
                    AdapterName = $adapterName
                }
                Write-Info "Relay subnet detected: $ip/$prefix (broadcast $broadcast) on $adapterName"
            }
        }
    } catch {
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

    $relayDepth = 0
    if ($null -ne $p.relay_depth) { $relayDepth = [int]$p.relay_depth }

    $isPrimary = $false
    if ($null -ne $p.is_primary) { $isPrimary = [bool]$p.is_primary }

    # Order must match Flask server _build_packet exactly
    $payloadJson = '{"request_id":"' + $p.request_id + '","mode":"' + $p.mode + '","target":"' + $p.target + '","token":"' + $p.token + '","callback_url":"' + $p.callback_url + '","timestamp":"' + $p.timestamp + '","relay_depth":' + $relayDepth + ',"is_primary":' + $isPrimary.ToString().ToLower() + '}'
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

        $req             = [System.Net.HttpWebRequest]::Create($CallbackUrl)
        $req.Method      = 'POST'
        $req.ContentType = 'application/json'
        $req.Timeout     = $POST_TIMEOUT * 1000
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

# ── Build a relay broadcast packet ────────────────────────────────────────────
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

    $payloadJson = '{"request_id":"' + $relayPayload.request_id + '","mode":"' + $relayPayload.mode + '","target":"' + $relayPayload.target + '","token":"' + $relayPayload.token + '","callback_url":"' + $relayPayload.callback_url + '","timestamp":"' + $relayPayload.timestamp + '","relay_depth":' + $relayPayload.relay_depth + '}'
    $sig = Get-HmacSha256 -Secret $Token -Message $payloadJson

    $envelope = @{ payload = $relayPayload; sig = $sig }
    return [System.Text.Encoding]::UTF8.GetBytes(($envelope | ConvertTo-Json -Compress -Depth 5))
}

# ── ARP cache reader ──────────────────────────────────────────────────────────
# Returns hashtable of IP → MAC for dynamic ARP entries inside the given subnet.
# Always excludes $ExcludeIP (the local interface address).
function Get-ArpHostsInSubnet {
    param(
        [string]$LocalIP,
        [int]   $PrefixLength,
        [string]$ExcludeIP
    )
    $hosts = @{}
    try {
        $ipObj   = [System.Net.IPAddress]::Parse($LocalIP)
        $ipBytes = $ipObj.GetAddressBytes(); [array]::Reverse($ipBytes)
        $ipInt   = [BitConverter]::ToUInt32($ipBytes, 0)

        $mask = [uint32]0
        for ($b = 0; $b -lt $PrefixLength; $b++) { $mask = $mask -bor (1 -shl (31 - $b)) }
        $network   = $ipInt -band $mask
        $broadcast = $network -bor (-bnot $mask -band 0xFFFFFFFF)

        $arpOutput = arp -a 2>$null
        foreach ($line in $arpOutput) {
            if ($line -match '(\d{1,3}(?:\.\d{1,3}){3})\s+([\da-fA-F]{2}(?:[:\-][\da-fA-F]{2}){5})\s+(dynamic|static)') {
                $arpIP  = $Matches[1]
                $arpMac = ($Matches[2].ToUpper() -replace '-', ':')
                if ($arpIP -eq $ExcludeIP) { continue }
                try {
                    $aObj   = [System.Net.IPAddress]::Parse($arpIP)
                    $aBytes = $aObj.GetAddressBytes(); [array]::Reverse($aBytes)
                    $aInt   = [BitConverter]::ToUInt32($aBytes, 0)
                    if (($aInt -band $mask) -eq $network -and $aInt -ne $broadcast -and $aInt -ne $network) {
                        $hosts[$arpIP] = $arpMac
                    }
                } catch {}
            }
        }
    } catch {
        Write-Warn "Get-ArpHostsInSubnet error: $_"
    }
    return $hosts
}

# ── Subnet relay ──────────────────────────────────────────────────────────────
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

    # ── Step 1: Early ping sweep to seed the ARP cache ────────────────────────
    # Fire async pings at the whole subnet range NOW, before starting the
    # listener. Responses will populate the ARP table while the listener is
    # running, so by the time we do ARP reads we have fresh entries.
    #
    # CRITICAL: Do NOT use $host as the loop variable — it is a PowerShell
    # reserved automatic variable (read-only). Using it throws:
    #   "Cannot overwrite variable Host because it is read-only or constant"
    # and aborts the entire loop. Use $hostNum instead.
    Write-Info "Ping sweep (ARP seed) on $localIP/$prefix ..."
    try {
        $ipObj   = [System.Net.IPAddress]::Parse($localIP)
        $ipBytes = $ipObj.GetAddressBytes(); [array]::Reverse($ipBytes)
        $ipInt   = [BitConverter]::ToUInt32($ipBytes, 0)

        $mask      = [uint32]0
        for ($b = 0; $b -lt $prefix; $b++) { $mask = $mask -bor (1 -shl (31 - $b)) }
        $network   = $ipInt -band $mask
        $broadcast = $network -bor (-bnot $mask -band 0xFFFFFFFF)

        for ($hostNum = ($network + 1); $hostNum -lt $broadcast; $hostNum++) {
            $hBytes = [BitConverter]::GetBytes([uint32]$hostNum)
            [array]::Reverse($hBytes)
            $targetIP = ([System.Net.IPAddress]$hBytes).ToString()
            if ($targetIP -eq $localIP) { continue }
            try {
                $ping = New-Object System.Net.NetworkInformation.Ping
                $ping.SendAsync($targetIP, 150, $null) | Out-Null
            } catch {}
        }

        # Short wait so some pings can populate the ARP table before we read it
        Start-Sleep -Milliseconds 800
    } catch {
        Write-Warn "Ping sweep failed on $localIP/$prefix : $_"
    }

    # ── Step 2: Read ARP table (pre-listener snapshot) ────────────────────────
    $arpHosts = Get-ArpHostsInSubnet -LocalIP $localIP -PrefixLength $prefix -ExcludeIP $localIP
    Write-Info "ARP pre-scan: $(@($arpHosts.Keys).Count) host(s) known on $localIP/$prefix"

    # ── Step 3: Start relay HTTP listener ─────────────────────────────────────
    # Try ports 5002→5006. $localCallbackUrl is only set AFTER a port succeeds,
    # so the URL embedded in relay packets always points to the live listener.
    $listener         = $null
    $listenerStarted  = $false
    $relayPort        = $null
    $localCallbackUrl = $null

    for ($attempt = 0; $attempt -le 4; $attempt++) {
        try {
            $relayPort = $RELAY_HTTP_PORT + $attempt

            Write-Info "Attempting relay listener on ${localIP}:$relayPort"

            $listener = New-Object System.Net.HttpListener
            $listener.Prefixes.Add("http://$($localIP):$relayPort/api/report/")
            $listener.Start()

            # Only set the URL here — after Start() confirms the port is live
            $localCallbackUrl = "http://$($localIP):$relayPort/api/report"
            $listenerStarted  = $true
            Write-Info "Relay HTTP listener started on ${localIP}:$relayPort"
            break
        } catch {
            Write-Warn "Relay listener attempt $attempt failed on port $relayPort : $_"
            try { if ($listener) { $listener.Close() } } catch {}
            $listener = $null
        }
    }

    if (-not $listenerStarted) {
        Write-Warn "Failed to start relay listener for subnet $localIP/$prefix"
        return
    }

    try {
        # ── Step 4: Build relay packet (uses the confirmed live callback URL) ──
        $packetBytes = Build-RelayPacket `
            -OriginalPayload  $Packet `
            -LocalCallbackUrl $localCallbackUrl `
            -Token            $Config.token `
            -RelayDepth       $newDepth

        # ── Step 5: ARP-first targeted unicast delivery ───────────────────────
        # For every host already in the ARP table, send a direct UDP unicast.
        # This means managed agents on hotspot-connected devices receive a
        # packet with the correct callback URL immediately, without relying on
        # broadcast delivery (which some OS/driver combinations suppress).
        foreach ($arpIP in $arpHosts.Keys) {
            try {
                $udpUnicast = New-Object System.Net.Sockets.UdpClient
                $udpUnicast.EnableBroadcast = $false
                $udpUnicast.Send($packetBytes, $packetBytes.Length, $arpIP, $UDP_PORT) | Out-Null
                $udpUnicast.Close()
                Write-Info "Unicast discovery sent to $arpIP (MAC $($arpHosts[$arpIP]))"
            } catch {
                Write-Warn "Unicast to $arpIP failed: $_"
            }
        }

        # Subnet broadcast for any device not yet in the ARP table
        try {
            $udpBcast = New-Object System.Net.Sockets.UdpClient
            $udpBcast.EnableBroadcast = $true
            $udpBcast.Send($packetBytes, $packetBytes.Length, $broadcastAddr, $UDP_PORT) | Out-Null
            $udpBcast.Close()
            Write-Info "Rebroadcasting discovery to ${broadcastAddr}:$UDP_PORT (depth $newDepth)"
        } catch {
            Write-Warn "UDP rebroadcast to $broadcastAddr failed: $_"
        }

        # ── Step 6: Collect managed agent responses (30s window) ──────────────
        $managedReports = @()
        $deadline       = [DateTime]::Now.AddSeconds(30)

        while ([DateTime]::Now -lt $deadline) {
            try {
                if (-not $listener.IsListening) { break }

                $asyncResult = $listener.BeginGetContext($null, $null)
                $signaled    = $asyncResult.AsyncWaitHandle.WaitOne(250)
                if (-not $signaled) { continue }

                $ctx    = $listener.EndGetContext($asyncResult)
                $req    = $ctx.Request
                $res    = $ctx.Response
                $reader = New-Object System.IO.StreamReader($req.InputStream, [System.Text.Encoding]::UTF8)
                $body   = $reader.ReadToEnd()
                $reader.Close()

                # Acknowledge immediately so the client doesn't hang
                $buf = [System.Text.Encoding]::UTF8.GetBytes('{"status":"ok"}')
                $res.ContentLength64 = $buf.Length
                $res.OutputStream.Write($buf, 0, $buf.Length)
                $res.OutputStream.Close()

                $report       = $body | ConvertFrom-Json
                $clientHmac   = $req.Headers.Get('X-Signature')
                $expectedHmac = Get-HmacSha256 -Secret $Config.token -Message $body

                if ((Test-ConstantTimeEqual $clientHmac $expectedHmac) -and
                    (Test-ConstantTimeEqual $report.token $Config.token)) {
                    $managedReports += $report
                    Write-Info "Managed client responded via relay: $($report.hostname) ($($report.ip))"
                } else {
                    Write-Warn "Invalid signature on relay response - discarded"
                }
            } catch {
                Write-Warn "Error reading relay response: $_"
            }
        }

        Write-Info "Relay listener completed. Managed responses: $(@($managedReports).Count)"

        # ── Step 7: Re-read ARP (now fully populated after the 30s window) ────
        $arpHostsFinal = Get-ArpHostsInSubnet -LocalIP $localIP -PrefixLength $prefix -ExcludeIP $localIP
        Write-Info "ARP scan found $(@($arpHostsFinal.Keys).Count) device(s) in $localIP/$prefix"

        # ── Step 8: Forward managed/relayed reports to the Flask server ───────
        # The hotspot host POSTs on behalf of relay clients using the original
        # Flask server callback URL ($Packet.callback_url), not the local relay
        # listener port (which is about to be torn down).
        $managedMacs = @{}
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

            Send-Report -CallbackUrl $Packet.callback_url -Report $relayReport -Token $Config.token
        }

        # ── Step 9: Forward unmanaged (ARP-only) devices to the Flask server ──
        # Devices seen in ARP that never POSTed a managed report have no agent.
        # The hotspot host reports them as type='unmanaged' so the server knows
        # they exist. Building/room are blank — their location is unknown.
        foreach ($arpIP in $arpHostsFinal.Keys) {
            $arpMac = $arpHostsFinal[$arpIP]
            if ($managedMacs.ContainsKey($arpMac)) { continue }

            $hostname = Resolve-DeviceHostname -IP $arpIP
            if (-not $hostname) { $hostname = "Unmanaged-$arpIP" }
            $vendor = Get-MacVendor -MAC $arpMac

            Write-Info "Unmanaged device discovered: $arpIP ($arpMac) $vendor"

            $unmanagedReport = @{
                token          = $Config.token
                request_id     = $Packet.request_id
                hostname       = $hostname
                mac            = $arpMac
                ip             = $arpIP
                username       = ''
                # Unmanaged devices cannot report their own location.
                # Inherit building/room from the relay host so the server
                # knows this device was physically near the hotspotting machine.
                building       = $MyBuilding
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

    } finally {
        if ($listener) {
            try { if ($listener.IsListening) { $listener.Stop() } } catch {}
            try { $listener.Close() } catch {}
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
    $isPrimary   = [bool]$payload.is_primary

    if (-not $requestId -or -not $callbackUrl) {
        Write-Warn "Packet missing request_id or callback_url - dropped"
        return
    }

    # ── FIX 1: Dedup check runs FIRST ─────────────────────────────────────────
    # The Flask server broadcasts once per local interface (Python _broadcast_all
    # spawns one thread per interface). All copies carry the same request_id but
    # arrive as separate UDP datagrams, potentially milliseconds apart. If the
    # dedup check runs after Get-NetworkAdapters / the self-report block, all
    # three copies can pass concurrently before any of them has inserted the ID
    # into the cache, spawning duplicate Invoke-SubnetRelay calls that race for
    # the same relay ports (causing the 5002/5003/5004 conflict storm in logs).
    #
    # By running Test-AlreadySeen first — before ANY other work — the mutex
    # ensures exactly one copy wins and all subsequent duplicates are dropped
    # immediately with zero side effects.
    if (Test-AlreadySeen -RequestId $requestId) {
        Write-Debug2 "Duplicate request_id $requestId - ignored"
        return
    }

    # ── Self-loopback guard ────────────────────────────────────────────────────
    # When THIS machine relays into a subnet it owns (hotspot / WSL vEthernet),
    # the UDP broadcast loops back to our own socket. Drop any packet whose
    # sender IP is one of our own adapter addresses.
    $adapters = Get-NetworkAdapters
    $myIPs    = @($adapters | ForEach-Object { $_.IP })

    if ($myIPs -contains $SenderIP) {
        Write-Debug2 "Dropping self-originated broadcast from $SenderIP (id=$requestId, depth=$relayDepth) - loopback of our own relay rebroadcast"
        return
    }

    Write-Info "Discovery request: mode=$mode depth=$relayDepth id=$requestId from=$SenderIP"

    $myHostname = $env:COMPUTERNAME
    $myBuilding = $Config.building
    $myRoom     = $Config.room

    # ── Self-report ────────────────────────────────────────────────────────────
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

        # Include physical port and connection info if this is a primary subnet discovery
        
            $report.connection_type  = $Config.connection_type
            $report.port             = $Config.port
            $report.additional_ports = $Config.additional_ports
        

        Send-Report -CallbackUrl $callbackUrl -Report $report -Token $Config.token
    }

    # ── Relay into secondary subnets ───────────────────────────────────────────
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