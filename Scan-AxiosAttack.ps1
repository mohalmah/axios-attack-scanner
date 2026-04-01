#Requires -Version 5.1
<#
.SYNOPSIS
    Axios Supply Chain Attack Scanner - Windows Edition  v2.0
    Checks for axios@1.14.1 / plain-crypto-js RAT (March 2026)

.DESCRIPTION
    Interactive menu lets you choose which scan categories to run.
    Includes Claude Code-specific checks and real Windows IoCs.

.NOTES
    Run as Administrator for full scan.
    Usage: powershell -ExecutionPolicy Bypass -File .\Scan-AxiosAttack.ps1

.SOURCES
    Elastic Security Labs : https://www.elastic.co/security-labs/axios-one-rat-to-rule-them-all
    Wiz Blog              : https://www.wiz.io/blog/axios-npm-compromised-in-supply-chain-attack
    SANS Institute        : https://www.sans.org/blog/axios-npm-supply-chain-compromise-malicious-packages-remote-access-trojan
    Snyk                  : https://snyk.io/blog/axios-npm-package-compromised-supply-chain-attack-delivers-cross-platform/
    Aikido                : https://www.aikido.dev/blog/axios-npm-compromised-maintainer-hijacked-rat
    The Hacker News       : https://thehackernews.com/2026/03/axios-supply-chain-attack-pushes-cross.html
#>

param(
    [string]$ScanRoot    = $env:USERPROFILE,
    [switch]$FullDriveScan,
    [switch]$SkipProgress,
    [switch]$NoMenu
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "SilentlyContinue"

# ============================================================
#  GLOBALS
# ============================================================
$Script:Findings     = [System.Collections.Generic.List[hashtable]]::new()
$Script:ScannedCount = 0
$Script:StartTime    = Get-Date
$Script:IsAdmin      = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
                           [Security.Principal.WindowsBuiltInRole]::Administrator)

# Real C2 infrastructure (Elastic / Wiz research)
$Script:C2_Domain = "sfrclak.com"
$Script:C2_IP     = "142.11.206.73"
$Script:C2_Port   = 8000

# ============================================================
#  COLOUR / UI HELPERS
# ============================================================
function Write-Color {
    param([string]$Text, [ConsoleColor]$Color = "White", [switch]$NoNewline)
    if ($NoNewline) { Write-Host $Text -ForegroundColor $Color -NoNewline }
    else            { Write-Host $Text -ForegroundColor $Color }
}

function Write-Banner {
    Clear-Host
    Write-Color ""
    Write-Color "  +====================================================================+" Cyan
    Write-Color "  |   AXIOS SUPPLY CHAIN ATTACK SCANNER  v2.0  (Windows)              |" Cyan
    Write-Color "  |   March 2026 RAT Detection & Compromise Assessment                |" Cyan
    Write-Color "  +====================================================================+" Cyan
    Write-Color ""
    Write-Color "  Threat   : " White -NoNewline; Write-Color "axios@1.14.1 + plain-crypto-js@4.2.1" Yellow -NoNewline; Write-Color " (cross-platform RAT)" Red
    Write-Color "  C2 Host  : " White -NoNewline; Write-Color "sfrclak.com:8000 / 142.11.206.73" Red
    Write-Color "  Window   : " White -NoNewline; Write-Color "2026-03-31  00:21 UTC - 03:29 UTC" DarkYellow
    Write-Color "  Admin    : " White -NoNewline
    if ($Script:IsAdmin) { Write-Color "YES  (full scan)" Green }
    else { Write-Color "NO   (run as Admin for complete scan)" DarkYellow }
    Write-Color ""
    Write-Color "  ---- Sources -------------------------------------------------------" DarkGray
    Write-Color "  Elastic Security Labs, Wiz, SANS, Snyk, Aikido, The Hacker News" DarkGray
    Write-Color "  --------------------------------------------------------------------" DarkGray
    Write-Color ""
}

function Write-Section ([string]$Title) {
    $pad = "-" * [Math]::Max(2, 55 - $Title.Length)
    Write-Color ""
    Write-Color "  [ $Title ] $pad" Cyan
    Write-Color ""
}

function Write-Finding ([string]$Severity, [string]$Message, [string]$Detail = "") {
    $tag   = "[$Severity]".PadRight(10)
    $color = switch ($Severity) {
        "CRITICAL" { "Red" }
        "WARNING"  { "Yellow" }
        "INFO"     { "Cyan" }
        "SAFE"     { "Green" }
        default    { "Gray" }
    }
    Write-Color "  $tag " $color -NoNewline
    Write-Color $Message White
    if ($Detail) { Write-Color "             $Detail" DarkGray }
    $Script:Findings.Add(@{ Severity=$Severity; Message=$Message; Detail=$Detail })
}

function Write-ProgressBar ([string]$Status, [int]$Pct) {
    if ($SkipProgress) { return }
    $filled = [int]($Pct / 5)
    $bar    = ("#" * $filled) + ("." * (20 - $filled))
    $s      = if ($Status.Length -gt 45) { "..." + $Status.Substring($Status.Length-42) } else { $Status }
    Write-Host ("`r  [$bar] $("$Pct%".PadLeft(4))  $s" + (" " * 8)) -NoNewline -ForegroundColor DarkCyan
}

function Clear-Line { Write-Host ("`r" + (" " * 82) + "`r") -NoNewline }

# ============================================================
#  INTERACTIVE MENU
# ============================================================
function Show-Menu {
    $categories = [ordered]@{
        "1"  = "Lockfiles       - Scan package-lock.json / yarn.lock / pnpm-lock.yaml"
        "2"  = "node_modules    - Check if plain-crypto-js is installed on disk"
        "3"  = "Persistence     - Registry Run keys, Scheduled Tasks, Startup folder"
        "4"  = "Artifacts       - Known RAT files (%PROGRAMDATA%\wt.exe, TEMP, etc.)"
        "5"  = "Network / C2    - Active connections to sfrclak.com / 142.11.206.73"
        "6"  = "Processes       - Suspicious node.js processes"
        "7"  = "Claude Code     - Claude Code install, hooks, API keys, ~/.claude dir"
        "8"  = "Credentials     - Inventory SSH, AWS, .npmrc, .env files"
        "9"  = "Projects        - Full Node.js project inventory with axios versions"
        "A"  = "ALL             - Run every category above"
    }

    Write-Color "  Select scan categories (comma-separated, e.g. 1,3,7 or A for all):" White
    Write-Color ""
    foreach ($k in $categories.Keys) {
        $c = if ($k -eq "A") { "Yellow" } else { "Cyan" }
        Write-Color "    [$k] " $c -NoNewline
        Write-Color $categories[$k] White
    }
    Write-Color ""
    Write-Color "  > " Green -NoNewline
    $raw = Read-Host

    if ([string]::IsNullOrWhiteSpace($raw)) { $raw = "A" }
    $tokens = $raw.ToUpper().Split(",") | ForEach-Object { $_.Trim() }

    if ($tokens -contains "A") { return @("1","2","3","4","5","6","7","8","9") }
    return $tokens | Where-Object { $_ -match '^[1-9]$' }
}

# ============================================================
#  SCAN 1 : NPM LOCKFILES
# ============================================================
function Invoke-LockfileScan {
    Write-Section "1. NPM LOCKFILES"

    $roots = if ($FullDriveScan) {
        Get-PSDrive -PSProvider FileSystem | Where-Object { $_.Used -gt 0 } | Select-Object -ExpandProperty Root
    } else {
        @($ScanRoot,
          "$env:USERPROFILE\Desktop",
          "$env:USERPROFILE\Documents",
          "C:\dev","C:\projects","C:\code","C:\repos","C:\workspace",
          "C:\Users\$env:USERNAME\source",
          "C:\Users\$env:USERNAME\AppData\Roaming\npm",
          "C:\Program Files\nodejs")
    }

    $locks = [System.Collections.Generic.List[string]]::new()
    $i = 0
    foreach ($root in $roots) {
        if (-not (Test-Path $root)) { $i++; continue }
        Write-ProgressBar "Indexing $root..." ([int](($i/$roots.Count)*30))
        try {
            Get-ChildItem -Path $root -Recurse -Depth 8 -File -ErrorAction SilentlyContinue `
                -Include "package-lock.json","yarn.lock","pnpm-lock.yaml" |
            Where-Object { $_.FullName -notmatch '\\node_modules\\node_modules\\' } |
            ForEach-Object { $locks.Add($_.FullName) }
        } catch {}
        $i++
    }
    Clear-Line
    Write-Color "  Found $($locks.Count) lockfile(s)" DarkGray
    Write-Color ""

    $compromised = [System.Collections.Generic.List[string]]::new()
    $total = $locks.Count
    $idx   = 0

    foreach ($f in $locks) {
        $idx++
        $pct   = [int](30 + ($idx/[Math]::Max($total,1))*55)
        $short = $f -replace [regex]::Escape($env:USERPROFILE),"~"
        Write-ProgressBar $short $pct
        $Script:ScannedCount++

        try {
            $c        = [System.IO.File]::ReadAllText($f)
            $hasAxios = $c -match 'axios@1\.14\.1|"axios":\s*"1\.14\.1"'
            $hasCrypt = $c -match 'plain-crypto-js'
            $hasOld04 = $c -match 'axios@0\.30\.4|"axios":\s*"0\.30\.4"'   # second malicious version

            if ($hasAxios -or $hasCrypt -or $hasOld04) {
                $compromised.Add($f)
                Clear-Line
                Write-Finding "CRITICAL" "COMPROMISED lockfile!" $f
                if ($hasAxios)  { Write-Color "             -> axios@1.14.1 found" Red }
                if ($hasOld04)  { Write-Color "             -> axios@0.30.4 found (also malicious!)" Red }
                if ($hasCrypt)  { Write-Color "             -> plain-crypto-js present (RAT dropper)" Red }
            }
        } catch {}
    }
    Clear-Line

    if ($compromised.Count -eq 0) {
        Write-Finding "SAFE" "No compromised lockfiles ($total scanned)"
    } else {
        Write-Color ""
        Write-Color "  !! $($compromised.Count) COMPROMISED PROJECT(S) FOUND !!" Red
    }

    return $compromised
}

# ============================================================
#  SCAN 2 : NODE_MODULES ON DISK
# ============================================================
function Invoke-NodeModulesScan {
    Write-Section "2. INSTALLED node_modules"

    $roots   = @($ScanRoot,"C:\dev","C:\projects","C:\code","C:\repos")
    $results = [System.Collections.Generic.List[string]]::new()

    foreach ($root in $roots) {
        if (-not (Test-Path $root)) { continue }
        try {
            Get-ChildItem -Path $root -Recurse -Depth 10 -Directory `
                -Filter "plain-crypto-js" -ErrorAction SilentlyContinue |
            ForEach-Object { $results.Add($_.FullName) }
        } catch {}
    }

    if ($results.Count -gt 0) {
        foreach ($d in $results) { Write-Finding "CRITICAL" "plain-crypto-js INSTALLED on disk!" $d }
    } else {
        Write-Finding "SAFE" "plain-crypto-js not found in any node_modules"
    }
}

# ============================================================
#  SCAN 3 : WINDOWS PERSISTENCE
# ============================================================
function Invoke-PersistenceScan {
    Write-Section "3. WINDOWS PERSISTENCE"

    $badTerms = @("plain-crypto","axios-rat","sfrclak","act.mond","ld-linux",
                  "cryptojs-payload","npm-postinstall-rat","node-rat","exfil","wt.exe")

    # Registry Run keys
    Write-Color "  Checking registry Run keys..." DarkGray
    $runKeys = @(
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run",
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce",
        "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run",
        "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce",
        "HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run"
    )
    $regHits = 0
    foreach ($key in $runKeys) {
        try {
            $props = Get-ItemProperty -Path $key -ErrorAction SilentlyContinue
            if (-not $props) { continue }
            $props.PSObject.Properties | Where-Object { $_.Name -notlike "PS*" } | ForEach-Object {
                $val = $_.Value.ToString().ToLower()
                foreach ($t in $badTerms) {
                    if ($val -match [regex]::Escape($t)) {
                        Write-Finding "CRITICAL" "Suspicious registry Run: $($_.Name)" "$key = $($_.Value)"
                        $regHits++
                    }
                }
                if ($val -match 'node(\.exe)?.*(temp|appdata|roaming|programdata)' -or
                    $val -match '(temp|tmp).*(\.js|node)') {
                    Write-Finding "WARNING"  "Suspicious node autorun: $($_.Name)" $_.Value
                    $regHits++
                }
            }
        } catch {}
    }
    if ($regHits -eq 0) { Write-Finding "SAFE" "Registry Run keys clean" }

    # Scheduled Tasks
    Write-Color "  Checking Scheduled Tasks..." DarkGray
    $taskHits = 0
    try {
        Get-ScheduledTask -ErrorAction SilentlyContinue |
        Where-Object { $_.State -ne "Disabled" } |
        ForEach-Object {
            $task = $_
            $task.Actions | Where-Object { $_.Execute } | ForEach-Object {
                $combined = ("$($_.Execute) $($_.Arguments)").ToLower()
                foreach ($t in $badTerms) {
                    if ($combined -match [regex]::Escape($t)) {
                        Write-Finding "CRITICAL" "Suspicious scheduled task: $($task.TaskName)" $combined
                        $taskHits++
                    }
                }
                if ($combined -match 'node(\.exe)?.*(temp|tmp|appdata|programdata)') {
                    Write-Finding "WARNING"  "Suspicious node.js task: $($task.TaskName)" $combined
                    $taskHits++
                }
            }
        }
    } catch {}
    if ($taskHits -eq 0) { Write-Finding "SAFE" "No suspicious scheduled tasks" }

    # Startup folder
    Write-Color "  Checking Startup folders..." DarkGray
    $startupDirs = @(
        "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup",
        "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp"
    )
    $startupHits = 0
    foreach ($dir in $startupDirs) {
        if (-not (Test-Path $dir)) { continue }
        Get-ChildItem -Path $dir -File -ErrorAction SilentlyContinue |
        Where-Object { $_.Extension -in @(".js",".ts",".vbs",".bat",".cmd",".ps1") } |
        ForEach-Object {
            Write-Finding "WARNING" "Script in Startup folder: $($_.Name)" $_.FullName
            $startupHits++
        }
    }
    if ($startupHits -eq 0) { Write-Finding "SAFE" "No suspicious scripts in Startup folders" }
}

# ============================================================
#  SCAN 4 : WINDOWS RAT ARTIFACTS (real IoCs from Elastic/Wiz)
# ============================================================
function Invoke-ArtifactScan {
    Write-Section "4. RAT ARTIFACTS (Windows IoCs)"

    Write-Color "  Checking primary Windows IoC: %PROGRAMDATA%\wt.exe ..." DarkGray
    Write-Color "  (RAT copies hidden VBScript interpreter here - Elastic Security Labs)" DarkGray
    Write-Color ""

    # PRIMARY IoC: wt.exe in ProgramData (not the legitimate Windows Terminal)
    $wtPath = "$env:PROGRAMDATA\wt.exe"
    if (Test-Path $wtPath) {
        $f = Get-Item $wtPath -ErrorAction SilentlyContinue
        # Legitimate Windows Terminal is in WindowsApps, not ProgramData root
        Write-Finding "CRITICAL" "wt.exe found in ProgramData - RAT IoC!" $wtPath
        Write-Color "             Size: $($f.Length) bytes  |  Created: $($f.CreationTime)" Red
    } else {
        Write-Finding "SAFE" "%PROGRAMDATA%\wt.exe not present (primary Windows IoC)" $wtPath
    }

    # Secondary artifact locations
    $patterns = @(
        "$env:TEMP\plain-crypto*",
        "$env:TMP\plain-crypto*",
        "$env:LOCALAPPDATA\Temp\plain-crypto*",
        "$env:APPDATA\plain-crypto*",
        "$env:LOCALAPPDATA\plain-crypto*",
        "$env:TEMP\ld*",
        "$env:TMP\ld*",
        "$env:PROGRAMDATA\plain-crypto*",
        "$env:PROGRAMDATA\npm-*"
    )

    $artHits = 0
    foreach ($p in $patterns) {
        try {
            Get-Item -Path $p -ErrorAction SilentlyContinue | ForEach-Object {
                Write-Finding "CRITICAL" "RAT artifact found!" $_.FullName
                $artHits++
            }
        } catch {}
    }

    # VBScript / WScript files created recently in ProgramData
    Write-Color "  Checking ProgramData for suspicious scripts..." DarkGray
    try {
        Get-ChildItem -Path $env:PROGRAMDATA -File -Filter "*.vbs" -ErrorAction SilentlyContinue |
        Where-Object { $_.CreationTime -gt (Get-Date).AddDays(-30) } |
        ForEach-Object {
            Write-Finding "WARNING" "Recent .vbs in ProgramData: $($_.Name)" $_.FullName
            $artHits++
        }
    } catch {}

    # Suspicious .js in TEMP (last 7 days)
    Write-Color "  Checking TEMP for obfuscated .js files..." DarkGray
    try {
        Get-ChildItem -Path $env:TEMP -Filter "*.js" -File -ErrorAction SilentlyContinue |
        Where-Object { $_.CreationTime -gt (Get-Date).AddDays(-7) } |
        ForEach-Object {
            $content = [System.IO.File]::ReadAllText($_.FullName) -replace '\s',''
            if ($content.Length -gt 400 -and $content -match 'eval|exec|spawn|socket|https?\.') {
                Write-Finding "WARNING" "Obfuscated .js in TEMP: $($_.Name)" $_.FullName
                $artHits++
            }
        }
    } catch {}

    if ($artHits -eq 0) { Write-Finding "SAFE" "No secondary RAT artifacts found" }
}

# ============================================================
#  SCAN 5 : NETWORK / C2 CONNECTIONS
# ============================================================
function Invoke-NetworkScan {
    Write-Section "5. NETWORK - C2 CONNECTIONS"

    Write-Color "  Known C2 infrastructure:" DarkGray
    Write-Color "    Domain : sfrclak.com" DarkYellow
    Write-Color "    IP     : 142.11.206.73" DarkYellow
    Write-Color "    Port   : 8000" DarkYellow
    Write-Color "    Beacon : POST to packages.npm.org/product1" DarkYellow
    Write-Color ""

    $netHits = 0

    # Check active TCP connections
    Write-Color "  Scanning active TCP connections..." DarkGray
    try {
        $conns = Get-NetTCPConnection -State Established,TimeWait -ErrorAction SilentlyContinue
        foreach ($conn in $conns) {
            $ip   = $conn.RemoteAddress
            $port = $conn.RemotePort

            if ($ip -eq $Script:C2_IP -or $port -eq $Script:C2_Port) {
                $proc = Get-Process -Id $conn.OwningProcess -ErrorAction SilentlyContinue
                $name = if ($proc) { $proc.Name } else { "PID $($conn.OwningProcess)" }
                Write-Finding "CRITICAL" "LIVE C2 CONNECTION DETECTED!" "$name -> $ip`:$port"
                $netHits++
            }
        }
    } catch {}

    # DNS cache check for C2 domain
    Write-Color "  Checking DNS cache for C2 domain..." DarkGray
    try {
        $dnsCache = Get-DnsClientCache -ErrorAction SilentlyContinue
        $c2dns    = $dnsCache | Where-Object { $_.Entry -match "sfrclak" -or $_.Data -eq $Script:C2_IP }
        if ($c2dns) {
            foreach ($entry in $c2dns) {
                Write-Finding "CRITICAL" "C2 domain in DNS cache - machine called home!" "$($entry.Entry) -> $($entry.Data)"
                $netHits++
            }
        }
    } catch {}

    # Hosts file tampering
    Write-Color "  Checking hosts file for tampering..." DarkGray
    $hostsPath = "$env:SystemRoot\System32\drivers\etc\hosts"
    try {
        $hosts = Get-Content $hostsPath -ErrorAction SilentlyContinue
        $suspicious = $hosts | Where-Object {
            $_ -notmatch '^#' -and $_ -match '\S' -and
            ($_ -match 'sfrclak|plain-crypto|npm-postinstall')
        }
        if ($suspicious) {
            foreach ($line in $suspicious) {
                Write-Finding "CRITICAL" "Suspicious hosts file entry!" $line
                $netHits++
            }
        } else {
            Write-Finding "SAFE" "Hosts file looks clean"
        }
    } catch {}

    # Windows Firewall - check for suspicious outbound rules
    Write-Color "  Checking Windows Firewall outbound rules..." DarkGray
    try {
        $fwRules = Get-NetFirewallRule -Direction Outbound -Action Allow -ErrorAction SilentlyContinue |
                   Where-Object { $_.DisplayName -match 'node|npm|plain-crypto|sfrclak' -and
                                  $_.Enabled -eq "True" }
        if ($fwRules) {
            foreach ($rule in $fwRules) {
                Write-Finding "WARNING" "Suspicious firewall rule: $($rule.DisplayName)" $rule.Description
                $netHits++
            }
        }
    } catch {}

    if ($netHits -eq 0) { Write-Finding "SAFE" "No active C2 connections or DNS evidence found" }
}

# ============================================================
#  SCAN 6 : RUNNING PROCESSES
# ============================================================
function Invoke-ProcessScan {
    Write-Section "6. RUNNING PROCESSES"

    $procHits = 0
    try {
        $nodeProcs = Get-Process -Name "node" -ErrorAction SilentlyContinue
        if ($nodeProcs) {
            foreach ($proc in $nodeProcs) {
                try {
                    $wmi = Get-WmiObject Win32_Process -Filter "ProcessId=$($proc.Id)" -ErrorAction SilentlyContinue
                    $cl  = if ($wmi -and $wmi.CommandLine) { $wmi.CommandLine.ToLower() } else { "" }
                    if ($cl -match 'temp|tmp|appdata.*node|plain-crypto|exfil|sfrclak') {
                        Write-Finding "WARNING" "Suspicious node.js process" "PID $($proc.Id): $cl"
                        $procHits++
                    } else {
                        Write-Color "  [OK]       node.exe PID $($proc.Id)  $cl" DarkGray
                    }
                } catch {}
            }
        } else {
            Write-Color "  No node.exe processes running" DarkGray
        }

        # wt.exe process (should only exist in WindowsApps if Win Terminal)
        $wtProcs = Get-Process -Name "wt" -ErrorAction SilentlyContinue
        foreach ($p in $wtProcs) {
            try {
                $wmi  = Get-WmiObject Win32_Process -Filter "ProcessId=$($p.Id)" -ErrorAction SilentlyContinue
                $path = if ($wmi -and $wmi.ExecutablePath) { $wmi.ExecutablePath } else { "" }
                if ($path -and $path -notmatch 'WindowsApps') {
                    Write-Finding "CRITICAL" "wt.exe running from non-standard path!" "PID $($p.Id): $path"
                    $procHits++
                }
            } catch {}
        }
    } catch {}

    if ($procHits -eq 0) { Write-Finding "SAFE" "No suspicious processes detected" }
}

# ============================================================
#  SCAN 7 : CLAUDE CODE SPECIFIC
# ============================================================
function Invoke-ClaudeCodeScan {
    Write-Section "7. CLAUDE CODE"

    Write-Color "  Claude Code could be affected if updated during the attack window:" DarkGray
    Write-Color "  2026-03-31 00:21 UTC to 03:29 UTC" DarkYellow
    Write-Color ""

    $claudeHits = 0

    # Location of Claude Code global npm install
    $claudePaths = @(
        "$env:APPDATA\npm\node_modules\@anthropic-ai\claude-code",
        "$env:APPDATA\npm\node_modules\claude",
        "C:\Program Files\nodejs\node_modules\@anthropic-ai\claude-code",
        "$env:USERPROFILE\AppData\Roaming\npm\node_modules\@anthropic-ai\claude-code"
    )

    Write-Color "  Checking Claude Code installation for axios contamination..." DarkGray
    $claudeInstallFound = $false
    foreach ($path in $claudePaths) {
        if (-not (Test-Path $path)) { continue }
        $claudeInstallFound = $true
        Write-Color "  Found Claude Code at: $path" DarkGray

        # Check its own lockfile / node_modules
        $lock = "$path\package-lock.json"
        if (Test-Path $lock) {
            $c = [System.IO.File]::ReadAllText($lock)
            if ($c -match 'axios@1\.14\.1|axios@0\.30\.4|plain-crypto-js') {
                Write-Finding "CRITICAL" "Claude Code install contains compromised axios!" $lock
                $claudeHits++
            } else {
                Write-Finding "SAFE" "Claude Code lockfile clean" $lock
            }
        }

        $cryptoDir = "$path\node_modules\plain-crypto-js"
        if (Test-Path $cryptoDir) {
            Write-Finding "CRITICAL" "plain-crypto-js found in Claude Code node_modules!" $cryptoDir
            $claudeHits++
        }
    }
    if (-not $claudeInstallFound) {
        Write-Color "  Claude Code global install not found in standard paths." DarkGray
        Write-Color "  Run: npm list -g --depth=0  to check manually." DarkGray
    }

    # ~/.claude directory
    $claudeDir = "$env:USERPROFILE\.claude"
    Write-Color ""
    Write-Color "  Checking ~/.claude directory..." DarkGray
    if (Test-Path $claudeDir) {
        Write-Color "  Found: $claudeDir" DarkGray

        # settings.json - check for injected hooks
        $settingsPath = "$claudeDir\settings.json"
        if (Test-Path $settingsPath) {
            try {
                $settings = Get-Content $settingsPath -Raw | ConvertFrom-Json -ErrorAction SilentlyContinue
                $settingsRaw = Get-Content $settingsPath -Raw

                # Check for suspicious hooks
                if ($settingsRaw -match 'hooks') {
                    Write-Color "  Hooks found in settings.json - reviewing..." DarkYellow
                    # Look for hooks that exec external URLs or temp paths
                    if ($settingsRaw -match 'sfrclak|plain-crypto|tmp.*node|temp.*node|http.*8000') {
                        Write-Finding "CRITICAL" "Malicious hook in Claude Code settings.json!" $settingsPath
                        $claudeHits++
                    } else {
                        Write-Finding "INFO" "Hooks present in settings.json - review manually" $settingsPath
                        Write-Color "             Check: $settingsPath" DarkGray
                    }
                } else {
                    Write-Finding "SAFE" "settings.json - no hooks configured"
                }
            } catch {
                Write-Finding "INFO" "Could not parse settings.json" $settingsPath
            }
        } else {
            Write-Color "  settings.json not found" DarkGray
        }

        # Check for ANTHROPIC_API_KEY exposure
        $envFile = "$claudeDir\.env"
        if (Test-Path $envFile) {
            Write-Finding "INFO" ".env found in ~/.claude - rotate ANTHROPIC_API_KEY if compromised" $envFile
        }

        # Recent files in ~/.claude (last 7 days, unusual extensions)
        try {
            Get-ChildItem -Path $claudeDir -Recurse -File -ErrorAction SilentlyContinue |
            Where-Object { $_.LastWriteTime -gt (Get-Date).AddDays(-7) -and
                           $_.Extension -in @(".js",".ts",".vbs",".exe",".bat") } |
            ForEach-Object {
                Write-Finding "WARNING" "Unusual recent file in ~/.claude: $($_.Name)" $_.FullName
                $claudeHits++
            }
        } catch {}

    } else {
        Write-Color "  ~/.claude directory not found (Claude Code may not be installed)" DarkGray
    }

    # Check ANTHROPIC_API_KEY env var exposure window
    Write-Color ""
    Write-Color "  Checking for Anthropic API key in environment..." DarkGray
    $apiKey = [System.Environment]::GetEnvironmentVariable("ANTHROPIC_API_KEY","User")
    if ($apiKey) {
        Write-Finding "INFO" "ANTHROPIC_API_KEY is set as user environment variable"
        Write-Color "             If machine was compromised, rotate at: console.anthropic.com/settings/keys" DarkYellow
    } else {
        Write-Color "  ANTHROPIC_API_KEY not set as user env var" DarkGray
    }

    if ($claudeHits -eq 0) { Write-Finding "SAFE" "No Claude Code-specific compromise indicators found" }
}

# ============================================================
#  SCAN 8 : CREDENTIAL EXPOSURE
# ============================================================
function Invoke-CredentialExposureScan {
    Write-Section "8. CREDENTIAL FILES AT RISK"

    Write-Color "  If ANY lockfile was compromised, rotate ALL of these:" DarkYellow
    Write-Color ""

    $credItems = @(
        @{ Path="$env:USERPROFILE\.ssh";         Label="SSH private keys  "; Patterns=@("id_*","*.pem","*.key") }
        @{ Path="$env:USERPROFILE\.aws";         Label="AWS credentials   "; Patterns=@("credentials","config") }
        @{ Path="$env:APPDATA\gcloud";           Label="GCloud credentials"; Patterns=@("*.json") }
        @{ Path="$env:USERPROFILE\.npmrc";       Label=".npmrc (npm token)"; Patterns=@() }
        @{ Path="$env:USERPROFILE\.gitconfig";   Label=".gitconfig        "; Patterns=@() }
        @{ Path="$env:USERPROFILE\.config\gh";   Label="GitHub CLI token  "; Patterns=@("hosts.yml","config.yml") }
    )

    foreach ($item in $credItems) {
        if (-not (Test-Path $item.Path)) { continue }
        $target = Get-Item $item.Path -ErrorAction SilentlyContinue
        if (-not $target) { continue }
        $count = 0
        if ($target.PSIsContainer) {
            foreach ($pat in $item.Patterns) {
                $count += (Get-ChildItem -Path $item.Path -Filter $pat -File -ErrorAction SilentlyContinue |
                           Measure-Object).Count
            }
        } else { $count = 1 }
        if ($count -gt 0) {
            Write-Color "  [KEY]  $($item.Label) " Yellow -NoNewline
            Write-Color "($count file(s))  $($item.Path)" DarkGray
        }
    }

    $envCount = 0
    try {
        $envCount = (Get-ChildItem -Path $ScanRoot -Recurse -Filter ".env" -Depth 6 `
                     -File -ErrorAction SilentlyContinue | Measure-Object).Count
    } catch {}
    if ($envCount -gt 0) {
        Write-Color "  [KEY]  .env files           " Yellow -NoNewline
        Write-Color "($envCount found under $ScanRoot)" DarkGray
    }

    Write-Color ""
    Write-Finding "INFO" "Rotate above credentials immediately if compromised files were found"
    Write-Color ""
    Write-Color "  Rotation links:" DarkGray
    Write-Color "  npm token  : https://www.npmjs.com/settings/tokens" DarkGray
    Write-Color "  GitHub     : https://github.com/settings/tokens" DarkGray
    Write-Color "  Anthropic  : https://console.anthropic.com/settings/keys" DarkGray
    Write-Color "  AWS        : https://console.aws.amazon.com/iam/home#/security_credentials" DarkGray
}

# ============================================================
#  SCAN 9 : PROJECT INVENTORY
# ============================================================
function Invoke-ProjectInventory {
    Write-Section "9. NODE.JS PROJECT INVENTORY"

    $roots    = @($ScanRoot,"C:\dev","C:\projects","C:\code","C:\repos","C:\workspace")
    $projects = [System.Collections.Generic.List[hashtable]]::new()

    foreach ($root in $roots) {
        if (-not (Test-Path $root)) { continue }
        try {
            Get-ChildItem -Path $root -Recurse -Filter "package.json" -Depth 6 `
                -File -ErrorAction SilentlyContinue |
            Where-Object { $_.FullName -notmatch '\\node_modules\\' } |
            ForEach-Object {
                try {
                    $j      = Get-Content $_.FullName -Raw | ConvertFrom-Json -ErrorAction SilentlyContinue
                    $name   = if ($j.name)    { $j.name }    else { Split-Path $_.DirectoryName -Leaf }
                    $ver    = if ($j.version) { $j.version } else { "?" }
                    $axiosV = ""
                    if ($j.dependencies    -and $j.dependencies.axios)    { $axiosV = $j.dependencies.axios }
                    if ($j.devDependencies -and $j.devDependencies.axios)  { $axiosV = $j.devDependencies.axios }
                    $projects.Add(@{ Name=$name; Version=$ver; Path=$_.DirectoryName; AxiosVer=$axiosV })
                } catch {}
            }
        } catch {}
    }

    if ($projects.Count -eq 0) {
        Write-Color "  No Node.js projects found. Use -ScanRoot 'path' to target a folder." DarkGray
        return
    }

    Write-Color ("  " + "Project".PadRight(26) + "Ver".PadRight(9) + "Axios".PadRight(16) + "Path") DarkCyan
    Write-Color ("  " + ("-" * 76)) DarkGray

    $dangerCount = 0
    foreach ($p in $projects | Sort-Object { -not $p.AxiosVer }) {
        $isDanger = $p.AxiosVer -match '1\.14\.1|0\.30\.4|\^1\.14|\^1\b'
        if ($isDanger) { $dangerCount++ }

        $nc = if ($isDanger) { "Red" } elseif ($p.AxiosVer) { "Yellow" } else { "White" }
        $ac = if ($isDanger) { "Red" } elseif ($p.AxiosVer) { "Yellow" } else { "DarkGray" }
        $axD = if ($p.AxiosVer) { $p.AxiosVer } else { "none" }

        $col1 = $p.Name.Substring(0,[Math]::Min(25,$p.Name.Length)).PadRight(26)
        $col2 = $p.Version.Substring(0,[Math]::Min(8,$p.Version.Length)).PadRight(9)
        $col3 = $axD.Substring(0,[Math]::Min(15,$axD.Length)).PadRight(16)
        $col4 = ($p.Path -replace [regex]::Escape($env:USERPROFILE),"~")

        Write-Color "  $col1" $nc  -NoNewline
        Write-Color $col2         White -NoNewline
        Write-Color $col3         $ac   -NoNewline
        Write-Color $col4         DarkGray
    }

    Write-Color ""
    Write-Color "  Total: $($projects.Count)  |  " White -NoNewline
    if ($dangerCount -gt 0) { Write-Color "$dangerCount with dangerous axios version in package.json!" Red }
    else { Write-Color "No dangerous axios versions in package.json" Green }
}

# ============================================================
#  SUMMARY
# ============================================================
function Write-Summary ([System.Collections.Generic.List[string]]$CompromisedFiles) {
    $elapsed   = [Math]::Round(((Get-Date) - $Script:StartTime).TotalSeconds, 1)
    $criticals = @($Script:Findings | Where-Object { $_.Severity -eq "CRITICAL" })
    $warnings  = @($Script:Findings | Where-Object { $_.Severity -eq "WARNING" })

    Write-Color ""
    Write-Color "  ====================================================================" Cyan
    Write-Color "  SCAN COMPLETE  |  Time: ${elapsed}s  |  Files checked: $Script:ScannedCount" Cyan
    Write-Color "  ====================================================================" Cyan
    Write-Color ""

    if ($criticals.Count -gt 0) {
        Write-Color "  +------------------------------------------------------------------+" Red
        Write-Color "  |   !! MACHINE MAY BE COMPROMISED !!                               |" Red
        Write-Color "  |   $($criticals.Count) CRITICAL finding(s). Act NOW.                              |" Red
        Write-Color "  +------------------------------------------------------------------+" Red
        Write-Color ""
        Write-Color "  STEP 1 - Delete node_modules in affected projects:" Yellow
        foreach ($f in $CompromisedFiles) {
            Write-Color "    Remove-Item '$(Split-Path $f)\node_modules' -Recurse -Force" DarkYellow
        }
        Write-Color ""
        Write-Color "  STEP 2 - Pin axios to safe version in affected package.json:" Yellow
        Write-Color '    Set axios to exactly "1.14.0" then run: npm install' DarkYellow
        Write-Color ""
        Write-Color "  STEP 3 - ROTATE ALL CREDENTIALS (RAT ran as your user account):" Yellow
        Write-Color "    - SSH keys       (~\.ssh\id_*)" DarkYellow
        Write-Color "    - AWS creds      (~\.aws\credentials)" DarkYellow
        Write-Color "    - npm token      (~\.npmrc)" DarkYellow
        Write-Color "    - GitHub tokens  (github.com/settings/tokens)" DarkYellow
        Write-Color "    - Anthropic key  (console.anthropic.com/settings/keys)" DarkYellow
        Write-Color "    - .env API keys  (all projects)" DarkYellow
        Write-Color ""
        Write-Color "  STEP 4 - Block C2 in Windows Firewall:" Yellow
        Write-Color "    New-NetFirewallRule -DisplayName 'Block Axios RAT C2' -Direction Outbound -Action Block -RemoteAddress 142.11.206.73" DarkYellow
        Write-Color ""
        Write-Color "  STEP 5 - Check cloud audit logs for unauthorized activity" Yellow
        Write-Color "  STEP 6 - If wt.exe artifact found, consider OS reinstall" Yellow

    } elseif ($warnings.Count -gt 0) {
        Write-Color "  +------------------------------------------------------------------+" Yellow
        Write-Color "  |   WARNINGS found - investigate items above before proceeding      |" Yellow
        Write-Color "  +------------------------------------------------------------------+" Yellow

    } else {
        Write-Color "  +------------------------------------------------------------------+" Green
        Write-Color "  |   MACHINE APPEARS CLEAN                                           |" Green
        Write-Color "  |   No signs of the axios RAT attack detected.                      |" Green
        Write-Color "  +------------------------------------------------------------------+" Green
        Write-Color ""
        Write-Color "  Harden going forward:" Green
        Write-Color "    - npm install --ignore-scripts   (blocks postinstall RATs)" DarkGray
        Write-Color "    - Pin exact versions: no ^ or ~ in package.json" DarkGray
        Write-Color "    - npm audit  after every install" DarkGray
        Write-Color "    - Block C2 IP as a precaution:" DarkGray
        Write-Color "      New-NetFirewallRule -DisplayName 'Block Axios RAT C2' -Direction Outbound -Action Block -RemoteAddress 142.11.206.73" DarkGray
    }

    Write-Color ""
    Write-Color "  ---- References ----------------------------------------------------" DarkGray
    Write-Color "  Elastic  : elastic.co/security-labs/axios-one-rat-to-rule-them-all" DarkGray
    Write-Color "  Wiz      : wiz.io/blog/axios-npm-compromised-in-supply-chain-attack" DarkGray
    Write-Color "  SANS     : sans.org/blog/axios-npm-supply-chain-compromise-..." DarkGray
    Write-Color "  Snyk     : snyk.io/blog/axios-npm-package-compromised-supply-chain" DarkGray
    Write-Color "  Aikido   : aikido.dev/blog/axios-npm-compromised-maintainer-hijacked-rat" DarkGray
    Write-Color "  --------------------------------------------------------------------" DarkGray
    Write-Color ""
}

# ============================================================
#  ENTRY POINT
# ============================================================
Write-Banner

if (-not $Script:IsAdmin) {
    Write-Color "  TIP: Re-run as Administrator for complete registry + firewall scan." DarkYellow
    Write-Color ""
}

Write-Color "  Scan root  : " White -NoNewline; Write-Color $ScanRoot Yellow
if ($FullDriveScan) { Write-Color "  Mode       : FULL DRIVE SCAN (may take minutes)" Yellow }
Write-Color "  Press Ctrl+C to abort at any time." DarkGray
Write-Color ""

# Select categories
$selected = if ($NoMenu) {
    @("1","2","3","4","5","6","7","8","9")
} else {
    Show-Menu
}

Write-Color ""
Write-Color "  Running categories: $($selected -join ', ')" DarkCyan
Write-Color ""

$compromised = [System.Collections.Generic.List[string]]::new()

foreach ($cat in $selected) {
    switch ($cat) {
        "1" { $result = Invoke-LockfileScan;  if ($result) { foreach ($r in $result) { $compromised.Add($r) } } }
        "2" { Invoke-NodeModulesScan }
        "3" { Invoke-PersistenceScan }
        "4" { Invoke-ArtifactScan }
        "5" { Invoke-NetworkScan }
        "6" { Invoke-ProcessScan }
        "7" { Invoke-ClaudeCodeScan }
        "8" { Invoke-CredentialExposureScan }
        "9" { Invoke-ProjectInventory }
    }
}

Write-Summary $compromised
