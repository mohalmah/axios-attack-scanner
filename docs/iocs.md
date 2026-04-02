# Indicators of Compromise (IoCs)

All IoCs sourced from Elastic Security Labs, Wiz, SANS, and Snyk research
published on or after 2026-03-31.

---

## Malicious npm Packages

| Package | Version | Action |
|---|---|---|
| `axios` | `1.14.1` | Remove, downgrade to `1.14.0` |
| `axios` | `0.30.4` | Remove, downgrade to `0.30.3` |
| `plain-crypto-js` | `4.2.1` | Remove immediately — RAT dropper |

---

## File System — Windows

| Path | Significance | Confidence |
|---|---|---|
| `%PROGRAMDATA%\wt.exe` | RAT copies VBScript interpreter here (legitimate wt.exe is never in this directory) | HIGH |
| `node_modules\plain-crypto-js\` | RAT dropper physically installed | HIGH |
| `%TEMP%\plain-crypto*` | Staging artifacts | MEDIUM |
| `%TMP%\plain-crypto*` | Staging artifacts | MEDIUM |
| `%APPDATA%\plain-crypto*` | Persistence artifacts | MEDIUM |
| `%PROGRAMDATA%\plain-crypto*` | Persistence artifacts | MEDIUM |
| `%PROGRAMDATA%\*.vbs` (recent) | Hidden VBScript payloads | MEDIUM |
| `%TEMP%\*.js` with eval/exec (recent) | Obfuscated staging scripts | LOW–MEDIUM |

## File System — macOS

| Path | Significance |
|---|---|
| `/Library/Caches/com.apple.act.mond` | macOS RAT artifact (NOT Windows) |

## File System — Linux

| Path | Significance |
|---|---|
| `/tmp/ld*` | Linux RAT staging files (NOT Windows) |

---

## Network

| Type | Indicator | Notes |
|---|---|---|
| IPv4 | `142.11.206.73` | Primary C2 server |
| Domain | `sfrclak.com` | C2 domain |
| TCP Port | `8000` | C2 listener port |
| HTTP path (Windows) | `POST /product1` | Windows RAT beacon |
| HTTP path (Linux) | `POST /product2` | Linux RAT beacon |
| HTTP path (macOS) | `POST /product3` | macOS RAT beacon |
| User-Agent | `Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.1)` | Hardcoded in all variants — trivially detectable |

---

## Registry — Windows

Suspicious patterns to search for in Run/RunOnce keys:

- Any value referencing `wt.exe` outside of `\WindowsApps\`
- `node.exe` running from `%TEMP%`, `%TMP%`, `%APPDATA%`, or `%PROGRAMDATA%`
- Values containing `sfrclak`, `plain-crypto`, `exfil`

---

## Process Behavior

| Process | Suspicious If |
|---|---|
| `node.exe` | Command line contains `temp`, `tmp`, `sfrclak`, `plain-crypto`, `exfil` |
| `wt.exe` | Running from any path other than `\WindowsApps\` |
| `wscript.exe` | Running with arguments pointing to `%PROGRAMDATA%` or `%TEMP%` |

---

## Lockfile Patterns (grep/Select-String)

```powershell
# PowerShell — search all lockfiles from current directory
Select-String -Path ".\**\package-lock.json",".\**\yarn.lock",".\**\pnpm-lock.yaml" `
    -Pattern "axios@1\.14\.1|axios@0\.30\.4|plain-crypto-js" -Recurse

# Bash / Git Bash
grep -rH --include="package-lock.json" -E "axios@1\.14\.1|axios@0\.30\.4|plain-crypto-js" .
```

---

## Network Detection (SIEM / Firewall)

```
dst_ip = 142.11.206.73
OR dst_domain CONTAINS "sfrclak.com"
OR (http.user_agent CONTAINS "MSIE 8.0" AND http.user_agent CONTAINS "Windows NT 5.1" AND dst_port = 8000)
OR (http.method = "POST" AND http.uri IN ["/product1", "/product2", "/product3"] AND dst_port = 8000)
```

---

## Block C2 (Windows Firewall)

```powershell
New-NetFirewallRule `
    -DisplayName "Block Axios RAT C2 - sfrclak.com" `
    -Direction Outbound `
    -Action Block `
    -RemoteAddress 142.11.206.73 `
    -Protocol TCP
```
