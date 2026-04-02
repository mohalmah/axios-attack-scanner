# Axios Attack Scanner — Windows Edition

A colorful, interactive PowerShell tool that checks whether your Windows machine
was compromised by the **March 2026 axios npm supply chain attack**
(`axios@1.14.1` / `plain-crypto-js@4.2.1` RAT).

---

## Quick Start

```powershell
# Right-click PowerShell → "Run as Administrator", then:
cd C:\dev\axios-attack-scanner
powershell -ExecutionPolicy Bypass -File .\Scan-AxiosAttack.ps1 -ScanRoot "C:\dev"
```

Select categories from the interactive menu, or press **A** to run everything.

---

## Requirements

| Requirement | Detail |
|---|---|
| PowerShell | 5.1 or later (built into Windows 10/11) |
| Privileges | Standard user for most checks; **Administrator** for registry, firewall, and scheduled task scans |
| OS | Windows 10 / 11 |

---

## Parameters

| Parameter | Type | Default | Description |
|---|---|---|---|
| `-ScanRoot` | `string` | `%USERPROFILE%` | Root directory for lockfile and project scans |
| `-FullDriveScan` | switch | off | Scan all mounted drives (slow — use for thorough investigation) |
| `-SkipProgress` | switch | off | Suppress the live status line (useful for CI / log capture) |
| `-NoMenu` | switch | off | Skip the category menu and run all 9 checks automatically |

### Examples

```powershell
# Scan just your dev folder (fastest)
.\Scan-AxiosAttack.ps1 -ScanRoot "C:\dev"

# Silent full run — all categories, no menu, no progress bar
.\Scan-AxiosAttack.ps1 -ScanRoot "C:\dev" -NoMenu -SkipProgress

# Full drive sweep (thorough — may take 5-15 minutes)
.\Scan-AxiosAttack.ps1 -FullDriveScan
```

---

## Scan Categories

The interactive menu lets you run all nine checks or pick individual ones.

### [1] Lockfile Scan

**What it does:** Walks your directory tree using a live BFS queue and checks
every `package-lock.json`, `yarn.lock`, and `pnpm-lock.yaml` file for the
malicious strings.

**Checks for:**
- `axios@1.14.1` — first malicious version (published 2026-03-31 ~00:21 UTC)
- `axios@0.30.4` — second malicious version (published during same 39-min window)
- `plain-crypto-js` — the phantom RAT-dropper dependency injected by both versions

**Why this matters:** The attack modified axios to declare `plain-crypto-js@4.2.1`
as a dependency. When you ran `npm install`, npm also installed this package and
its `postinstall` hook silently downloaded and executed a platform-specific RAT.
The lockfile is the ground truth — if these strings appear there, the malicious
package was present in your install.

**Shows live:** Current directory, directories walked, lockfiles found, files scanned.

---

### [2] node_modules Check

**What it does:** Walks node_modules directories looking for a folder literally
named `plain-crypto-js`.

**Why this matters:** Even if you've since re-run `npm install` with a clean
version of axios, the old `node_modules` folder might still contain the physical
RAT dropper directory. Finding it here means the malicious `postinstall` hook
ran on your machine.

---

### [3] Windows Persistence

**What it does:** Checks three common Windows persistence mechanisms for
suspicious entries.

| Mechanism | Registry path / location |
|---|---|
| Run keys | `HKCU\...\CurrentVersion\Run` and `RunOnce` |
| Run keys (system) | `HKLM\...\CurrentVersion\Run` and `WOW6432Node\...` |
| Scheduled Tasks | All enabled tasks — flags node.exe in TEMP/AppData paths |
| Startup folder | `%APPDATA%\...\Startup` and `C:\ProgramData\...\StartUp` |

**Flags if:** Any entry references known IoC strings (`sfrclak`, `plain-crypto`,
`wt.exe`, etc.) or runs `node.exe` from a temp/AppData location.

---

### [4] RAT Artifact Files

**What it does:** Checks the specific file locations the Windows RAT variant
is known to create, based on Elastic Security Labs and Wiz reverse engineering.

**Primary Windows IoC:**

```
%PROGRAMDATA%\wt.exe
```

The RAT copies a hidden VBScript interpreter (`wscript.exe`) to this path and
uses it to execute its persistence payload. Legitimate Windows Terminal
(`wt.exe`) lives in `%LOCALAPPDATA%\Microsoft\WindowsApps\` — never in
`%PROGRAMDATA%` root.

**Secondary locations checked:**
- `%TEMP%\plain-crypto*`
- `%TMP%\plain-crypto*`
- `%LOCALAPPDATA%\Temp\plain-crypto*`
- `%APPDATA%\plain-crypto*`
- `%PROGRAMDATA%\plain-crypto*`
- `%PROGRAMDATA%\*.vbs` (created in last 30 days)
- `%TEMP%\*.js` with obfuscated content (created in last 7 days)

---

### [5] Network / C2 Connections

**What it does:** Checks for active or historical network communication with
the attacker's command-and-control infrastructure.

**Known C2 infrastructure (Elastic / Wiz research):**

| Indicator | Value |
|---|---|
| C2 domain | `sfrclak.com` |
| C2 IP address | `142.11.206.73` |
| C2 port | `8000` |
| Windows beacon endpoint | `POST packages.npm.org/product1` |
| User-agent fingerprint | IE8/Windows XP string (hardcoded in all RAT variants) |

**Checks performed:**
1. **Live TCP connections** — active `ESTABLISHED` or `TIME_WAIT` connections
   to the C2 IP or port 8000
2. **DNS cache** — `Get-DnsClientCache` for `sfrclak.com` or the C2 IP
   (a cache hit means your machine resolved the domain even if the connection
   is no longer active)
3. **Hosts file tampering** — checks `%SystemRoot%\System32\drivers\etc\hosts`
   for injected entries
4. **Windows Firewall rules** — outbound `Allow` rules for suspicious process names

**Recommended hardening (run regardless of scan result):**

```powershell
New-NetFirewallRule -DisplayName "Block Axios RAT C2" `
    -Direction Outbound -Action Block -RemoteAddress 142.11.206.73
```

---

### [6] Process Scan

**What it does:** Inspects all running `node.exe` processes and any `wt.exe`
process not launched from Windows Terminal's expected path.

**Flags if:**
- A `node.exe` process has `temp`, `tmp`, `appdata`, `plain-crypto`, or
  `sfrclak` in its command line
- `wt.exe` is running from any path other than `\WindowsApps\`

---

### [7] Claude Code

**What it does:** Checks whether Claude Code itself was compromised and whether
the RAT tampered with your Claude Code configuration.

**Background:** Claude Code is distributed as an npm package. If you ran
`npm install -g @anthropic-ai/claude-code` (or an update) between
**2026-03-31 00:21 UTC and 03:29 UTC**, Claude Code's own install may have
pulled in the malicious axios version.

Additionally, Anthropic's Claude Code source leak (reported by VentureBeat)
revealed the exact hook and MCP orchestration logic. Attackers aware of this
could craft malicious repos that inject commands via `~/.claude/settings.json`
hooks before you see a trust prompt.

**Checks performed:**

| Check | Details |
|---|---|
| CC global install lockfile | Scans `%APPDATA%\npm\node_modules\@anthropic-ai\claude-code\package-lock.json` for malicious axios |
| CC node_modules | Checks if `plain-crypto-js` is physically installed inside Claude Code's own `node_modules` |
| `~/.claude/settings.json` hooks | Parses hooks config; flags any hook referencing C2 patterns or temp/node paths |
| Unusual files in `~/.claude` | Flags `.js`, `.ts`, `.exe`, `.vbs`, `.bat` files written in the last 7 days |
| `ANTHROPIC_API_KEY` env var | Flags if set (means it was readable to any process running as your user) |

**If your Anthropic API key was exposed:** Rotate it at
`https://console.anthropic.com/settings/keys`

---

### [8] Credential Inventory

**What it does:** Inventories all credential files on the machine that the RAT
could have exfiltrated. The RAT runs as your user account — it has read access
to everything you can read.

| Credential | Location |
|---|---|
| SSH private keys | `~\.ssh\id_*`, `*.pem`, `*.key` |
| AWS credentials | `~\.aws\credentials`, `~\.aws\config` |
| Google Cloud | `%APPDATA%\gcloud\*.json` |
| npm auth token | `~\.npmrc` |
| Git identity | `~\.gitconfig` |
| GitHub CLI token | `~\.config\gh\hosts.yml` |
| .env files | All `.env` files under `ScanRoot` (up to depth 6) |

**Action:** If any lockfile compromise was confirmed, rotate **all** of the above
immediately. Do not wait — the RAT had a ~3-hour live window.

---

### [9] Project Inventory

**What it does:** Finds every `package.json` under `ScanRoot` and the common
project directories, extracts the project name, version, and declared axios
version, and displays them in a color-coded table.

**Color coding:**

| Color | Meaning |
|---|---|
| Red | Axios version matches `1.14.1`, `0.30.4`, or a range (`^1.14`, `^1`) that would resolve to the malicious version |
| Yellow | Axios is a dependency but version is not in the dangerous range |
| White / Gray | No axios dependency |

---

## Severity Levels

| Level | Color | Meaning |
|---|---|---|
| `[CRITICAL]` | Red | Confirmed IoC — immediate action required |
| `[WARNING]` | Yellow | Suspicious finding — investigate before proceeding |
| `[INFO]` | Cyan | Informational — no action required but worth knowing |
| `[SAFE]` | Green | Check passed — nothing found |

---

## What To Do If Compromised

### Step 1 — Contain

```powershell
# Block the C2 server immediately
New-NetFirewallRule -DisplayName "Block Axios RAT C2" `
    -Direction Outbound -Action Block -RemoteAddress 142.11.206.73

# Remove the malicious package from affected projects
Remove-Item "C:\path\to\project\node_modules" -Recurse -Force
```

### Step 2 — Clean

Edit `package.json` to pin axios to the last safe version:
```json
"axios": "1.14.0"
```
Then reinstall with postinstall hooks blocked:
```powershell
npm install --ignore-scripts
```

### Step 3 — Rotate All Credentials

The RAT ran as your Windows user account. Treat every secret it could read as
compromised. Rotate in this order (highest risk first):

1. **npm token** — `https://www.npmjs.com/settings/tokens`
2. **GitHub / GitLab tokens** — `https://github.com/settings/tokens`
3. **Anthropic API key** — `https://console.anthropic.com/settings/keys`
4. **AWS keys** — `https://console.aws.amazon.com/iam/home#/security_credentials`
5. **SSH keys** — generate new keys and update all remote authorized_keys
6. **All `.env` secrets** — every API key, database URL, webhook secret in every project

### Step 4 — Audit Cloud Accounts

Before rotating removes access, check audit logs for unauthorized actions:
- AWS CloudTrail — look for IAM changes, S3 access, new users
- GitHub — Settings → Security log
- GCP — Cloud Audit Logs

### Step 5 — Check for Deeper Persistence

```powershell
# Check for wt.exe artifact (primary Windows IoC)
Test-Path "$env:PROGRAMDATA\wt.exe"

# List all scheduled tasks created/modified recently
Get-ScheduledTask | Where-Object { $_.Date -gt (Get-Date).AddDays(-7) }

# Check startup entries
Get-Item "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
```

If `%PROGRAMDATA%\wt.exe` exists, or if you find unauthorized scheduled tasks
or startup entries, consider a full OS reinstall — the RAT may have established
deeper persistence.

---

## Hardening (Prevent Future Attacks)

### 1. Always use `--ignore-scripts`

```powershell
npm install --ignore-scripts
```

This is the single most effective defense. It prevents `postinstall` hooks from
running entirely. The axios RAT **would not have executed** if this flag was set.

### 2. Pin exact versions — no ranges

```json
{
  "dependencies": {
    "axios": "1.14.0"
  }
}
```

Never use `^` or `~`. Ranges silently upgrade to the latest matching version,
which is exactly how this attack succeeded.

### 3. Audit after every install

```powershell
npm audit
```

### 4. Review lockfile diffs before committing

The lockfile diff would have shown `plain-crypto-js` appearing as a new
transitive dependency — a clear red flag.

### 5. For Claude Code users — add a hook

Add this to `~/.claude/settings.json` to force `--ignore-scripts` on every
npm install Claude Code runs:

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": [
          {
            "type": "command",
            "command": "node -e \"const i=JSON.parse(require('fs').readFileSync('/dev/stdin','utf8'));if(i.tool_input&&i.tool_input.command&&/npm\\s+install/.test(i.tool_input.command)&&!/--ignore-scripts/.test(i.tool_input.command)){process.exit(2);}process.exit(0);\""
          }
        ]
      }
    ]
  }
}
```

---

## Attack Timeline

| Time (UTC) | Event |
|---|---|
| 2026-03-31 ~00:21 | Attacker publishes `axios@1.14.1` from compromised maintainer account |
| 2026-03-31 ~00:30 | Attacker publishes `axios@0.30.4` (second malicious version) |
| 2026-03-31 ~03:00 | Aikido Security detects the compromise via automated scanning |
| 2026-03-31 ~03:29 | Both malicious versions removed from npm registry |
| 2026-03-31 (day) | Elastic, Wiz, SANS, Snyk publish detailed analysis |

Attack window: approximately **3 hours and 8 minutes**.

---

## References

| Source | Link |
|---|---|
| Elastic Security Labs (full reverse engineering) | https://www.elastic.co/security-labs/axios-one-rat-to-rule-them-all |
| Wiz Blog (supply chain analysis) | https://www.wiz.io/blog/axios-npm-compromised-in-supply-chain-attack |
| SANS Internet Storm Center | https://www.sans.org/blog/axios-npm-supply-chain-compromise-malicious-packages-remote-access-trojan |
| Snyk vulnerability report | https://snyk.io/blog/axios-npm-package-compromised-supply-chain-attack-delivers-cross-platform/ |
| Aikido Security (initial discovery) | https://www.aikido.dev/blog/axios-npm-compromised-maintainer-hijacked-rat |
| The Hacker News | https://thehackernews.com/2026/03/axios-supply-chain-attack-pushes-cross.html |
| StepSecurity analysis | https://www.stepsecurity.io/blog/axios-compromised-on-npm-malicious-versions-drop-remote-access-trojan |
| Tenable (scope and impact) | https://www.tenable.com/blog/supply-chain-attack-on-axios-npm-package-scope-impact-and-remediations |
| CyberScoop | https://cyberscoop.com/axios-software-developer-tool-attack-compromise/ |
| Socket.dev | https://socket.dev/blog/axios-npm-package-compromised |
| r/ClaudeAI community thread | https://www.reddit.com/r/ClaudeAI/ |

---

## Indicators of Compromise (IoC) Summary

### Files

| Path | Significance |
|---|---|
| `%PROGRAMDATA%\wt.exe` | RAT copies hidden VBScript interpreter here |
| Any `node_modules\plain-crypto-js\` directory | RAT dropper physically present |
| `%TEMP%\ld*` | Linux/cross-platform RAT staging file |

### Network

| Indicator | Type | Value |
|---|---|---|
| C2 IP | IPv4 | `142.11.206.73` |
| C2 domain | DNS | `sfrclak.com` |
| C2 port | TCP | `8000` |
| Beacon path | HTTP POST | `/product1` (Windows), `/product2` (Linux), `/product3` (macOS) |
| User-agent | HTTP header | IE8/Windows XP string (hardcoded across all three OS variants) |

### npm Packages

| Package | Version | Status |
|---|---|---|
| `axios` | `1.14.1` | MALICIOUS — remove immediately |
| `axios` | `0.30.4` | MALICIOUS — remove immediately |
| `plain-crypto-js` | `4.2.1` | MALICIOUS RAT dropper — never install |
| `axios` | `1.14.0` | SAFE (last clean 1.x release with SLSA provenance) |
| `axios` | `0.30.3` | SAFE (last clean 0.30.x release) |
