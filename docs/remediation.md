# Remediation Guide

Use this guide if the scanner found any CRITICAL results.

---

## Immediate Triage (First 15 Minutes)

### 1. Block the C2 server

Do this first — before anything else. This cuts off any active RAT connection.

```powershell
New-NetFirewallRule `
    -DisplayName "Block Axios RAT C2" `
    -Direction Outbound `
    -Action Block `
    -RemoteAddress 142.11.206.73 `
    -Protocol TCP
```

### 2. Identify affected projects

```powershell
# Find all compromised lockfiles on your machine
Select-String -Path "C:\**\package-lock.json","C:\**\yarn.lock" `
    -Pattern "axios@1\.14\.1|axios@0\.30\.4|plain-crypto-js" -Recurse |
    Select-Object -ExpandProperty Path
```

### 3. Kill any suspicious node processes

```powershell
Get-Process -Name "node" | ForEach-Object {
    $wmi = Get-WmiObject Win32_Process -Filter "ProcessId=$($_.Id)"
    if ($wmi.CommandLine -match 'temp|tmp|plain-crypto|sfrclak') {
        Write-Host "Killing suspicious PID $($_.Id): $($wmi.CommandLine)" -ForegroundColor Red
        Stop-Process -Id $_.Id -Force
    }
}
```

---

## Clean Up Affected Projects

### Remove the malicious packages

```powershell
# For each affected project directory:
$projectDir = "C:\path\to\your\project"
Remove-Item "$projectDir\node_modules" -Recurse -Force
Remove-Item "$projectDir\package-lock.json" -Force  # optional — will be regenerated
```

### Pin axios to a safe version

Edit `package.json`:

```json
{
  "dependencies": {
    "axios": "1.14.0"
  }
}
```

Use an exact version — no `^` or `~`.

### Reinstall with postinstall hooks disabled

```powershell
cd C:\path\to\your\project
npm install --ignore-scripts
```

This prevents any postinstall hooks from executing — including any from
packages that may still be in your registry cache.

### Verify the reinstall is clean

```powershell
npm audit
npm ls axios                # should show 1.14.0 only
```

---

## Remove Persistence Artifacts

### Check and remove wt.exe (primary Windows IoC)

```powershell
$wtPath = "$env:PROGRAMDATA\wt.exe"
if (Test-Path $wtPath) {
    Write-Host "FOUND: $wtPath" -ForegroundColor Red
    # Remove it
    Remove-Item $wtPath -Force
}
```

### Remove suspicious scheduled tasks

```powershell
# List recently created tasks
Get-ScheduledTask | Where-Object {
    $_.Date -gt (Get-Date).AddDays(-30) -and
    $_.TaskPath -notlike '\Microsoft\*'
} | Select-Object TaskName, TaskPath, Date | Format-Table

# Remove a specific task (replace TaskName)
Unregister-ScheduledTask -TaskName "SuspiciousTaskName" -Confirm:$false
```

### Remove suspicious Run key entries

```powershell
# List current user Run entries
Get-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"

# Remove a specific entry (replace ValueName)
Remove-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" `
    -Name "SuspiciousValueName"
```

---

## Rotate All Credentials

The RAT runs as your Windows user account. It can read any file your user
can access. Rotate in this priority order:

### 1. npm token
1. Go to https://www.npmjs.com/settings/tokens
2. Delete all existing tokens
3. Create a new Automation token for CI and a new Publish token for releases

### 2. GitHub / GitLab tokens
- GitHub: https://github.com/settings/tokens — revoke all, regenerate
- GitLab: Profile → Access Tokens → revoke all

### 3. Anthropic API key (Claude Code users)
1. Go to https://console.anthropic.com/settings/keys
2. Revoke the exposed key
3. Generate a new key
4. Update `ANTHROPIC_API_KEY` wherever it is set

### 4. AWS credentials
1. Go to https://console.aws.amazon.com/iam/home#/security_credentials
2. Deactivate then delete the exposed access key
3. Create a new access key
4. Update `~/.aws/credentials`

### 5. SSH keys
```powershell
# Generate new key pair
ssh-keygen -t ed25519 -C "your_email@example.com" -f "$env:USERPROFILE\.ssh\id_ed25519_new"

# Update authorized_keys on each remote server
# Then remove old key from ~/.ssh/authorized_keys on servers
```

### 6. .env files
Search for every `.env` file and rotate each secret:
```powershell
Get-ChildItem -Path C:\dev -Recurse -Filter ".env" -Depth 6 |
    Select-Object -ExpandProperty FullName
```

---

## Audit Cloud Accounts

Before finishing, check whether credentials were used maliciously during
the attack window (2026-03-31 00:21 – 03:29 UTC).

### AWS CloudTrail
1. AWS Console → CloudTrail → Event History
2. Filter by: Time range covering 2026-03-31 00:00 – 06:00 UTC
3. Look for: IAM user/key creation, S3 GetObject on sensitive buckets,
   Lambda/ECS deployments, new security group rules

### GitHub Security Log
1. github.com → Settings → Security → Audit log
2. Look for: New SSH keys added, OAuth apps authorized, forks of private repos,
   new deploy keys

### Google Cloud
1. Cloud Console → IAM & Admin → Audit Logs
2. Look for: Service account key creation, new IAM bindings, unusual API calls

---

## Decision: Clean vs. Reinstall OS

**Clean and rotate is sufficient if ALL of the following are true:**
- `%PROGRAMDATA%\wt.exe` does NOT exist
- No suspicious scheduled tasks or Run keys found
- DNS cache has no record of `sfrclak.com`
- No active network connections to `142.11.206.73`
- All credentials have been rotated
- Cloud audit logs show no unauthorized activity

**Consider full OS reinstall if ANY of the following are true:**
- `%PROGRAMDATA%\wt.exe` was found
- Suspicious scheduled tasks were found that you did not create
- DNS cache shows `sfrclak.com` was resolved (machine called home)
- Cloud audit logs show unauthorized activity
- You cannot account for all persistence mechanisms found

---

## Hardening — Prevent the Next Attack

```powershell
# Always use --ignore-scripts (blocks postinstall hooks)
npm install --ignore-scripts

# Pin exact versions in package.json
npm install axios@1.14.0 --save-exact

# Audit regularly
npm audit

# Block known C2 (defense in depth)
New-NetFirewallRule -DisplayName "Block Axios RAT C2" `
    -Direction Outbound -Action Block -RemoteAddress 142.11.206.73
```
