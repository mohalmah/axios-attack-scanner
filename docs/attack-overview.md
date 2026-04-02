# Attack Overview — axios npm Supply Chain Compromise (March 2026)

## What Happened

On March 31, 2026, an attacker gained control of the npm publishing credentials
belonging to `jasonsaayman`, one of the primary maintainers of the `axios` package.

axios is one of the most depended-upon packages in the JavaScript ecosystem with
approximately **100 million weekly downloads**. The attacker used this privileged
access to publish two backdoored versions within a 39-minute window:

| Version | Published | Removed |
|---|---|---|
| `axios@1.14.1` | ~00:21 UTC | ~03:29 UTC |
| `axios@0.30.4` | ~00:30 UTC | ~03:29 UTC |

Total exposure window: approximately **3 hours 8 minutes**.

---

## Attack Mechanics

### Stage 1 — Dependency Injection

The malicious versions introduced a single new dependency not present in any
legitimate axios release:

```
plain-crypto-js@4.2.1
```

This is a purpose-built malicious package with no legitimate function. Its sole
job is executing a `postinstall` hook.

### Stage 2 — Postinstall Hook Execution

When any developer ran `npm install` in a project that resolved to axios@1.14.1
or axios@0.30.4, npm automatically installed `plain-crypto-js@4.2.1` as a
transitive dependency and executed its `postinstall` hook.

The hook:
1. Detected the operating system (Windows / macOS / Linux)
2. Downloaded a platform-specific stage-2 RAT binary from `sfrclak.com:8000`
3. Executed the binary silently
4. Replaced its own source files with clean decoys to erase evidence

### Stage 3 — RAT Execution

The downloaded payload is a cross-platform Remote Access Trojan with three
OS-specific variants. All three variants share an identical C2 protocol and
a hardcoded IE8/Windows XP `User-Agent` string, which is the most reliable
network-level detection fingerprint.

### Windows-Specific Behavior

On Windows, the RAT:
- Copies a VBScript interpreter (`wscript.exe`) to `%PROGRAMDATA%\wt.exe`
- Executes a hidden VBScript payload via the renamed interpreter
- Establishes persistence via registry Run keys or scheduled tasks
- Beacons home via HTTP POST to `sfrclak.com:8000/product1`
- Exfiltrates environment variables, SSH keys, cloud credentials, and `.env` files

---

## Why Developers Were Especially Vulnerable

### npm's Transitive Dependency Model

Most developers explicitly depend on `axios`, not `plain-crypto-js`. However,
npm's default behavior installs all transitive dependencies and runs their
`postinstall` hooks automatically. Developers never saw `plain-crypto-js` in
their `package.json` — it appeared only in the lockfile.

### "Vibe Coding" with AI Tools

AI coding assistants (including Claude Code) routinely scaffold projects and
run `npm install` without version constraints. Because the malicious version was
live in the npm registry for over three hours, any project scaffolded or
dependency updated during that window could have installed it.

### Version Range Resolution

Many `package.json` files declare axios with a caret range such as `"^1.7.0"`,
meaning "any compatible version". npm's resolver would silently upgrade this to
`1.14.1` as the latest matching release during the attack window.

---

## Safe Versions

| Range | Safe Version |
|---|---|
| `1.x` | `1.14.0` (last clean release, has SLSA provenance) |
| `0.30.x` | `0.30.3` (last clean release) |

---

## Source: Elastic Security Labs

Elastic Security Labs performed the most detailed reverse engineering of the
attack. Key findings from their report:

> "The toolkit's most reliable detection indicator is also its most curious
> design choice: the IE8/Windows XP user-agent string hardcoded identically
> across all three platform variants, which provides a consistent protocol
> fingerprint for C2 server-side routing but is trivially detectable on any
> modern network."

Full report: https://www.elastic.co/security-labs/axios-one-rat-to-rule-them-all
