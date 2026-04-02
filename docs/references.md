# References and Sources

All IoCs, attack mechanics, and remediation steps in this tool are derived
from the following sources. All were published on or after 2026-03-31.

---

## Primary Technical Research

### Elastic Security Labs
**"Inside the Axios supply chain compromise — one RAT to rule them all"**
https://www.elastic.co/security-labs/axios-one-rat-to-rule-them-all

The most comprehensive reverse-engineering report. Covers:
- Full decompilation of all three OS variants
- C2 protocol analysis and the IE8 user-agent fingerprint
- Windows-specific `%PROGRAMDATA%\wt.exe` artifact
- Network-level detection rules (SIEM queries)

---

### Wiz Blog
**"Axios NPM Distribution Compromised in Supply Chain Attack"**
https://www.wiz.io/blog/axios-npm-compromised-in-supply-chain-attack

Covers:
- Cloud credential exfiltration risk
- IAM and secrets rotation procedures
- Cloud audit log review guidance

---

### SANS Internet Storm Center
**"Axios NPM Supply Chain Compromise: Malicious Packages Deliver Remote Access Trojan"**
https://www.sans.org/blog/axios-npm-supply-chain-compromise-malicious-packages-remote-access-trojan

Covers:
- Attack timeline
- Detection methods for blue teams
- SIEM detection logic

---

### Snyk
**"Axios npm Package Compromised: Supply Chain Attack Delivers Cross-Platform RAT"**
https://snyk.io/blog/axios-npm-package-compromised-supply-chain-attack-delivers-cross-platform/

Covers:
- Vulnerability severity scoring
- Automated scanning detection
- Remediation steps for affected packages

---

### Aikido Security (Initial Discovery)
**"axios npm compromised — maintainer account hijacked, RAT deployed"**
https://www.aikido.dev/blog/axios-npm-compromised-maintainer-hijacked-rat

Aikido's automated scanning detected the malicious package within hours of
publication. Covers:
- Initial detection methodology
- First public IoCs
- Timeline of npm's response

---

## Additional Coverage

### The Hacker News
**"Axios Supply Chain Attack Pushes Cross-Platform RAT via Compromised npm Account"**
https://thehackernews.com/2026/03/axios-supply-chain-attack-pushes-cross.html

### StepSecurity
**"axios Compromised on npm — Malicious Versions Drop Remote Access Trojan"**
https://www.stepsecurity.io/blog/axios-compromised-on-npm-malicious-versions-drop-remote-access-trojan

StepSecurity specifically covers hook-based enforcement as a prevention layer
(blocking postinstall execution at the tool level).

### Tenable
**"Supply chain attack on Axios npm package: Scope, impact, and remediations"**
https://www.tenable.com/blog/supply-chain-attack-on-axios-npm-package-scope-impact-and-remediations

Covers enterprise scope assessment and patch management guidance.

### CyberScoop
**"Attack on axios software developer tool threatens widespread compromises"**
https://cyberscoop.com/axios-software-developer-tool-attack-compromise/

### Socket.dev
**"axios npm package compromised"**
https://socket.dev/blog/axios-npm-package-compromised

Socket caught the package via their supply chain security scanning service.

### Malwarebytes
**"Axios supply chain attack chops away at npm trust"**
https://www.malwarebytes.com/blog/news/2026/03/axios-supply-chain-attack-chops-away-at-npm-trust

### Trend Micro
**"Axios NPM Package Compromised: Supply Chain Attack Hits JavaScript HTTP Client with 100M+ Weekly Downloads"**
https://www.trendmicro.com/en_us/research/26/c/axios-npm-package-compromised.html

### iTnews
**"Supply chain attack hits 100 million-download Axios npm package"**
https://www.itnews.com.au/news/supply-chain-attack-hits-100-million-download-axios-npm-package-624699

---

## Community

### r/ClaudeAI — Community Detection Thread
Thread by u/truongnguyenptit warning the AI coding community
https://www.reddit.com/r/ClaudeAI/

Notable for being an early community-level warning specifically targeting
developers who use AI coding assistants, which was the primary at-risk group.

---

## Related — npm Ecosystem Defense

### npm provenance (SLSA)
https://docs.npmjs.com/generating-provenance-statements

The last clean axios release (`1.14.0`) has SLSA provenance attestation.
Pinning to this version and verifying provenance is the recommended safe state.

### GitHub — axios official repository
https://github.com/axios/axios

The axios maintainers published an incident report and remediation guidance
in the repository.
