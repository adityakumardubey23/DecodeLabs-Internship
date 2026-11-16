# System Vulnerability Checklist

A small, defensive, read-only system-auditing project inspired by **Project 4: System Vulnerability Checklist** in the supplied training slides.

It helps a student or junior security analyst establish a baseline, inspect common endpoint controls, record manual checks, prioritize findings, and produce a Markdown/JSON report.

> **Scope and safety:** Run this only on a computer you own or are explicitly authorized to assess. The automated checks are intended to read configuration/status information only. The tool does not exploit vulnerabilities, change settings, install software, disable controls, collect passwords, or upload data. Some checks are platform-dependent and may return `UNKNOWN` when the operating system does not expose reliable information.

## Features

- Detects operating system and basic host information.
- Checks firewall status where a supported native command is available.
- Checks disk-encryption status where a supported native command is available.
- Inspects local administrator-group membership on supported systems.
- Checks for pending operating-system updates using native package/update tools.
- Provides manual checklist items for password/passphrase quality, phishing-resistant MFA, guest access, physical security, least privilege, and unapproved software.
- Produces timestamped Markdown and JSON reports locally.
- Supports a manual findings file so observations and remediation can be documented.

## Requirements

- Python 3.10 or newer
- Windows 10/11, macOS, or a Linux distribution
- No third-party Python packages are required

## Quick start

### 1. Open a terminal in this project directory

```bash
python --version
```

### 2. Install the local project and run the audit

```bash
python -m pip install -e .
sysaudit audit
```

To write reports to a chosen directory:

```bash
sysaudit audit --output reports
```

On Windows, if the `sysaudit` command is not on PATH immediately after installation, use:

```powershell
py -m pip install -e .
py -m sysaudit.cli audit --output reports
```

On macOS/Linux:

```bash
python3 -m pip install -e .
python3 -m sysaudit.cli audit --output reports
```

## Commands

| Command | Purpose |
|---|---|
| `sysaudit audit` | Run supported read-only checks and create Markdown + JSON reports |
| `sysaudit checklist` | Print the manual review checklist |
| `sysaudit audit --output reports` | Choose report output directory |

## What is checked

| Area | Automated evidence | Limitations |
|---|---|---|
| Firewall | Native firewall status query | A third-party endpoint agent may manage network controls separately |
| Disk encryption | BitLocker, FileVault, or Linux block-device indicators | Linux layouts vary; validate full-disk coverage manually |
| Administrator rights | Local Administrators / admin / sudo / wheel group membership | Directory-managed identities may not be fully represented |
| OS updates | Native update/package-manager query | Availability and output vary by OS and package manager |
| Passwords and MFA | Manual review | The tool never requests or reads credentials; verify passkeys/security keys and account settings yourself |
| Guest access and shadow IT | Manual review | Requires an authorized review of accounts and installed applications |
| Physical/behavioral hygiene | Manual review | Verify screen lock, removable media, backups, and social-engineering procedures |

## Understanding results

- `PASS`: the check found the expected protective state.
- `WARN`: the check found a potentially weak or incomplete state that needs review.
- `INFO`: informational evidence; not automatically a vulnerability.
- `UNKNOWN`: the check could not reliably determine the state. Do not interpret this as secure.

The tool intentionally avoids claiming that a system is fully secure. A clean automated report is not a penetration test, compliance certification, or guarantee against compromise.

## Manual checklist

1. **Identity:** Use long, unique passphrases; use a password manager; enable phishing-resistant MFA (FIDO2/WebAuthn security key or passkey) where supported; remove stale accounts.
2. **Patch management:** Enable automatic security updates; update browsers and applications; remove unsupported software; document exceptions.
3. **Human perimeter:** Disable unused guest accounts; review administrator membership; lock the screen when away; restrict removable storage; verify requests through a second trusted channel.
4. **Network and endpoint:** Confirm firewall profiles are enabled; enable full-disk encryption; maintain backups; verify endpoint protection is active.
5. **Shadow IT:** Review installed applications and browser extensions against organizational policy; do not uninstall anything without authorization.

## Record manual findings

Copy `docs/report-template.md` and record at least three specific observations from your own authorized audit. For each finding include evidence, impact, risk level, remediation, and a verification result after remediation. Do not include passwords, recovery codes, personal files, or other secrets in the report.

## Project structure

```text
system-vulnerability-checklist/
├── README.md
├── pyproject.toml
├── requirements.txt
├── .gitignore
├── src/
│   └── sysaudit/
│       ├── __init__.py
│       ├── checks.py
│       ├── cli.py
│       ├── models.py
│       └── reporting.py
├── docs/
│   └── report-template.md
└── tests/
    └── test_models.py
```

## Testing

```bash
python -m unittest discover -s tests -v
```

## Limitations and responsible use

- Run with normal user privileges first. Elevated privileges are not required for most checks and should only be used when your organization authorizes them.
- Some commands may be absent or restricted. The tool reports `UNKNOWN` rather than guessing.
- The output may contain a hostname and local account names. Store and share reports according to your organization's privacy policy.
- Review every proposed remediation with the system owner before changing configuration.

## Learning references

The supplied training material mentions NIST SP 800-63B, CIS Controls, CVSS, ISO 27001, and SOC 2. This project is an educational checklist, not an official implementation or certification of those frameworks. Consult the current official publications and your organization's policies for authoritative requirements.
