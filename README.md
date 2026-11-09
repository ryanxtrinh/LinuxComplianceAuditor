# Linux Security Compliance Auditor

A Java command-line tool that checks a Linux system against **63 security controls based on CIS Benchmarks**, maps each one to **NIST CSF 2.0** and **ISO/IEC 27001:2022**, and writes an audit report with a risk-weighted compliance score.

It is **read-only**: it never changes anything on the system. Pure Java 17+, no external libraries.

## What it checks

| Category | Controls | Examples |
|---|---|---|
| SSH Server | 12 | Root login disabled, key-only auth, MaxAuthTries, idle timeout, host key permissions |
| Password Policy | 6 | Password aging, minimum length (pwquality), strong hashing, account lockout (faillock) |
| Accounts & Privileges | 8 | Only root has UID 0, no empty passwords, service accounts can't log in, no `NOPASSWD` sudo |
| File Permissions | 8 | `/etc/shadow`, `/etc/passwd`, GRUB config, world-writable files in `/etc` |
| Network & Kernel | 13 | Firewall active, ICMP redirects, SYN cookies, ASLR, kernel pointer hiding |
| Services & Software | 8 | No telnet/FTP/rsh, automatic security updates, pending patches, AppArmor/SELinux |
| Logging & Monitoring | 5 | auditd, syslog/journald, persistent logs, time sync |
| Filesystem | 3 | `/tmp` and `/dev/shm` mounted `nodev,nosuid,noexec` |

Run `java -jar auditor.jar --list` to see every control and its framework mapping.

## Build and run

```bash
./build.sh                          # needs JDK 17+  (or: mvn package)
sudo java -jar auditor.jar          # full audit of this machine
```

Output goes to `audit-output/`:
- `report.html`: the audit report (open in a browser; Ctrl+P saves it as a PDF)
- `findings.csv`: every control with its result and evidence (opens in Excel)

Without `sudo`, controls that need root (e.g. reading `/etc/shadow`) are marked **ERROR / not evaluated**.

## Before/after remediation workflow

```bash
sudo java -jar auditor.jar --out before        # 1. baseline audit
cp before/findings.csv baseline.csv
# 2. fix findings using the Recommendation in each one
sudo java -jar auditor.jar --out after --compare baseline.csv   # 3. re-audit
```

The report gets a **Before vs. After** section listing the score change, every control you remediated, and anything that regressed.

Tip: run this on a VM or test machine and take a snapshot first. A few fixes (disabling SSH password login, firewall rules) can lock you out if you do them in the wrong order.

## Options

```
--out <dir>         Output folder (default: audit-output)
--compare <csv>     Earlier findings.csv to compare against
--category <name>   Run one category only, e.g. --category ssh
--root <dir>        Audit a mounted disk image or folder instead of /
--no-commands       File checks only; don't run any system commands
--list              List all controls
```

## How scoring works

- Each control has a risk rating: **High = 3, Medium = 2, Low = 1** points.
- PASS earns full points, PARTIAL earns half, FAIL earns zero. N/A and not-evaluated controls are excluded.
- Score = earned ÷ possible. Rating: Strong ≥ 90%, Satisfactory 75–89%, Needs Improvement 50–74%, Unsatisfactory < 50%.

Weighting means fixing one high-risk issue moves the score more than fixing a cosmetic one, the same way a real audit rating works.

## Report format

Each finding follows the standard internal-audit structure:

- **Condition**: what was observed (actual evidence from the system)
- **Criteria**: what it should be (the standard)
- **Risk**: why it matters
- **Recommendation**: the exact fix
- **Framework**: NIST CSF 2.0 subcategory + ISO 27001 Annex A control

## Code layout

```
src/main/java/auditor/
  Main.java                  CLI, runs checks, console output
  checks/Catalog.java        all 63 controls (add new ones here)
  checks/Helpers.java        reusable test builders (sysctl, permissions, services, mounts...)
  system/SystemContext.java  read-only access to files, permissions, services, packages
  system/SshConfig.java      effective sshd config (sshd -T, or parses Include/first-match rules)
  model/                     Check, Result, Finding
  report/                    Score, HtmlReport, CsvIO
```

## Design notes

- **Why read-only?** Audit independence: the auditor gathers evidence and recommends fixes, and the system owner remediates. A tool that silently "fixed" things would destroy the evidence trail.
- **SSH config is first-match-wins**, and Ubuntu includes `sshd_config.d/*.conf` *before* the main file. So a cloud-init file can override what you see in `sshd_config`. The tool handles this (or uses `sshd -T` when root).
- **PWD-01 vs NIST SP 800-63B:** CIS still recommends password expiry, but NIST now advises against forced periodic changes. The report flags the control and notes the tradeoff. Which policy to follow is a documented decision for the system owner.
- **Accepted risk:** some "failures" are legitimate (IP forwarding on a Docker host). In a real audit you document those as accepted exceptions rather than fixing them.
- **Limitations:** point-in-time snapshot, a subset of the full CIS Benchmark, and no review of policies, people or applications.

## Disclaimer

Controls are *based on* CIS Benchmark recommendations but are not an official CIS-certified implementation. For a certified assessment use CIS-CAT Pro.
