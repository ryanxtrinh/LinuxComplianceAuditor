package auditor.checks;

import auditor.model.Check;
import auditor.model.Check.Severity;
import auditor.model.Result;
import auditor.system.SshConfig;
import auditor.system.SystemContext;

import java.util.*;
import java.util.function.Function;

import static auditor.checks.Helpers.*;
import static auditor.model.Check.Severity.*;

/**
 * Every control the auditor tests, grouped by category.
 *
 * The controls are based on CIS Benchmark recommendations for Linux. Each one is mapped to
 * NIST Cybersecurity Framework 2.0 and ISO/IEC 27001:2022 Annex A, so a failing check
 * can be traced back to a framework requirement, the same way an audit team does it.
 *
 * To add a control: copy one block, give it a new ID, write its test.
 */
public final class Catalog {

    private Catalog() {}

    // Framework references used below
    private static final String
            N_ID_MGMT = "PR.AA-01", N_AUTH = "PR.AA-03", N_LEAST_PRIV = "PR.AA-05",
            N_CONFIG = "PR.PS-01", N_SOFTWARE = "PR.PS-02", N_LOGS = "PR.PS-04", N_UNAUTH_SW = "PR.PS-05",
            N_NETWORK = "PR.IR-01", N_DATA_REST = "PR.DS-01", N_MONITOR = "DE.CM-09";
    private static final String
            I_ACCESS = "A.5.15 Access control", I_AUTH_INFO = "A.5.17 Authentication information",
            I_PRIV = "A.8.2 Privileged access rights", I_RESTRICT = "A.8.3 Information access restriction",
            I_SECURE_AUTH = "A.8.5 Secure authentication", I_MALWARE = "A.8.7 Protection against malware",
            I_VULN = "A.8.8 Management of technical vulnerabilities", I_CONFIG = "A.8.9 Configuration management",
            I_LOGGING = "A.8.15 Logging", I_CLOCK = "A.8.17 Clock synchronization",
            I_SW_INSTALL = "A.8.19 Installation of software on operational systems",
            I_NETSEC = "A.8.20 Networks security", I_NETSVC = "A.8.21 Security of network services";

    private static final List<Check> ALL = new ArrayList<>();

    private static void add(String id, String cat, String title, Severity sev, String criteria, String risk,
                            String fix, String nist, String iso, Function<SystemContext, Result> test) {
        ALL.add(new Check(id, cat, title, sev, criteria, risk, fix, nist, iso, test));
    }

    public static List<Check> all() { return Collections.unmodifiableList(ALL); }

    static {
        ssh();
        passwords();
        accounts();
        filePermissions();
        networkAndKernel();
        services();
        logging();
        filesystem();
    }

    // =====================================================================================
    private static void ssh() {
        String C = "SSH Server";
        String fixPrefix = "Edit /etc/ssh/sshd_config (or a file in /etc/ssh/sshd_config.d/), then: sudo systemctl reload ssh. Set: ";

        add("SSH-01", C, "Root login over SSH is disabled", HIGH,
                "PermitRootLogin no",
                "Attackers brute-force the 'root' account because the username is always known. Direct root login also removes accountability: you can't tell which admin did what.",
                fixPrefix + "PermitRootLogin no", N_LEAST_PRIV, I_PRIV,
                sshRule(s -> {
                    String v = s.get("PermitRootLogin").toLowerCase(Locale.ROOT);
                    if (v.equals("no")) return Result.pass(s.describe("PermitRootLogin"));
                    if (v.equals("yes")) return Result.fail(s.describe("PermitRootLogin"));
                    return Result.warn(s.describe("PermitRootLogin") + " (root can still log in with a key)");
                }));

        add("SSH-02", C, "SSH password authentication is disabled", MEDIUM,
                "PasswordAuthentication no (key-based login only)",
                "Password logins can be brute-forced or used with credentials leaked in other breaches. SSH keys cannot be guessed.",
                fixPrefix + "PasswordAuthentication no  (set up keys first with ssh-copy-id, or you'll lock yourself out)",
                N_AUTH, I_SECURE_AUTH,
                sshRule(s -> Result.of(s.get("PasswordAuthentication").equalsIgnoreCase("no"), s.describe("PasswordAuthentication"))));

        add("SSH-03", C, "Empty passwords are not allowed over SSH", HIGH,
                "PermitEmptyPasswords no",
                "Any account without a password would be reachable by anyone on the network.",
                fixPrefix + "PermitEmptyPasswords no", N_AUTH, I_SECURE_AUTH,
                sshRule(s -> Result.of(s.get("PermitEmptyPasswords").equalsIgnoreCase("no"), s.describe("PermitEmptyPasswords"))));

        add("SSH-04", C, "SSH login attempts per connection are limited", MEDIUM,
                "MaxAuthTries 4 or less",
                "A high limit lets an attacker try more passwords per connection, which speeds up brute-force attacks.",
                fixPrefix + "MaxAuthTries 4", N_AUTH, I_SECURE_AUTH,
                sshRule(s -> {
                    Integer n = parseInt(s.get("MaxAuthTries"));
                    return Result.of(n != null && n <= 4, s.describe("MaxAuthTries"));
                }));

        add("SSH-05", C, "X11 forwarding is disabled", LOW,
                "X11Forwarding no",
                "X11 forwarding exposes the client's display to the server. A compromised server could capture keystrokes or screenshots.",
                fixPrefix + "X11Forwarding no", N_CONFIG, I_CONFIG,
                sshRule(s -> Result.of(s.get("X11Forwarding").equalsIgnoreCase("no"), s.describe("X11Forwarding"))));

        add("SSH-06", C, "Idle SSH sessions time out", LOW,
                "ClientAliveInterval between 1 and 900 seconds",
                "Unattended open sessions on an unlocked workstation can be hijacked by anyone with physical or remote access.",
                fixPrefix + "ClientAliveInterval 300 and ClientAliveCountMax 3", N_AUTH, I_SECURE_AUTH,
                sshRule(s -> {
                    int sec = SshConfig.seconds(s.get("ClientAliveInterval"));
                    return Result.of(sec > 0 && sec <= 900, s.describe("ClientAliveInterval")
                            + (sec == 0 ? " (0 = sessions never time out)" : ""));
                }));

        add("SSH-07", C, "SSH login grace time is short", LOW,
                "LoginGraceTime 60 seconds or less",
                "Long grace periods let attackers hold many unauthenticated connections open, which helps denial-of-service and brute-force attacks.",
                fixPrefix + "LoginGraceTime 60", N_AUTH, I_SECURE_AUTH,
                sshRule(s -> {
                    int sec = SshConfig.seconds(s.get("LoginGraceTime"));
                    return Result.of(sec > 0 && sec <= 60, s.describe("LoginGraceTime"));
                }));

        add("SSH-08", C, "Host-based (rhosts) authentication is disabled", MEDIUM,
                "IgnoreRhosts yes and HostbasedAuthentication no",
                "Host-based trust lets anyone who controls a 'trusted' machine log in without a password, a classic way to move laterally between machines.",
                fixPrefix + "IgnoreRhosts yes and HostbasedAuthentication no", N_AUTH, I_SECURE_AUTH,
                sshRule(s -> Result.of(s.get("IgnoreRhosts").equalsIgnoreCase("yes")
                                && s.get("HostbasedAuthentication").equalsIgnoreCase("no"),
                        s.describe("IgnoreRhosts") + "; " + s.describe("HostbasedAuthentication"))));

        add("SSH-09", C, "Users cannot set environment options for SSH", LOW,
                "PermitUserEnvironment no",
                "Allowing users to set environment variables (like LD_PRELOAD) through SSH can bypass restrictions.",
                fixPrefix + "PermitUserEnvironment no", N_CONFIG, I_CONFIG,
                sshRule(s -> Result.of(s.get("PermitUserEnvironment").equalsIgnoreCase("no"), s.describe("PermitUserEnvironment"))));

        add("SSH-10", C, "SSH logging level captures logins", LOW,
                "LogLevel INFO or VERBOSE",
                "Without adequate logging, failed and successful logins can't be investigated after an incident.",
                fixPrefix + "LogLevel VERBOSE", N_LOGS, I_LOGGING,
                sshRule(s -> {
                    String v = s.get("LogLevel").toUpperCase(Locale.ROOT);
                    return Result.of(v.equals("INFO") || v.equals("VERBOSE"), s.describe("LogLevel"));
                }));

        add("SSH-11", C, "sshd_config is protected", MEDIUM,
                "/etc/ssh/sshd_config permissions 0600, owned by root",
                "If non-root users can read or change the SSH configuration, they can learn about weak settings or weaken them.",
                "sudo chown root:root /etc/ssh/sshd_config && sudo chmod 600 /etc/ssh/sshd_config", N_CONFIG, I_CONFIG,
                ctx -> Helpers.ssh(ctx).isEmpty() ? Result.na("No OpenSSH server installed")
                        : perms("/etc/ssh/sshd_config", 0600, false, "root").apply(ctx));

        add("SSH-12", C, "SSH private host keys are protected", MEDIUM,
                "/etc/ssh/ssh_host_*_key permissions 0600 (or 0640 group ssh_keys), owned by root",
                "A stolen host key lets an attacker impersonate this server and intercept users' SSH sessions (man-in-the-middle).",
                "sudo chmod 600 /etc/ssh/ssh_host_*_key && sudo chown root:root /etc/ssh/ssh_host_*_key", N_DATA_REST, I_RESTRICT,
                ctx -> {
                    if (Helpers.ssh(ctx).isEmpty()) return Result.na("No OpenSSH server installed");
                    List<String> keys = ctx.glob("/etc/ssh", "ssh_host_*_key");
                    if (keys.isEmpty()) return Result.na("No host keys generated yet");
                    List<String> bad = new ArrayList<>();
                    for (String k : keys) {
                        int m = ctx.mode(k);
                        boolean groupKeys = ctx.group(k).equals("ssh_keys");
                        int allowed = groupKeys ? 0640 : 0600;
                        if ((m & ~allowed & 0777) != 0 || !ctx.owner(k).equals("root"))
                            bad.add(k + " " + octal(m) + " " + ctx.owner(k) + ":" + ctx.group(k));
                    }
                    return bad.isEmpty() ? Result.pass(keys.size() + " host keys correctly restricted")
                            : Result.fail("Too permissive: " + String.join("; ", bad));
                });
    }

    // =====================================================================================
    private static void passwords() {
        String C = "Password Policy";

        add("PWD-01", C, "Passwords have a maximum age", MEDIUM,
                "PASS_MAX_DAYS 365 or less in /etc/login.defs",
                "Passwords that never expire stay valid forever if they're leaked. (Note: NIST SP 800-63B no longer recommends forced periodic changes when other controls exist. Document whichever policy your organization chooses.)",
                "Set PASS_MAX_DAYS 365 in /etc/login.defs; apply to existing users with: sudo chage --maxdays 365 <user>",
                N_ID_MGMT, I_AUTH_INFO,
                ctx -> keyValue(ctx, "/etc/login.defs", "PASS_MAX_DAYS")
                        .map(v -> { Integer n = parseInt(v); return Result.of(n != null && n > 0 && n <= 365, "PASS_MAX_DAYS = " + v); })
                        .orElse(Result.fail("PASS_MAX_DAYS not set (passwords never expire)")));

        add("PWD-02", C, "Minimum days between password changes", LOW,
                "PASS_MIN_DAYS 1 or more",
                "Without a minimum, users can change a password several times in a row to get their old one back, defeating password history.",
                "Set PASS_MIN_DAYS 1 in /etc/login.defs", N_ID_MGMT, I_AUTH_INFO,
                ctx -> keyValue(ctx, "/etc/login.defs", "PASS_MIN_DAYS")
                        .map(v -> { Integer n = parseInt(v); return Result.of(n != null && n >= 1, "PASS_MIN_DAYS = " + v); })
                        .orElse(Result.fail("PASS_MIN_DAYS not set")));

        add("PWD-03", C, "Users are warned before passwords expire", LOW,
                "PASS_WARN_AGE 7 or more",
                "Without warning, users get locked out unexpectedly and tend to pick weak replacement passwords in a hurry.",
                "Set PASS_WARN_AGE 7 in /etc/login.defs", N_ID_MGMT, I_AUTH_INFO,
                ctx -> keyValue(ctx, "/etc/login.defs", "PASS_WARN_AGE")
                        .map(v -> { Integer n = parseInt(v); return Result.of(n != null && n >= 7, "PASS_WARN_AGE = " + v); })
                        .orElse(Result.fail("PASS_WARN_AGE not set")));

        add("PWD-04", C, "Minimum password length is enforced", MEDIUM,
                "pam_pwquality enabled with minlen 14 or more",
                "Short passwords can be cracked quickly. Length is the single biggest factor in password strength.",
                "sudo apt install libpam-pwquality, then set minlen = 14 in /etc/security/pwquality.conf",
                N_ID_MGMT, I_AUTH_INFO,
                ctx -> {
                    boolean enabled = pamFiles(ctx, "common-password", "system-auth").stream().anyMatch(l -> l.contains("pam_pwquality"));
                    List<String> files = new ArrayList<>(List.of("/etc/security/pwquality.conf"));
                    files.addAll(ctx.glob("/etc/security/pwquality.conf.d", "*.conf"));
                    Optional<String> minlen = iniValue(ctx, "minlen", files.toArray(String[]::new));
                    Integer n = minlen.map(Helpers::parseInt).orElse(8); // pwquality default is 8
                    String ev = "pam_pwquality " + (enabled ? "enabled" : "NOT enabled") + "; minlen = "
                            + n + (minlen.isEmpty() ? " (default)" : "");
                    return Result.of(enabled && n != null && n >= 14, ev);
                });

        add("PWD-05", C, "Passwords are stored with a strong hash", MEDIUM,
                "ENCRYPT_METHOD SHA512 or YESCRYPT in /etc/login.defs",
                "Weak hashes (MD5, DES) let an attacker who steals /etc/shadow crack most passwords in hours.",
                "Set ENCRYPT_METHOD YESCRYPT (or SHA512) in /etc/login.defs, then have users change passwords",
                N_DATA_REST, I_AUTH_INFO,
                ctx -> keyValue(ctx, "/etc/login.defs", "ENCRYPT_METHOD")
                        .map(v -> Result.of(v.equalsIgnoreCase("SHA512") || v.equalsIgnoreCase("YESCRYPT"), "ENCRYPT_METHOD = " + v))
                        .orElse(Result.warn("ENCRYPT_METHOD not set in login.defs; PAM's default hash applies")));

        add("PWD-06", C, "Accounts lock after repeated failed logins", MEDIUM,
                "pam_faillock (or pam_tally2) configured in the PAM auth stack",
                "Without lockout, an attacker can guess passwords against local logins indefinitely.",
                "Add pam_faillock to /etc/pam.d/common-auth (Debian/Ubuntu) or use authselect enable-feature with-faillock (RHEL); set deny = 5 in /etc/security/faillock.conf",
                N_AUTH, I_SECURE_AUTH,
                ctx -> {
                    List<String> pam = pamFiles(ctx, "common-auth", "system-auth");
                    if (pam.isEmpty()) return Result.na("No PAM auth configuration found");
                    Optional<String> line = pam.stream().filter(l -> l.contains("pam_faillock") || l.contains("pam_tally2")).findFirst();
                    return line.map(l -> Result.pass("Configured: " + l))
                            .orElse(Result.fail("No pam_faillock / pam_tally2 entry in the PAM auth stack"));
                });
    }

    // =====================================================================================
    private static void accounts() {
        String C = "Accounts & Privileges";

        add("ACC-01", C, "Only root has UID 0", HIGH,
                "root is the only account in /etc/passwd with UID 0",
                "Any other UID-0 account is a full superuser, and often a backdoor left by an attacker.",
                "Investigate the extra account, then remove it (sudo userdel <name>) or assign it a normal UID",
                N_LEAST_PRIV, I_PRIV,
                ctx -> {
                    List<String> uid0 = new ArrayList<>();
                    for (String[] f : passwd(ctx)) if (f[2].equals("0")) uid0.add(f[0]);
                    return Result.of(uid0.equals(List.of("root")), "UID 0 accounts: " + String.join(", ", uid0));
                });

        add("ACC-02", C, "No accounts have an empty password", HIGH,
                "Every account in /etc/shadow has a password hash or is locked (! or *)",
                "An account with an empty password can be logged into by anyone.",
                "Lock the account (sudo passwd -l <user>) or set a password",
                N_AUTH, I_AUTH_INFO,
                ctx -> {
                    List<String> empty = new ArrayList<>();
                    int total = 0;
                    for (String l : ctx.lines("/etc/shadow")) {
                        String[] f = l.split(":", -1);
                        if (f.length < 2) continue;
                        total++;
                        if (f[1].isEmpty()) empty.add(f[0]);
                    }
                    if (total == 0) return Result.error("/etc/shadow is empty or missing");
                    return Result.of(empty.isEmpty(), empty.isEmpty() ? "All " + total + " accounts have a hash or are locked"
                            : "Empty password: " + String.join(", ", empty));
                });

        add("ACC-03", C, "System accounts can't log in interactively", MEDIUM,
                "Accounts with UID below 1000 (except root) use /usr/sbin/nologin or /bin/false",
                "Service accounts like 'www-data' have no human owner. If one has a real shell and gets compromised, the attacker gets an interactive foothold.",
                "sudo usermod -s /usr/sbin/nologin <account>", N_LEAST_PRIV, I_ACCESS,
                ctx -> {
                    Set<String> exempt = Set.of("root", "sync", "shutdown", "halt");
                    List<String> bad = new ArrayList<>();
                    for (String[] f : passwd(ctx)) {
                        Integer uid = parseInt(f[2]);
                        if (uid == null || uid >= 1000 || exempt.contains(f[0])) continue;
                        String shell = f[6];
                        if (!(shell.endsWith("nologin") || shell.endsWith("/false") || shell.isEmpty()))
                            bad.add(f[0] + " (" + shell + ")");
                    }
                    return Result.of(bad.isEmpty(), bad.isEmpty() ? "All system accounts use a non-login shell"
                            : "Login shells on system accounts: " + String.join(", ", bad));
                });

        add("ACC-04", C, "Default file permissions (umask) are restrictive", LOW,
                "UMASK 027 or stricter in /etc/login.defs",
                "With umask 022, every new file a user creates is readable by all other users on the system.",
                "Set UMASK 027 in /etc/login.defs", N_LEAST_PRIV, I_RESTRICT,
                ctx -> keyValue(ctx, "/etc/login.defs", "UMASK").map(v -> {
                    try {
                        int u = Integer.parseInt(v, 8);
                        return Result.of((u & 027) == 027, "UMASK = " + v);
                    } catch (NumberFormatException e) { return Result.error("Unreadable UMASK value: " + v); }
                }).orElse(Result.fail("UMASK not set (system default 022 applies)")));

        add("ACC-05", C, "Inactive accounts are disabled automatically", LOW,
                "INACTIVE 30 days or less in /etc/default/useradd",
                "Accounts of people who left or no longer use the system stay usable indefinitely, which is a common audit finding.",
                "sudo useradd -D -f 30", N_ID_MGMT, I_ACCESS,
                ctx -> {
                    Optional<String> v = iniValue(ctx, "INACTIVE", "/etc/default/useradd");
                    Integer n = v.map(Helpers::parseInt).orElse(-1);
                    return Result.of(n != null && n >= 0 && n <= 30, "INACTIVE = " + (n == null ? v.orElse("?") : n)
                            + (n != null && n < 0 ? " (never disabled)" : ""));
                });

        add("ACC-06", C, "sudo does not allow password-less root", MEDIUM,
                "No NOPASSWD rules in /etc/sudoers or /etc/sudoers.d",
                "NOPASSWD means anyone who gets the user's session (stolen laptop, malware) becomes root instantly with no extra barrier.",
                "Remove NOPASSWD from the rule with: sudo visudo (or the file in /etc/sudoers.d)",
                N_LEAST_PRIV, I_PRIV,
                ctx -> {
                    if (!ctx.exists("/etc/sudoers")) return Result.na("sudo not installed");
                    List<String> hits = sudoers(ctx).stream().filter(l -> l.contains("NOPASSWD") && !l.startsWith("Defaults")).toList();
                    return Result.of(hits.isEmpty(), hits.isEmpty() ? "No NOPASSWD rules" : "NOPASSWD rules: " + String.join(" | ", hits));
                });

        add("ACC-07", C, "sudo commands run in a pseudo-terminal", LOW,
                "Defaults use_pty in sudoers",
                "Without use_pty, a malicious program run with sudo can keep running in the background after sudo exits and inject keystrokes into the user's terminal.",
                "sudo visudo, then add: Defaults use_pty", N_LEAST_PRIV, I_PRIV,
                ctx -> {
                    if (!ctx.exists("/etc/sudoers")) return Result.na("sudo not installed");
                    boolean on = sudoers(ctx).stream().anyMatch(l -> l.startsWith("Defaults") && l.matches(".*\\buse_pty\\b.*") && !l.contains("!use_pty"));
                    return Result.of(on, on ? "Defaults use_pty is set" : "use_pty not set");
                });

        add("ACC-08", C, "sudo usage is logged to a dedicated file", LOW,
                "Defaults logfile=\"/var/log/sudo.log\" in sudoers",
                "A dedicated sudo log makes reviewing privileged activity straightforward, which is a common audit evidence request.",
                "sudo visudo, then add: Defaults logfile=\"/var/log/sudo.log\"", N_LOGS, I_LOGGING,
                ctx -> {
                    if (!ctx.exists("/etc/sudoers")) return Result.na("sudo not installed");
                    Optional<String> l = sudoers(ctx).stream().filter(x -> x.startsWith("Defaults") && x.contains("logfile")).findFirst();
                    return l.map(x -> Result.pass(x)).orElse(Result.fail("No sudo logfile configured (only syslog/journal)"));
                });
    }

    // =====================================================================================
    private static void filePermissions() {
        String C = "File Permissions";

        add("FP-01", C, "/etc/passwd permissions", MEDIUM, "0644 or stricter, root:root",
                "If writable by others, anyone could add an account or change a user's UID to 0.",
                "sudo chown root:root /etc/passwd && sudo chmod 644 /etc/passwd", N_LEAST_PRIV, I_RESTRICT,
                perms("/etc/passwd", 0644, false, "root"));

        add("FP-02", C, "/etc/shadow permissions", HIGH, "0640 or stricter, owned by root, group root or shadow",
                "/etc/shadow holds password hashes. Anyone who can read it can crack passwords offline.",
                "sudo chown root:shadow /etc/shadow && sudo chmod 640 /etc/shadow", N_DATA_REST, I_AUTH_INFO,
                perms("/etc/shadow", 0640, false, "root", "shadow"));

        add("FP-03", C, "/etc/group permissions", MEDIUM, "0644 or stricter, root:root",
                "If writable, any user could add themselves to the sudo or admin group.",
                "sudo chown root:root /etc/group && sudo chmod 644 /etc/group", N_LEAST_PRIV, I_RESTRICT,
                perms("/etc/group", 0644, false, "root"));

        add("FP-04", C, "/etc/gshadow permissions", MEDIUM, "0640 or stricter, owned by root, group root or shadow",
                "Holds group password hashes and group administrator lists.",
                "sudo chown root:shadow /etc/gshadow && sudo chmod 640 /etc/gshadow", N_DATA_REST, I_AUTH_INFO,
                perms("/etc/gshadow", 0640, true, "root", "shadow"));

        add("FP-05", C, "/etc/crontab permissions", LOW, "0600 or stricter, root:root",
                "Readable cron files tell an attacker which scripts run as root and when, a roadmap for privilege escalation.",
                "sudo chown root:root /etc/crontab && sudo chmod 600 /etc/crontab", N_CONFIG, I_CONFIG,
                perms("/etc/crontab", 0600, true, "root"));

        add("FP-06", C, "Bootloader config permissions", MEDIUM, "grub.cfg 0600 or stricter, root:root",
                "Readable boot config can reveal a GRUB password hash. If it's writable, the kernel can be booted with security disabled.",
                "sudo chown root:root /boot/grub/grub.cfg && sudo chmod 600 /boot/grub/grub.cfg", N_CONFIG, I_CONFIG,
                ctx -> {
                    for (String p : new String[]{"/boot/grub/grub.cfg", "/boot/grub2/grub.cfg"})
                        if (ctx.exists(p)) return perms(p, 0600, false, "root").apply(ctx);
                    return Result.na("No GRUB config found (container, VM without GRUB, or EFI-only boot)");
                });

        add("FP-07", C, "/tmp has the sticky bit", MEDIUM, "/tmp mode includes the sticky bit (1777)",
                "Without the sticky bit, any user can delete or replace other users' temporary files, including ones root programs rely on.",
                "sudo chmod 1777 /tmp", N_LEAST_PRIV, I_RESTRICT,
                ctx -> {
                    int m = ctx.mode("/tmp");
                    if (m < 0) return Result.fail("/tmp missing");
                    return Result.of((m & 01000) != 0, "/tmp is " + octal(m));
                });

        add("FP-08", C, "No world-writable files in /etc", MEDIUM, "No regular file under /etc writable by all users",
                "A world-writable config file lets any user change system behavior, often straight to root.",
                "sudo chmod o-w <file> for each file listed", N_CONFIG, I_CONFIG,
                ctx -> {
                    List<String> bad = new ArrayList<>();
                    walk(ctx, "/etc", 4, bad);
                    return Result.of(bad.isEmpty(), bad.isEmpty() ? "None found"
                            : bad.size() + " found: " + String.join(", ", bad.subList(0, Math.min(10, bad.size()))));
                });
    }

    private static void walk(SystemContext ctx, String dir, int depth, List<String> bad) {
        if (depth < 0) return;
        java.nio.file.Path d = ctx.path(dir);
        try (var ds = java.nio.file.Files.newDirectoryStream(d)) {
            for (var p : ds) {
                String abs = dir + "/" + p.getFileName();
                if (java.nio.file.Files.isSymbolicLink(p)) continue;
                if (java.nio.file.Files.isDirectory(p)) walk(ctx, abs, depth - 1, bad);
                else if (java.nio.file.Files.isRegularFile(p) && (ctx.mode(abs) & 02) != 0) bad.add(abs);
            }
        } catch (java.io.IOException ignored) { }
    }

    // =====================================================================================
    private static void networkAndKernel() {
        String C = "Network & Kernel";

        add("NET-01", C, "Host firewall is active", HIGH,
                "ufw, firewalld or nftables/iptables filtering incoming traffic",
                "Without a firewall, every listening service is exposed to the whole network, including ones you didn't know were running.",
                "sudo ufw default deny incoming && sudo ufw allow ssh && sudo ufw enable", N_NETWORK, I_NETSEC,
                Catalog::firewall);

        add("NET-02", C, "IP forwarding is disabled", MEDIUM, "net.ipv4.ip_forward = 0",
                "A workstation that forwards packets can be used as a router to reach networks it bridges, or to man-in-the-middle traffic. (Docker hosts and routers legitimately need this; document it as an accepted exception.)",
                "echo 'net.ipv4.ip_forward = 0' | sudo tee /etc/sysctl.d/60-hardening.conf && sudo sysctl --system",
                N_NETWORK, I_NETSEC, sysctlEquals("net.ipv4.ip_forward", "0"));

        add("NET-03", C, "ICMP redirects are not sent", MEDIUM,
                "net.ipv4.conf.all.send_redirects = 0 and .default.send_redirects = 0",
                "Only routers should send redirects. A compromised host could use them to reroute other machines' traffic.",
                "Add both settings = 0 to /etc/sysctl.d/60-hardening.conf, then sudo sysctl --system", N_NETWORK, I_NETSEC,
                sysctlAll("0", "net.ipv4.conf.all.send_redirects", "net.ipv4.conf.default.send_redirects"));

        add("NET-04", C, "ICMP redirects are not accepted", MEDIUM,
                "net.ipv4.conf.all.accept_redirects = 0 (IPv4 and IPv6)",
                "Forged redirect messages can silently send this machine's traffic through an attacker.",
                "Set net.ipv4.conf.all.accept_redirects = 0 and net.ipv6.conf.all.accept_redirects = 0", N_NETWORK, I_NETSEC,
                sysctlAll("0", "net.ipv4.conf.all.accept_redirects", "net.ipv4.conf.default.accept_redirects",
                        "net.ipv6.conf.all.accept_redirects"));

        add("NET-05", C, "Source-routed packets are rejected", MEDIUM,
                "net.ipv4.conf.all.accept_source_route = 0",
                "Source routing lets the sender choose the path a packet takes, which can be used to get around firewalls.",
                "Set net.ipv4.conf.all.accept_source_route = 0", N_NETWORK, I_NETSEC,
                sysctlAll("0", "net.ipv4.conf.all.accept_source_route", "net.ipv4.conf.default.accept_source_route"));

        add("NET-06", C, "TCP SYN cookies are enabled", MEDIUM, "net.ipv4.tcp_syncookies = 1",
                "Protects against SYN-flood denial-of-service attacks that exhaust the connection table.",
                "Set net.ipv4.tcp_syncookies = 1", N_NETWORK, I_NETSEC,
                sysctlEquals("net.ipv4.tcp_syncookies", "1"));

        add("NET-07", C, "Broadcast pings are ignored", LOW, "net.ipv4.icmp_echo_ignore_broadcasts = 1",
                "Prevents the machine from taking part in 'smurf' amplification attacks.",
                "Set net.ipv4.icmp_echo_ignore_broadcasts = 1", N_NETWORK, I_NETSEC,
                sysctlEquals("net.ipv4.icmp_echo_ignore_broadcasts", "1"));

        add("NET-08", C, "Reverse path filtering is enabled", LOW, "net.ipv4.conf.all.rp_filter = 1",
                "Drops packets with spoofed source addresses that couldn't really have arrived on that interface.",
                "Set net.ipv4.conf.all.rp_filter = 1 and net.ipv4.conf.default.rp_filter = 1", N_NETWORK, I_NETSEC,
                ctx -> sysctl(ctx, "net.ipv4.conf.all.rp_filter").map(v -> switch (v) {
                    case "1" -> Result.pass("rp_filter = 1 (strict)");
                    case "2" -> Result.warn("rp_filter = 2 (loose mode: partial protection)");
                    default -> Result.fail("rp_filter = " + v);
                }).orElse(Result.na("Not present")));

        add("NET-09", C, "Suspicious packets are logged", LOW, "net.ipv4.conf.all.log_martians = 1",
                "Logging packets with impossible source addresses gives early warning of spoofing or misconfiguration.",
                "Set net.ipv4.conf.all.log_martians = 1 and .default.log_martians = 1", N_MONITOR, I_LOGGING,
                sysctlAll("1", "net.ipv4.conf.all.log_martians", "net.ipv4.conf.default.log_martians"));

        add("KRN-01", C, "Address space layout randomization (ASLR) is full", HIGH, "kernel.randomize_va_space = 2",
                "ASLR makes memory-corruption exploits much harder by randomizing where code and data live in memory.",
                "Set kernel.randomize_va_space = 2", N_CONFIG, I_MALWARE,
                sysctlEquals("kernel.randomize_va_space", "2"));

        add("KRN-02", C, "Core dumps of privileged programs are disabled", LOW, "fs.suid_dumpable = 0",
                "A crashing setuid program could write memory, including password hashes or keys, to a file other users can read.",
                "Set fs.suid_dumpable = 0", N_DATA_REST, I_RESTRICT,
                sysctlEquals("fs.suid_dumpable", "0"));

        add("KRN-03", C, "Hardlink and symlink protections are on", LOW,
                "fs.protected_hardlinks = 1 and fs.protected_symlinks = 1",
                "Blocks a classic privilege-escalation trick: tricking a root process into following a link in /tmp to overwrite a protected file.",
                "Set both fs.protected_hardlinks = 1 and fs.protected_symlinks = 1", N_LEAST_PRIV, I_RESTRICT,
                sysctlAll("1", "fs.protected_hardlinks", "fs.protected_symlinks"));

        add("KRN-04", C, "Kernel pointers are hidden", LOW, "kernel.kptr_restrict = 1 or 2",
                "Leaked kernel memory addresses help attackers defeat kernel ASLR when writing exploits.",
                "Set kernel.kptr_restrict = 1", N_CONFIG, I_MALWARE,
                ctx -> sysctl(ctx, "kernel.kptr_restrict")
                        .map(v -> Result.of(v.equals("1") || v.equals("2"), "kernel.kptr_restrict = " + v))
                        .orElse(Result.na("Not present")));
    }

    private static Result firewall(SystemContext ctx) {
        if (!ctx.commandsAllowed()) {
            Optional<String> ufw = iniValue(ctx, "ENABLED", "/etc/ufw/ufw.conf");
            if (ufw.isPresent()) return Result.of(ufw.get().equalsIgnoreCase("yes"), "/etc/ufw/ufw.conf ENABLED=" + ufw.get());
            return Result.error("Can't determine firewall state from files alone (run on the live system)");
        }
        boolean askedAny = false;
        SystemContext.CommandResult r = ctx.run("ufw", "status");
        if (r != null && r.exitCode() == 0) {
            askedAny = true;
            if (r.output().contains("Status: active")) return Result.pass("ufw: Status: active");
        }
        if (ctx.serviceActive("firewalld", "firewalld")) return Result.pass("firewalld is running");
        r = ctx.run("nft", "list", "ruleset");
        if (r != null && r.exitCode() == 0) {
            askedAny = true;
            if (r.output().contains("hook input") && (r.output().contains("policy drop") || r.output().contains(" drop")))
                return Result.pass("nftables input chain with drop rules is loaded");
        }
        r = ctx.run("iptables", "-S", "INPUT");
        if (r != null && r.exitCode() == 0) {
            askedAny = true;
            if (r.output().contains("-P INPUT DROP") || r.output().lines().anyMatch(l -> l.startsWith("-A INPUT")))
                return Result.pass("iptables INPUT rules present");
        }
        if (!askedAny) return ctx.isRoot() ? Result.fail("No firewall tool (ufw, firewalld, nftables, iptables) found")
                                           : Result.error("Firewall status needs root (re-run with sudo)");
        return Result.fail("No active firewall: ufw inactive, firewalld not running, no input filtering rules loaded");
    }

    // =====================================================================================
    private static void services() {
        String C = "Services & Software";

        add("SVC-01", C, "Legacy cleartext remote-access services are absent", HIGH,
                "telnet, rsh/rlogin, tftp and inetd/xinetd servers are not installed or running",
                "These protocols send passwords and data unencrypted, so anyone on the network can capture them.",
                "sudo apt purge telnetd inetutils-telnetd rsh-server rsh-redone-server tftpd-hpa xinetd openbsd-inetd",
                N_SOFTWARE, I_NETSVC,
                notPresent(new String[]{"telnetd", "inetutils-telnetd", "telnet-server", "rsh-server", "rsh-redone-server",
                                "tftpd-hpa", "tftp-server", "xinetd", "openbsd-inetd"},
                        new String[]{"telnet.socket", "xinetd", "inetd", "tftpd-hpa"}, "in.telnetd", "telnetd", "xinetd", "inetd", "in.tftpd", "in.rshd"));

        add("SVC-02", C, "No FTP server is running", MEDIUM,
                "vsftpd, proftpd and pure-ftpd are not installed",
                "Plain FTP sends credentials in cleartext. Use SFTP (part of SSH) instead.",
                "sudo apt purge vsftpd proftpd-basic pure-ftpd", N_SOFTWARE, I_NETSVC,
                notPresent(new String[]{"vsftpd", "proftpd-basic", "proftpd", "pure-ftpd"},
                        new String[]{"vsftpd", "proftpd", "pure-ftpd"}, "vsftpd", "proftpd", "pure-ftpd"));

        add("SVC-03", C, "Avahi (mDNS) is disabled", LOW, "avahi-daemon not running",
                "Advertises this machine and its services to everyone on the local network. Unnecessary on servers and a recurring source of vulnerabilities.",
                "sudo systemctl disable --now avahi-daemon.socket avahi-daemon.service", N_CONFIG, I_NETSVC,
                ctx -> Result.of(!ctx.serviceActive("avahi-daemon", "avahi-daemon"),
                        ctx.serviceActive("avahi-daemon", "avahi-daemon") ? "avahi-daemon is running" : "avahi-daemon not running"));

        add("SVC-04", C, "rpcbind is disabled", LOW, "rpcbind not running (unless this host serves NFS)",
                "rpcbind exposes RPC services to the network and has been abused for DDoS amplification.",
                "sudo systemctl disable --now rpcbind.socket rpcbind.service", N_CONFIG, I_NETSVC,
                ctx -> Result.of(!ctx.serviceActive("rpcbind", "rpcbind"),
                        ctx.serviceActive("rpcbind", "rpcbind") ? "rpcbind is running" : "rpcbind not running"));

        add("SVC-05", C, "SNMP agent is disabled", LOW, "snmpd not running",
                "SNMP v1/v2 uses cleartext 'community strings' (often still 'public') and leaks detailed system information.",
                "sudo systemctl disable --now snmpd  (or move to SNMPv3 with authentication)", N_CONFIG, I_NETSVC,
                ctx -> Result.of(!ctx.serviceActive("snmpd", "snmpd"),
                        ctx.serviceActive("snmpd", "snmpd") ? "snmpd is running" : "snmpd not running"));

        add("SVC-06", C, "Automatic security updates are enabled", MEDIUM,
                "unattended-upgrades enabled (Debian/Ubuntu) or dnf-automatic timer active (RHEL/Fedora)",
                "Most real breaches exploit vulnerabilities that already had patches available. Automatic updates close that window.",
                "sudo apt install unattended-upgrades && sudo dpkg-reconfigure -plow unattended-upgrades",
                N_SOFTWARE, I_VULN,
                ctx -> {
                    List<String> files = ctx.glob("/etc/apt/apt.conf.d", "*");
                    if (!files.isEmpty()) {
                        boolean on = false;
                        for (String f : files)
                            for (String l : ctx.configLines(f))
                                if (l.replace(" ", "").contains("APT::Periodic::Unattended-Upgrade\"1\"")) on = true;
                        Boolean installed = ctx.packageInstalled("unattended-upgrades");
                        String ev = "unattended-upgrades " + (Boolean.TRUE.equals(installed) ? "installed" : "not installed")
                                + "; APT::Periodic::Unattended-Upgrade " + (on ? "= \"1\"" : "not enabled");
                        return Result.of(on && !Boolean.FALSE.equals(installed), ev);
                    }
                    if (ctx.findProgram("dnf") != null)
                        return Result.of(ctx.serviceActive("dnf-automatic.timer") || ctx.serviceActive("dnf-automatic-install.timer"),
                                "dnf-automatic timer " + (ctx.serviceActive("dnf-automatic.timer") ? "active" : "not active"));
                    return Result.na("Unsupported package manager");
                });

        add("SVC-07", C, "Installed packages are up to date", MEDIUM,
                "No pending upgrades (based on the last 'apt update')",
                "Every pending update is a known, published vulnerability that attackers can look up.",
                "sudo apt update && sudo apt upgrade", N_SOFTWARE, I_VULN,
                ctx -> {
                    SystemContext.CommandResult r = ctx.run("apt-get", "-s", "-o", "Debug::NoLocking=1", "upgrade");
                    if (r == null) return Result.na("apt not available (or running in --root mode)");
                    long total = r.output().lines().filter(l -> l.startsWith("Inst ")).count();
                    long security = r.output().lines().filter(l -> l.startsWith("Inst ") && l.contains("-security")).count();
                    if (total == 0) return Result.pass("No pending upgrades");
                    String ev = total + " pending upgrades (" + security + " from security repositories)";
                    return security > 0 ? Result.fail(ev) : Result.warn(ev);
                });

        add("SVC-08", C, "Mandatory access control is enabled", MEDIUM,
                "AppArmor or SELinux enabled (SELinux in enforcing mode)",
                "MAC confines programs to what they need, so a hacked web server can't read users' files even when it runs as root.",
                "Ubuntu: sudo apt install apparmor apparmor-utils && sudo systemctl enable --now apparmor. RHEL: set SELINUX=enforcing in /etc/selinux/config",
                N_UNAUTH_SW, I_MALWARE,
                ctx -> {
                    Optional<String> aa = ctx.read("/sys/module/apparmor/parameters/enabled");
                    if (aa.isPresent() && aa.get().trim().equals("Y")) return Result.pass("AppArmor enabled in the kernel");
                    Optional<String> se = ctx.read("/sys/fs/selinux/enforce");
                    if (se.isPresent()) return se.get().trim().equals("1") ? Result.pass("SELinux enforcing")
                            : Result.warn("SELinux present but permissive");
                    return Result.fail("Neither AppArmor nor SELinux is active");
                });
    }

    // =====================================================================================
    private static void logging() {
        String C = "Logging & Monitoring";

        add("LOG-01", C, "auditd is installed and running", MEDIUM,
                "The Linux audit daemon is active",
                "auditd records security-relevant events (logins, privilege use, changes to key files). Without it, an investigation has very little to go on.",
                "sudo apt install auditd && sudo systemctl enable --now auditd", N_LOGS, I_LOGGING,
                ctx -> Result.of(ctx.serviceActive("auditd", "auditd"),
                        ctx.serviceActive("auditd", "auditd") ? "auditd is running"
                                : "auditd not running" + (Boolean.TRUE.equals(ctx.packageInstalled("auditd")) ? " (installed)" : " (not installed)")));

        add("LOG-02", C, "System logging service is running", MEDIUM,
                "rsyslog or systemd-journald is active",
                "Without a logging service, authentication and system events are lost entirely.",
                "sudo systemctl enable --now rsyslog (or systemd-journald)", N_LOGS, I_LOGGING,
                ctx -> {
                    if (ctx.serviceActive("rsyslog", "rsyslogd")) return Result.pass("rsyslog running");
                    if (ctx.serviceActive("systemd-journald", "systemd-journal")) return Result.pass("systemd-journald running");
                    if (ctx.serviceActive("syslog-ng", "syslog-ng")) return Result.pass("syslog-ng running");
                    return Result.fail("No logging daemon running");
                });

        add("LOG-03", C, "Journal logs survive a reboot", LOW,
                "journald Storage=persistent (or /var/log/journal exists)",
                "With volatile logs, a reboot (or an attacker forcing one) erases the evidence.",
                "Set Storage=persistent in /etc/systemd/journald.conf, then: sudo systemctl restart systemd-journald",
                N_LOGS, I_LOGGING,
                ctx -> {
                    List<String> files = new ArrayList<>(List.of("/etc/systemd/journald.conf"));
                    files.addAll(ctx.glob("/etc/systemd/journald.conf.d", "*.conf"));
                    Optional<String> st = iniValue(ctx, "Storage", files.toArray(String[]::new));
                    if (st.isPresent() && st.get().equalsIgnoreCase("persistent")) return Result.pass("Storage=persistent");
                    if (st.isPresent() && st.get().equalsIgnoreCase("volatile")) return Result.fail("Storage=volatile");
                    if (ctx.exists("/var/log/journal")) return Result.pass("Storage=" + st.orElse("auto") + " with /var/log/journal present (persistent)");
                    if (ctx.serviceActive("rsyslog", "rsyslogd")) return Result.pass("Journal volatile, but rsyslog writes persistent logs to /var/log");
                    return Result.fail("Logs are kept in memory only (no /var/log/journal)");
                });

        add("LOG-04", C, "Time synchronization is active", MEDIUM,
                "systemd-timesyncd, chronyd or ntpd running",
                "Accurate timestamps are essential for correlating logs across systems during an investigation, and for certificates and Kerberos to work.",
                "sudo timedatectl set-ntp true  (or install chrony)", N_LOGS, I_CLOCK,
                ctx -> {
                    for (String[] s : new String[][]{{"systemd-timesyncd", "systemd-timesyn"}, {"chrony", "chronyd"}, {"chronyd", "chronyd"}, {"ntp", "ntpd"}, {"ntpsec", "ntpd"}})
                        if (ctx.serviceActive(s[0], s[1])) return Result.pass(s[0] + " running");
                    return Result.fail("No time synchronization service running");
                });

        add("LOG-05", C, "Authentication logs are not world-readable", LOW,
                "/var/log/auth.log (or /var/log/secure) 0640 or stricter",
                "Auth logs contain usernames and sometimes passwords mistakenly typed into the username field.",
                "sudo chmod 640 /var/log/auth.log", N_DATA_REST, I_LOGGING,
                ctx -> {
                    for (String p : new String[]{"/var/log/auth.log", "/var/log/secure"}) {
                        int m = ctx.mode(p);
                        if (m >= 0) return Result.of((m & 07) == 0, p + " is " + octal(m) + " " + ctx.owner(p) + ":" + ctx.group(p));
                    }
                    return Result.na("No auth.log / secure file (logs may be journal-only)");
                });
    }

    // =====================================================================================
    private static void filesystem() {
        String C = "Filesystem";

        add("FS-01", C, "/tmp is a separate filesystem", LOW,
                "/tmp mounted separately (partition or tmpfs)",
                "If /tmp shares the root filesystem, a user filling it can crash the system, and the restrictive mount options in FS-02 can't be applied.",
                "sudo systemctl enable --now tmp.mount (tmpfs), or add a /tmp entry to /etc/fstab", N_CONFIG, I_CONFIG,
                ctx -> mount(ctx, "/tmp").map(m -> Result.pass("/tmp mounted as " + m.type()))
                        .orElse(Result.fail("/tmp is part of the root filesystem")));

        add("FS-02", C, "/tmp blocks executables and device files", MEDIUM,
                "/tmp mounted with nodev,nosuid,noexec",
                "Attackers often download and run their tools from /tmp because every user can write there. noexec stops that.",
                "Add nodev,nosuid,noexec to the /tmp options in /etc/fstab, then: sudo mount -o remount /tmp", N_UNAUTH_SW, I_SW_INSTALL,
                mountOptions("/tmp", "nodev", "nosuid", "noexec"));

        add("FS-03", C, "/dev/shm blocks executables and device files", MEDIUM,
                "/dev/shm mounted with nodev,nosuid,noexec",
                "Shared memory is world-writable like /tmp and is a favorite place for fileless malware.",
                "Add to /etc/fstab: tmpfs /dev/shm tmpfs defaults,nodev,nosuid,noexec 0 0, then: sudo mount -o remount /dev/shm",
                N_UNAUTH_SW, I_SW_INSTALL,
                mountOptions("/dev/shm", "nodev", "nosuid", "noexec"));
    }
}
