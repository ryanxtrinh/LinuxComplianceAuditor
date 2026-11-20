package auditor.checks;

import auditor.FakeRoot;
import auditor.model.Check;
import auditor.model.Result;
import auditor.model.Result.Status;
import auditor.system.SystemContext;
import org.junit.jupiter.api.Test;

import static auditor.model.Result.Status.*;
import static org.junit.jupiter.api.Assertions.*;

/**
 * Runs real controls from the catalog against a hardened and a weak fake system and
 * checks the verdicts. This is the same path as "--root", so commands are disabled.
 */
class ChecksOnFakeRootTest {

    private static Result run(String id, SystemContext ctx) {
        Check c = Catalog.all().stream().filter(x -> x.id().equals(id)).findFirst()
                .orElseThrow(() -> new AssertionError("no control " + id));
        return c.test().apply(ctx);
    }

    private static void expect(Status want, String id, SystemContext ctx) {
        Result r = run(id, ctx);
        assertEquals(want, r.status(), id + " evidence: " + r.evidence());
        assertFalse(r.evidence().isBlank(), id + " must record evidence");
    }

    private static SystemContext hardened() {
        return new FakeRoot()
                .file("/etc/ssh/sshd_config",
                        "# hardened",
                        "PermitRootLogin no",
                        "PasswordAuthentication no",
                        "PermitEmptyPasswords no",
                        "MaxAuthTries 3",
                        "X11Forwarding no",
                        "ClientAliveInterval 5m",
                        "LoginGraceTime 30",
                        "IgnoreRhosts yes",
                        "HostbasedAuthentication no",
                        "LogLevel VERBOSE")
                .file("/etc/login.defs",
                        "PASS_MAX_DAYS   365",
                        "PASS_MIN_DAYS   1",
                        "PASS_WARN_AGE   7",
                        "ENCRYPT_METHOD  YESCRYPT",
                        "UMASK           027")
                .file("/etc/passwd",
                        "root:x:0:0:root:/root:/bin/bash",
                        "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin",
                        "www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin",
                        "ryan:x:1000:1000:Ryan:/home/ryan:/bin/bash")
                .file("/etc/shadow",
                        "root:!:19700:0:99999:7:::",
                        "daemon:*:19700:0:99999:7:::",
                        "ryan:$y$j9T$abc$def:19700:1:365:7:::")
                .file("/etc/pam.d/common-password", "password requisite pam_pwquality.so retry=3")
                .file("/etc/security/pwquality.conf", "minlen = 14")
                .file("/etc/pam.d/common-auth", "auth required pam_faillock.so preauth")
                .file("/etc/sysctl.d/60-hardening.conf",
                        "net.ipv4.ip_forward = 0",
                        "net.ipv4.tcp_syncookies = 1",
                        "kernel.randomize_va_space = 2",
                        "net.ipv4.conf.all.rp_filter = 1",
                        "fs.protected_hardlinks = 1",
                        "fs.protected_symlinks = 1")
                .file("/etc/fstab",
                        "UUID=abcd / ext4 defaults 0 1",
                        "tmpfs /tmp tmpfs defaults,nodev,nosuid,noexec 0 0",
                        "tmpfs /dev/shm tmpfs defaults,nodev,nosuid,noexec 0 0")
                .context();
    }

    private static SystemContext weak() {
        return new FakeRoot()
                .file("/etc/ssh/sshd_config",
                        "PermitRootLogin yes",
                        "PermitEmptyPasswords yes",
                        "MaxAuthTries 10",
                        "X11Forwarding yes",
                        "IgnoreRhosts no")
                .file("/etc/login.defs", "PASS_MAX_DAYS 99999", "PASS_MIN_DAYS 0", "ENCRYPT_METHOD MD5")
                .file("/etc/passwd",
                        "root:x:0:0:root:/root:/bin/bash",
                        "toor:x:0:0:backdoor:/root:/bin/bash",
                        "www-data:x:33:33:www-data:/var/www:/bin/bash")
                .file("/etc/shadow", "root:$6$x$y:19700::::::", "toor::19700::::::")
                .file("/etc/pam.d/common-auth", "auth [success=1 default=ignore] pam_unix.so nullok")
                .file("/etc/sysctl.conf",
                        "net.ipv4.ip_forward=1",
                        "kernel.randomize_va_space=0",
                        "net.ipv4.conf.all.rp_filter=2")
                .file("/etc/fstab", "UUID=abcd / ext4 defaults 0 1")
                .context();
    }

    @Test
    void hardenedSshPasses() {
        SystemContext ctx = hardened();
        for (String id : new String[]{"SSH-01", "SSH-02", "SSH-03", "SSH-04", "SSH-05",
                "SSH-06", "SSH-07", "SSH-08", "SSH-10"}) {
            expect(PASS, id, ctx);
        }
    }

    @Test
    void weakSshFails() {
        SystemContext ctx = weak();
        for (String id : new String[]{"SSH-01", "SSH-02", "SSH-03", "SSH-04", "SSH-05", "SSH-06", "SSH-07", "SSH-08"}) {
            expect(FAIL, id, ctx);
        }
    }

    @Test
    void sshDefaultRootLoginIsOnlyAWarning() {
        // OpenSSH default is prohibit-password: keys still work for root
        SystemContext ctx = new FakeRoot().file("/etc/ssh/sshd_config", "Port 22").context();
        Result r = run("SSH-01", ctx);
        assertEquals(WARN, r.status());
        assertTrue(r.evidence().contains("OpenSSH default"), r.evidence());
    }

    @Test
    void sshChecksAreNotApplicableWithoutSshServer() {
        expect(NOT_APPLICABLE, "SSH-01", new FakeRoot().file("/etc/hostname", "box").context());
    }

    @Test
    void passwordPolicy() {
        SystemContext good = hardened(), bad = weak();
        for (String id : new String[]{"PWD-01", "PWD-02", "PWD-03", "PWD-04", "PWD-05", "PWD-06"}) expect(PASS, id, good);
        for (String id : new String[]{"PWD-01", "PWD-02", "PWD-03", "PWD-04", "PWD-05", "PWD-06"}) expect(FAIL, id, bad);
    }

    @Test
    void accountChecks() {
        SystemContext good = hardened(), bad = weak();
        for (String id : new String[]{"ACC-01", "ACC-02", "ACC-03"}) expect(PASS, id, good);

        Result uid0 = run("ACC-01", bad);
        assertEquals(FAIL, uid0.status());
        assertTrue(uid0.evidence().contains("toor"), uid0.evidence());
        assertTrue(run("ACC-02", bad).evidence().contains("toor"));
        assertTrue(run("ACC-03", bad).evidence().contains("www-data"));
    }

    @Test
    void kernelParametersReadFromSysctlFiles() {
        SystemContext good = hardened(), bad = weak();
        for (String id : new String[]{"NET-02", "NET-06", "KRN-01", "KRN-03", "NET-08"}) expect(PASS, id, good);
        expect(FAIL, "NET-02", bad);
        expect(FAIL, "KRN-01", bad);
        expect(WARN, "NET-08", bad); // loose reverse-path filtering
        expect(NOT_APPLICABLE, "NET-06", bad);
    }

    @Test
    void laterSysctlFileOverridesEarlierOne() {
        SystemContext ctx = new FakeRoot()
                .file("/usr/lib/sysctl.d/50-default.conf", "kernel.randomize_va_space = 0")
                .file("/etc/sysctl.d/99-local.conf", "kernel.randomize_va_space = 2")
                .context();
        expect(PASS, "KRN-01", ctx);
    }

    @Test
    void tmpMountOptions() {
        SystemContext good = hardened(), bad = weak();
        expect(PASS, "FS-01", good);
        expect(PASS, "FS-02", good);
        expect(PASS, "FS-03", good);
        expect(FAIL, "FS-01", bad);
        expect(FAIL, "FS-02", bad);

        SystemContext partial = new FakeRoot().file("/etc/fstab", "tmpfs /tmp tmpfs defaults,nosuid 0 0").context();
        Result r = run("FS-02", partial);
        assertEquals(FAIL, r.status());
        assertTrue(r.evidence().contains("nodev") && r.evidence().contains("noexec"), r.evidence());
    }

    @Test
    void everyControlRunsOnAnEmptyRootWithoutCrashing() {
        SystemContext empty = new FakeRoot().context();
        for (Check c : Catalog.all()) {
            Result r;
            try {
                r = c.test().apply(empty);
            } catch (RuntimeException e) {
                throw new AssertionError(c.id() + " threw " + e, e);
            }
            assertNotNull(r, c.id());
            assertNotNull(r.status(), c.id());
        }
    }
}
