package auditor.system;

import auditor.FakeRoot;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class SshConfigTest {

    private static SshConfig load(FakeRoot root) {
        return SshConfig.load(root.context()).orElseThrow();
    }

    @Test
    void missingConfigMeansNoSshServer() {
        assertTrue(SshConfig.load(new FakeRoot().context()).isEmpty());
    }

    @Test
    void keywordsAreCaseInsensitiveAndFirstValueWins() {
        SshConfig s = load(new FakeRoot().file("/etc/ssh/sshd_config",
                "permitrootlogin no",
                "PermitRootLogin yes",
                "MaxAuthTries=3"));
        assertEquals("no", s.get("PermitRootLogin"));
        assertEquals("3", s.get("maxauthtries"));
        assertTrue(s.isExplicit("PERMITROOTLOGIN"));
    }

    @Test
    void unsetKeysFallBackToOpenSshDefaults() {
        SshConfig s = load(new FakeRoot().file("/etc/ssh/sshd_config", "Port 2222"));
        assertEquals("prohibit-password", s.get("PermitRootLogin"));
        assertEquals("6", s.get("MaxAuthTries"));
        assertFalse(s.isExplicit("MaxAuthTries"));
        assertTrue(s.describe("MaxAuthTries").contains("OpenSSH default"));
        assertEquals("", s.get("SomethingUnknown"));
    }

    @Test
    void includedDropInsOverrideTheMainFile() {
        // Ubuntu's layout: Include at the top, so sshd_config.d wins
        SshConfig s = load(new FakeRoot()
                .file("/etc/ssh/sshd_config",
                        "Include /etc/ssh/sshd_config.d/*.conf",
                        "PasswordAuthentication yes")
                .file("/etc/ssh/sshd_config.d/50-cloud-init.conf", "PasswordAuthentication no")
                .file("/etc/ssh/sshd_config.d/ignored.txt", "X11Forwarding yes"));
        assertEquals("no", s.get("PasswordAuthentication"));
        assertEquals("no", s.get("X11Forwarding"), "non-.conf files are not included");
    }

    @Test
    void relativeIncludeIsResolvedUnderEtcSsh() {
        SshConfig s = load(new FakeRoot()
                .file("/etc/ssh/sshd_config", "Include extra.conf")
                .file("/etc/ssh/extra.conf", "LoginGraceTime 20"));
        assertEquals("20", s.get("LoginGraceTime"));
    }

    @Test
    void settingsInsideMatchBlockAreNotGlobal() {
        SshConfig s = load(new FakeRoot().file("/etc/ssh/sshd_config",
                "X11Forwarding no",
                "Match User backup",
                "    PasswordAuthentication no"));
        assertEquals("no", s.get("X11Forwarding"));
        assertEquals("yes", s.get("PasswordAuthentication"), "Match-only setting must not count globally");
    }

    @Test
    void includeLoopDoesNotHang() {
        SshConfig s = load(new FakeRoot().file("/etc/ssh/sshd_config", "Include /etc/ssh/sshd_config", "MaxSessions 2"));
        assertEquals("2", s.get("MaxSessions"));
    }

    @Test
    void timeValues() {
        assertEquals(60, SshConfig.seconds("60"));
        assertEquals(120, SshConfig.seconds("2m"));
        assertEquals(5400, SshConfig.seconds("1h30m"));
        assertEquals(90, SshConfig.seconds("1M30S"));
        assertEquals(0, SshConfig.seconds("0"));
        assertEquals(-1, SshConfig.seconds(""));
    }
}
