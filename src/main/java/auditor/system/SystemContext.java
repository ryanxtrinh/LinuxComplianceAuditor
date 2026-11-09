package auditor.system;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.nio.file.attribute.PosixFilePermission;
import java.util.*;
import java.util.concurrent.TimeUnit;

/**
 * Read-only access to the system being audited.
 *
 * Nothing in this tool ever writes to, or changes, the system. It only reads files and
 * runs query commands (systemctl is-active, dpkg-query, ...).
 *
 * --root lets you audit a mounted disk image or a test folder instead of "/".
 * In that mode commands are disabled, because they would describe the
 * live machine rather than the image.
 */
public final class SystemContext {

    private final Path root;
    private final boolean allowCommands;
    private final boolean isRoot;
    private final Map<String, Optional<String>> cache = new HashMap<>();

    public SystemContext(Path root, boolean allowCommands) {
        this.root = root;
        this.allowCommands = allowCommands && root.toString().equals("/");
        this.isRoot = "root".equals(System.getProperty("user.name"));
    }

    public boolean isRoot() { return isRoot; }
    public boolean commandsAllowed() { return allowCommands; }
    public Path rootDir() { return root; }

    /** Map an absolute path like /etc/passwd to the audited root. */
    public Path path(String abs) {
        return root.resolve(abs.startsWith("/") ? abs.substring(1) : abs);
    }

    public boolean exists(String abs) { return Files.exists(path(abs)); }

    /** File contents, or empty if the file doesn't exist. Throws NeedsRootException if unreadable. */
    public Optional<String> read(String abs) {
        return cache.computeIfAbsent(abs, k -> {
            Path p = path(k);
            if (!Files.exists(p)) return Optional.empty();
            try {
                return Optional.of(Files.readString(p, StandardCharsets.UTF_8));
            } catch (AccessDeniedException e) {
                throw new NeedsRootException(k);
            } catch (IOException e) {
                try { // some /proc files aren't UTF-8 clean
                    return Optional.of(new String(Files.readAllBytes(p), StandardCharsets.ISO_8859_1));
                } catch (IOException e2) {
                    if (!Files.isReadable(p)) throw new NeedsRootException(k);
                    return Optional.empty();
                }
            }
        });
    }

    public List<String> lines(String abs) {
        return read(abs).map(s -> Arrays.asList(s.split("\n"))).orElse(List.of());
    }

    /** Lines with comments and blank lines removed, trimmed. */
    public List<String> configLines(String abs) {
        List<String> out = new ArrayList<>();
        for (String l : lines(abs)) {
            int hash = l.indexOf('#');
            String s = (hash >= 0 ? l.substring(0, hash) : l).trim();
            if (!s.isEmpty()) out.add(s);
        }
        return out;
    }

    /** Files matching a glob in a directory, e.g. ("/etc/ssh/sshd_config.d", "*.conf"), sorted. */
    public List<String> glob(String dir, String pattern) {
        Path d = path(dir);
        if (!Files.isDirectory(d)) return List.of();
        List<String> out = new ArrayList<>();
        try (DirectoryStream<Path> ds = Files.newDirectoryStream(d, pattern)) {
            for (Path p : ds) out.add(dir + "/" + p.getFileName());
        } catch (AccessDeniedException e) {
            throw new NeedsRootException(dir);
        } catch (IOException ignored) { }
        Collections.sort(out);
        return out;
    }

    /** Unix permission bits (e.g. 0644) or -1 if the file is missing. */
    public int mode(String abs) {
        Path p = path(abs);
        if (!Files.exists(p, LinkOption.NOFOLLOW_LINKS)) return -1;
        try {
            int m = 0;
            for (PosixFilePermission perm : Files.getPosixFilePermissions(p)) {
                m |= switch (perm) {
                    case OWNER_READ -> 0400; case OWNER_WRITE -> 0200; case OWNER_EXECUTE -> 0100;
                    case GROUP_READ -> 040;  case GROUP_WRITE -> 020;  case GROUP_EXECUTE -> 010;
                    case OTHERS_READ -> 04;  case OTHERS_WRITE -> 02;  case OTHERS_EXECUTE -> 01;
                };
            }
            Object raw = Files.getAttribute(p, "unix:mode"); // includes sticky/setuid bits
            if (raw instanceof Integer full) m = full & 07777;
            return m;
        } catch (UnsupportedOperationException | IllegalArgumentException e) {
            return modeFallback(p);
        } catch (IOException e) {
            return -1;
        }
    }

    private int modeFallback(Path p) {
        try {
            int m = 0;
            for (PosixFilePermission perm : Files.getPosixFilePermissions(p))
                m |= 1 << (8 - perm.ordinal());
            return m;
        } catch (IOException e) { return -1; }
    }

    public String owner(String abs) {
        try { return Files.getOwner(path(abs), LinkOption.NOFOLLOW_LINKS).getName(); }
        catch (IOException e) { return "?"; }
    }

    public String group(String abs) {
        try {
            Object g = Files.getAttribute(path(abs), "posix:group", LinkOption.NOFOLLOW_LINKS);
            return g.toString();
        } catch (IOException | UnsupportedOperationException e) { return "?"; }
    }

    // ------------------------------------------------------------------ commands

    public record CommandResult(int exitCode, String output) {}

    /** Runs a read-only query command. Returns null if commands are disabled or the program is missing. */
    public CommandResult run(String... cmd) {
        if (!allowCommands || findProgram(cmd[0]) == null) return null;
        try {
            Process p = new ProcessBuilder(cmd).redirectErrorStream(true).start();
            p.getOutputStream().close();
            String out = new String(p.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
            if (!p.waitFor(15, TimeUnit.SECONDS)) { p.destroyForcibly(); return null; }
            return new CommandResult(p.exitValue(), out.trim());
        } catch (IOException e) {
            return null;
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return null;
        }
    }

    public String findProgram(String name) {
        for (String dir : new String[]{"/usr/local/sbin", "/usr/local/bin", "/usr/sbin", "/usr/bin", "/sbin", "/bin"}) {
            if (Files.isExecutable(path(dir + "/" + name))) return dir + "/" + name;
        }
        return null;
    }

    /** True if systemd is the running init system (it isn't in most containers). */
    public boolean hasSystemd() {
        return allowCommands && Files.isDirectory(Path.of("/run/systemd/system")) && findProgram("systemctl") != null;
    }

    /**
     * Is a service running? Uses systemctl when available, otherwise looks for a
     * matching process name in /proc.
     */
    public boolean serviceActive(String unit, String... processNames) {
        if (hasSystemd()) {
            CommandResult r = run("systemctl", "is-active", unit);
            if (r != null && r.output().startsWith("active")) return true;
            if (r != null) return false;
        }
        if (!root.toString().equals("/")) return false;
        Set<String> names = new HashSet<>(Arrays.asList(processNames));
        if (names.isEmpty()) names.add(unit.replace(".service", "").replace(".socket", ""));
        try (DirectoryStream<Path> ds = Files.newDirectoryStream(Path.of("/proc"), "[0-9]*")) {
            for (Path pid : ds) {
                try {
                    String comm = Files.readString(pid.resolve("comm")).trim();
                    if (names.contains(comm)) return true;
                } catch (IOException ignored) { }
            }
        } catch (IOException ignored) { }
        return false;
    }

    /** Package installed? Returns null if no package manager could answer. */
    public Boolean packageInstalled(String pkg) {
        CommandResult r = run("dpkg-query", "-W", "-f=${Status}", pkg);
        if (r != null) return r.exitCode() == 0 && r.output().contains("install ok installed");
        r = run("rpm", "-q", pkg);
        if (r != null) return r.exitCode() == 0;
        // Offline/--root mode: look in the dpkg status database directly
        Optional<String> status = read("/var/lib/dpkg/status");
        if (status.isPresent()) {
            String block = "Package: " + pkg + "\n";
            int i = status.get().indexOf(block);
            if (i < 0) return false;
            int end = status.get().indexOf("\n\n", i);
            String entry = status.get().substring(i, end < 0 ? status.get().length() : end);
            return entry.contains("Status: install ok installed");
        }
        return null;
    }

    public String osName() {
        for (String l : lines("/etc/os-release"))
            if (l.startsWith("PRETTY_NAME=")) return l.substring(12).replace("\"", "");
        return "Unknown Linux";
    }

    public String hostname() {
        return read("/etc/hostname").map(String::trim).filter(s -> !s.isEmpty()).orElse("unknown-host");
    }
}
