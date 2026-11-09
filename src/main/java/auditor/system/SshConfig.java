package auditor.system;

import java.util.*;

/**
 * Works out the effective OpenSSH server configuration.
 *
 * Best source: `sshd -T` (needs root), which prints the final config with all defaults
 * applied. Otherwise we parse /etc/ssh/sshd_config ourselves:
 *   - keywords are case-insensitive
 *   - the FIRST value set for a keyword wins (unlike most config files)
 *   - "Include" pulls in other files at that point (Ubuntu includes sshd_config.d/*.conf
 *     at the top, so those files override the main file)
 *   - "Match" blocks only apply to some users/hosts, so we stop reading at the first one
 *   - anything not set falls back to OpenSSH's built-in default
 */
public final class SshConfig {

    private static final Map<String, String> DEFAULTS = Map.ofEntries(
            Map.entry("permitrootlogin", "prohibit-password"),
            Map.entry("passwordauthentication", "yes"),
            Map.entry("permitemptypasswords", "no"),
            Map.entry("x11forwarding", "no"),
            Map.entry("maxauthtries", "6"),
            Map.entry("clientaliveinterval", "0"),
            Map.entry("clientalivecountmax", "3"),
            Map.entry("logingracetime", "120"),
            Map.entry("ignorerhosts", "yes"),
            Map.entry("hostbasedauthentication", "no"),
            Map.entry("permituserenvironment", "no"),
            Map.entry("loglevel", "INFO"),
            Map.entry("allowtcpforwarding", "yes"),
            Map.entry("maxsessions", "10")
    );

    private final Map<String, String> values;
    public final String source;

    private SshConfig(Map<String, String> values, String source) {
        this.values = values;
        this.source = source;
    }

    /** Empty if no SSH server is installed. */
    public static Optional<SshConfig> load(SystemContext ctx) {
        if (!ctx.exists("/etc/ssh/sshd_config")) return Optional.empty();

        if (ctx.isRoot()) {
            SystemContext.CommandResult r = ctx.run("sshd", "-T");
            if (r != null && r.exitCode() == 0 && !r.output().isBlank()) {
                Map<String, String> m = new HashMap<>();
                for (String line : r.output().split("\n")) {
                    String[] kv = line.trim().split("\\s+", 2);
                    if (kv.length == 2) m.putIfAbsent(kv[0].toLowerCase(Locale.ROOT), kv[1]);
                }
                return Optional.of(new SshConfig(m, "sshd -T (effective config)"));
            }
        }

        Map<String, String> m = new HashMap<>();
        parse(ctx, "/etc/ssh/sshd_config", m, 0);
        return Optional.of(new SshConfig(m, "/etc/ssh/sshd_config (parsed)"));
    }

    /** Returns false if a Match block was reached (stop reading everything after it). */
    private static boolean parse(SystemContext ctx, String file, Map<String, String> m, int depth) {
        if (depth > 5) return true;
        for (String line : ctx.configLines(file)) {
            String[] kv = line.split("[\\s=]+", 2);
            String key = kv[0].toLowerCase(Locale.ROOT);
            String val = kv.length > 1 ? kv[1].trim() : "";
            if (key.equals("match")) return false;
            if (key.equals("include")) {
                for (String pattern : val.split("\\s+")) {
                    String abs = pattern.startsWith("/") ? pattern : "/etc/ssh/" + pattern;
                    int slash = abs.lastIndexOf('/');
                    String dir = abs.substring(0, slash), glob = abs.substring(slash + 1);
                    List<String> files = glob.contains("*") || glob.contains("?") ? ctx.glob(dir, glob) : List.of(abs);
                    for (String f : files) if (!parse(ctx, f, m, depth + 1)) return false;
                }
                continue;
            }
            m.putIfAbsent(key, val);
        }
        return true;
    }

    public String get(String key) {
        String k = key.toLowerCase(Locale.ROOT);
        return values.getOrDefault(k, DEFAULTS.getOrDefault(k, ""));
    }

    public boolean isExplicit(String key) { return values.containsKey(key.toLowerCase(Locale.ROOT)); }

    /** "MaxAuthTries 4" style evidence string, noting when we fell back to the default. */
    public String describe(String key) {
        return key + " = " + get(key) + (isExplicit(key) || source.startsWith("sshd -T") ? "" : " (OpenSSH default, not set)");
    }

    /** Parses a time value like "60", "2m", "1h30m" into seconds. */
    public static int seconds(String v) {
        int total = 0, num = 0;
        boolean any = false;
        for (char c : v.toLowerCase(Locale.ROOT).toCharArray()) {
            if (Character.isDigit(c)) { num = num * 10 + (c - '0'); any = true; }
            else {
                int mult = switch (c) { case 's' -> 1; case 'm' -> 60; case 'h' -> 3600; case 'd' -> 86400; case 'w' -> 604800; default -> 1; };
                total += num * mult; num = 0;
            }
        }
        return any ? total + num : -1;
    }
}
