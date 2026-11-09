package auditor.checks;

import auditor.model.Result;
import auditor.system.SshConfig;
import auditor.system.SystemContext;

import java.util.*;
import java.util.function.Function;

/** Reusable building blocks the check catalog is written with. */
final class Helpers {

    private Helpers() {}

    // ------------------------------------------------------------------ SSH

    private static final Map<SystemContext, Optional<SshConfig>> SSH = new IdentityHashMap<>();

    static Optional<SshConfig> ssh(SystemContext ctx) {
        return SSH.computeIfAbsent(ctx, SshConfig::load);
    }

    /** Builds an SSH test: N/A if no SSH server, otherwise apply the rule to the effective config. */
    static Function<SystemContext, Result> sshRule(Function<SshConfig, Result> rule) {
        return ctx -> ssh(ctx).map(rule).orElse(Result.na("No OpenSSH server installed (/etc/ssh/sshd_config not found)"));
    }

    // ------------------------------------------------------------------ key/value config files

    /** First "KEY value" in a whitespace-separated config like /etc/login.defs. */
    static Optional<String> keyValue(SystemContext ctx, String file, String key) {
        for (String l : ctx.configLines(file)) {
            String[] kv = l.split("\\s+", 2);
            if (kv[0].equals(key) && kv.length > 1) return Optional.of(kv[1].trim());
        }
        return Optional.empty();
    }

    /** "key = value" style (pwquality.conf, journald.conf). Last value wins across files, like the real parsers. */
    static Optional<String> iniValue(SystemContext ctx, String key, String... files) {
        String found = null;
        for (String f : files) {
            for (String l : ctx.configLines(f)) {
                int eq = l.indexOf('=');
                if (eq > 0 && l.substring(0, eq).trim().equalsIgnoreCase(key)) found = l.substring(eq + 1).trim();
            }
        }
        return Optional.ofNullable(found);
    }

    static Integer parseInt(String s) {
        try { return Integer.parseInt(s.trim()); } catch (NumberFormatException e) { return null; }
    }

    // ------------------------------------------------------------------ sysctl

    /**
     * Current kernel parameter. On a live system this is read from /proc/sys (the value
     * actually in force). With --root we read the sysctl config files instead.
     */
    static Optional<String> sysctl(SystemContext ctx, String key) {
        if (ctx.rootDir().toString().equals("/")) {
            Optional<String> v = ctx.read("/proc/sys/" + key.replace('.', '/'));
            if (v.isPresent()) return Optional.of(v.get().trim().replaceAll("\\s+", " "));
        }
        List<String> files = new ArrayList<>();
        files.addAll(ctx.glob("/usr/lib/sysctl.d", "*.conf"));
        files.addAll(ctx.glob("/etc/sysctl.d", "*.conf"));
        files.add("/etc/sysctl.conf");
        String found = null;
        for (String f : files) {
            for (String l : ctx.configLines(f)) {
                int eq = l.indexOf('=');
                if (eq > 0 && l.substring(0, eq).trim().replace('/', '.').equals(key)) found = l.substring(eq + 1).trim();
            }
        }
        return Optional.ofNullable(found);
    }

    static Function<SystemContext, Result> sysctlEquals(String key, String expected) {
        return ctx -> sysctl(ctx, key)
                .map(v -> Result.of(v.equals(expected), key + " = " + v + " (expected " + expected + ")"))
                .orElse(Result.na(key + " not present on this kernel"));
    }

    static Function<SystemContext, Result> sysctlAll(String expected, String... keys) {
        return ctx -> {
            List<String> ev = new ArrayList<>();
            boolean ok = true, any = false;
            for (String k : keys) {
                Optional<String> v = sysctl(ctx, k);
                if (v.isEmpty()) continue;
                any = true;
                ev.add(k + " = " + v.get());
                if (!v.get().equals(expected)) ok = false;
            }
            if (!any) return Result.na("Parameters not present on this kernel");
            return Result.of(ok, String.join("; ", ev) + " (expected " + expected + ")");
        };
    }

    // ------------------------------------------------------------------ permissions

    static String octal(int mode) { return mode < 0 ? "missing" : String.format("%04o", mode); }

    /**
     * File must exist (unless optional), have no permission bits beyond maxMode,
     * and be owned by root. Group must be one of the allowed groups.
     */
    static Function<SystemContext, Result> perms(String file, int maxMode, boolean optional, String... groups) {
        return ctx -> {
            int m = ctx.mode(file);
            if (m < 0) return optional ? Result.na(file + " does not exist") : Result.fail(file + " is missing");
            String owner = ctx.owner(file), group = ctx.group(file);
            boolean modeOk = (m & 0777 & ~maxMode) == 0;
            boolean ownerOk = owner.equals("root");
            boolean groupOk = groups.length == 0 || Arrays.asList(groups).contains(group);
            String ev = String.format("%s is %s %s:%s (allowed: %s or stricter, root-owned%s)",
                    file, octal(m), owner, group, octal(maxMode),
                    groups.length == 0 ? "" : ", group " + String.join("/", groups));
            return Result.of(modeOk && ownerOk && groupOk, ev);
        };
    }

    // ------------------------------------------------------------------ services & packages

    /** Passes if none of the given packages are installed and none of the processes are running. */
    static Function<SystemContext, Result> notPresent(String[] packages, String[] units, String... processes) {
        return ctx -> {
            List<String> found = new ArrayList<>();
            boolean couldCheckPackages = false;
            for (String p : packages) {
                Boolean inst = ctx.packageInstalled(p);
                if (inst != null) couldCheckPackages = true;
                if (Boolean.TRUE.equals(inst)) found.add("package " + p + " installed");
            }
            for (String u : units) {
                if (ctx.serviceActive(u, processes)) { found.add(u + " running"); break; }
            }
            if (!found.isEmpty()) return Result.fail(String.join("; ", found));
            return Result.pass(couldCheckPackages
                    ? "Not installed: " + String.join(", ", packages)
                    : "No matching services running (package database unavailable)");
        };
    }

    // ------------------------------------------------------------------ mounts

    record Mount(String device, String point, String type, Set<String> options) {}

    static List<Mount> mounts(SystemContext ctx) {
        String src = ctx.rootDir().toString().equals("/") && ctx.exists("/proc/mounts") ? "/proc/mounts" : "/etc/fstab";
        List<Mount> out = new ArrayList<>();
        for (String l : ctx.configLines(src)) {
            String[] f = l.split("\\s+");
            if (f.length >= 4) out.add(new Mount(f[0], f[1], f[2], new HashSet<>(Arrays.asList(f[3].split(",")))));
        }
        return out;
    }

    static Optional<Mount> mount(SystemContext ctx, String point) {
        Mount last = null;
        for (Mount m : mounts(ctx)) if (m.point().equals(point)) last = m; // last mount on top wins
        return Optional.ofNullable(last);
    }

    static Function<SystemContext, Result> mountOptions(String point, String... required) {
        return ctx -> {
            Optional<Mount> m = mount(ctx, point);
            if (m.isEmpty()) return Result.fail(point + " is not a separate mount, so mount options can't be enforced");
            List<String> missing = new ArrayList<>();
            for (String r : required) if (!m.get().options().contains(r)) missing.add(r);
            return missing.isEmpty()
                    ? Result.pass(point + " mounted with " + String.join(",", required))
                    : Result.fail(point + " is missing mount options: " + String.join(", ", missing));
        };
    }

    // ------------------------------------------------------------------ passwd / shadow

    static List<String[]> passwd(SystemContext ctx) {
        List<String[]> out = new ArrayList<>();
        for (String l : ctx.lines("/etc/passwd")) {
            if (l.isBlank() || l.startsWith("#")) continue;
            String[] f = l.split(":", -1);
            if (f.length >= 7) out.add(f);
        }
        return out;
    }

    /** All lines of the sudoers configuration (main file + sudoers.d), comments removed. */
    static List<String> sudoers(SystemContext ctx) {
        List<String> all = new ArrayList<>(ctx.configLines("/etc/sudoers"));
        for (String f : ctx.glob("/etc/sudoers.d", "*")) {
            String name = f.substring(f.lastIndexOf('/') + 1);
            if (name.endsWith("~") || name.contains(".")) continue; // sudo ignores these
            all.addAll(ctx.configLines(f));
        }
        return all;
    }

    static List<String> pamFiles(SystemContext ctx, String debianFile, String rhelFile) {
        List<String> lines = new ArrayList<>(ctx.configLines("/etc/pam.d/" + debianFile));
        lines.addAll(ctx.configLines("/etc/pam.d/" + rhelFile));
        return lines;
    }
}
