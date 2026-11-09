package auditor;

import auditor.checks.Catalog;
import auditor.model.Check;
import auditor.model.Finding;
import auditor.model.Result;
import auditor.model.Result.Status;
import auditor.report.CsvIO;
import auditor.report.HtmlReport;
import auditor.report.Score;
import auditor.system.NeedsRootException;
import auditor.system.SystemContext;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.*;

/**
 * Linux Security Compliance Auditor.
 *
 *   sudo java -jar auditor.jar                         audit this machine
 *   sudo java -jar auditor.jar --compare before.csv    show what changed since an earlier run
 *   java -jar auditor.jar --list                       list every control
 */
public class Main {

    private static final String RESET = "\u001B[0m", RED = "\u001B[31m", GREEN = "\u001B[32m",
            YELLOW = "\u001B[33m", GREY = "\u001B[90m", PURPLE = "\u001B[35m", BOLD = "\u001B[1m";

    public static void main(String[] args) throws Exception {
        Path out = Path.of("audit-output"), root = Path.of("/"), compare = null;
        boolean commands = true, color = System.console() != null;
        String only = null;

        for (int i = 0; i < args.length; i++) {
            switch (args[i]) {
                case "--out" -> out = Path.of(args[++i]);
                case "--compare" -> compare = Path.of(args[++i]);
                case "--root" -> root = Path.of(args[++i]).toAbsolutePath();
                case "--no-commands" -> commands = false;
                case "--category" -> only = args[++i];
                case "--no-color" -> color = false;
                case "--list" -> { list(); return; }
                case "-h", "--help" -> { usage(); return; }
                default -> { System.err.println("Unknown option: " + args[i]); usage(); System.exit(2); }
            }
        }

        SystemContext ctx = new SystemContext(root, commands);
        System.out.println(b(color, BOLD) + "Linux Security Compliance Auditor" + b(color, RESET));
        System.out.println("Target: " + ctx.hostname() + " (" + ctx.osName() + ")" + (root.toString().equals("/") ? "" : " at " + root));
        if (!ctx.isRoot()) System.out.println(b(color, YELLOW)
                + "Not running as root: some controls can't be evaluated. Use sudo for a complete audit." + b(color, RESET));
        System.out.println();

        List<Finding> findings = new ArrayList<>();
        String lastCat = "";
        for (Check c : Catalog.all()) {
            if (only != null && !c.category().toLowerCase().contains(only.toLowerCase())) continue;
            if (!c.category().equals(lastCat)) {
                System.out.println(b(color, BOLD) + c.category() + b(color, RESET));
                lastCat = c.category();
            }
            Result r;
            try {
                r = c.test().apply(ctx);
            } catch (NeedsRootException e) {
                r = Result.error(e.getMessage());
            } catch (RuntimeException e) {
                r = Result.error("Check failed to run: " + e);
            }
            findings.add(new Finding(c, r));
            System.out.printf("  %s %-7s%s %-6s %s%n", statusColor(color, r.status()), label(r.status()), b(color, RESET),
                    c.id(), c.title());
        }

        Score s = Score.of(findings);
        HtmlReport.Previous prev = null;
        if (compare != null) {
            List<String[]> rows = CsvIO.read(compare);
            Map<String, String> byId = new HashMap<>();
            for (String[] r : rows) byId.put(r[0], r[4]);
            prev = new HtmlReport.Previous(compare.getFileName().toString(), Score.ofRows(rows), byId);
        }

        Files.createDirectories(out);
        CsvIO.write(findings, out.resolve("findings.csv"));
        HtmlReport.write(findings, new HtmlReport.Meta(ctx.hostname(), ctx.osName(), ctx.isRoot(), ctx.commandsAllowed(),
                root.toString()), prev, out.resolve("report.html"));

        System.out.println();
        System.out.printf("%sCompliance score: %.0f%% (%s)%s%n", b(color, BOLD), s.percent(), s.rating(), b(color, RESET));
        System.out.printf("  %d passed, %d partial, %d failed, %d not applicable, %d not evaluated%n",
                s.pass(), s.warn(), s.fail(), s.na(), s.error());
        if (prev != null) System.out.printf("  Previous run: %.0f%%  ->  change %+.1f points%n",
                prev.score().percent(), s.percent() - prev.score().percent());
        System.out.println("\nReport:   " + out.resolve("report.html"));
        System.out.println("Findings: " + out.resolve("findings.csv")
                + "   (keep this, and pass it to --compare after you harden the system)");
    }

    private static String label(Status s) {
        return switch (s) { case PASS -> "PASS"; case FAIL -> "FAIL"; case WARN -> "PARTIAL"; case NOT_APPLICABLE -> "N/A"; case ERROR -> "ERROR"; };
    }

    private static String statusColor(boolean color, Status s) {
        if (!color) return "";
        return switch (s) { case PASS -> GREEN; case FAIL -> RED; case WARN -> YELLOW; case NOT_APPLICABLE -> GREY; case ERROR -> PURPLE; };
    }

    private static String b(boolean color, String code) { return color ? code : ""; }

    private static void list() {
        String cat = "";
        for (Check c : Catalog.all()) {
            if (!c.category().equals(cat)) { System.out.println("\n" + c.category()); cat = c.category(); }
            System.out.printf("  %-7s %-6s %-55s NIST %-9s %s%n", c.id(), c.severity(), c.title(), c.nist(), c.iso());
        }
        System.out.println("\n" + Catalog.all().size() + " controls");
    }

    private static void usage() {
        System.out.println("""
                Linux Security Compliance Auditor (read-only, changes nothing)

                Usage:  sudo java -jar auditor.jar [options]

                Options:
                  --out <dir>          Output folder (default: audit-output)
                  --compare <csv>      Earlier findings.csv for a before/after comparison
                  --category <name>    Only run one category, e.g. --category ssh
                  --root <dir>         Audit a mounted disk image / folder instead of /
                  --no-commands        Don't run any system commands (file checks only)
                  --list               List all controls and their framework mappings
                  --no-color           Plain console output
                """);
    }
}
