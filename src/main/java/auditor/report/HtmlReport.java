package auditor.report;

import auditor.model.Check.Severity;
import auditor.model.Finding;
import auditor.model.Result.Status;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;

/**
 * Self-contained HTML audit report, laid out like a real IT audit deliverable:
 * scope, executive summary and rating, findings in Condition / Criteria / Risk /
 * Recommendation format, framework mapping, and the full control matrix.
 * Prints cleanly to PDF from any browser (Ctrl+P).
 */
public final class HtmlReport {

    private HtmlReport() {}

    public record Meta(String host, String os, boolean root, boolean commands, String auditedRoot) {}

    /** A previous run for before/after comparison. */
    public record Previous(String label, Score score, Map<String, String> statusById) {}

    public static void write(List<Finding> findings, Meta meta, Previous prev, Path file) throws IOException {
        Score s = Score.of(findings);
        StringBuilder h = new StringBuilder();
        String date = ZonedDateTime.now().format(DateTimeFormatter.ofPattern("MMMM d, yyyy 'at' h:mm a z"));

        h.append("""
                <!DOCTYPE html><html lang="en"><head><meta charset="utf-8">
                <meta name="viewport" content="width=device-width,initial-scale=1">
                <title>Security Configuration Audit Report</title><style>
                :root{--ink:#1c2430;--muted:#5d6b7a;--line:#e3e8ee;--soft:#f6f8fa;--brand:#1f4e79;
                --pass:#1e8e5a;--warn:#c98a00;--fail:#c8372d;--na:#8a96a3}
                *{box-sizing:border-box}body{margin:0;color:var(--ink);background:#fff;
                font:14.5px/1.55 "Segoe UI",-apple-system,Roboto,Helvetica,Arial,sans-serif}
                .wrap{max-width:1040px;margin:0 auto;padding:40px 28px 60px}
                header{border-bottom:3px solid var(--brand);padding-bottom:18px;margin-bottom:26px}
                .eyebrow{color:var(--brand);font-weight:700;letter-spacing:.08em;font-size:12px;text-transform:uppercase}
                h1{margin:6px 0 10px;font-size:28px}h2{font-size:19px;color:var(--brand);margin:38px 0 14px;
                padding-bottom:6px;border-bottom:1px solid var(--line)}h3{margin:0;font-size:15.5px}
                .meta{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:4px 24px;color:var(--muted);font-size:13px}
                .meta b{color:var(--ink);font-weight:600}
                .summary{display:grid;grid-template-columns:200px 1fr;gap:28px;align-items:center}
                @media(max-width:640px){.summary{grid-template-columns:1fr}}
                .stats{display:grid;grid-template-columns:repeat(4,1fr);gap:10px;margin-top:14px}
                .stat{background:var(--soft);border-radius:8px;padding:10px 12px}.stat b{font-size:22px;display:block}
                .stat span{font-size:12px;color:var(--muted)}
                .rating{display:inline-block;padding:3px 12px;border-radius:99px;font-weight:700;font-size:13px;color:#fff}
                .bars .row{display:grid;grid-template-columns:190px 1fr 70px;gap:12px;align-items:center;margin:8px 0;font-size:13.5px}
                .track{height:12px;background:var(--soft);border-radius:99px;overflow:hidden}
                .track i{display:block;height:100%;border-radius:99px}
                table{width:100%;border-collapse:collapse;font-size:13px}th,td{padding:8px 10px;border-bottom:1px solid var(--line);
                text-align:left;vertical-align:top}th{background:var(--soft);font-weight:600;color:var(--muted);font-size:12px;
                text-transform:uppercase;letter-spacing:.04em}
                .pill{display:inline-block;font-size:11px;font-weight:700;padding:2px 8px;border-radius:99px;color:#fff;white-space:nowrap}
                .PASS{background:var(--pass)}.WARN{background:var(--warn)}.FAIL{background:var(--fail)}
                .NOT_APPLICABLE{background:var(--na)}.ERROR{background:#6b4fa0}
                .HIGH{background:var(--fail)}.MEDIUM{background:var(--warn)}.LOW{background:#4a7fb5}
                .finding{border:1px solid var(--line);border-left:5px solid var(--fail);border-radius:8px;padding:16px 18px;margin:14px 0;break-inside:avoid}
                .finding.MEDIUMb{border-left-color:var(--warn)}.finding.LOWb{border-left-color:#4a7fb5}
                .finding .top{display:flex;gap:10px;align-items:center;flex-wrap:wrap;margin-bottom:10px}
                .finding .id{font-family:ui-monospace,Menlo,Consolas,monospace;color:var(--muted);font-size:12.5px}
                .grid{display:grid;grid-template-columns:150px 1fr;gap:6px 14px;font-size:13.5px}
                .grid dt{font-weight:600;color:var(--muted)}.grid dd{margin:0}
                code{font-family:ui-monospace,Menlo,Consolas,monospace;font-size:12.5px;background:var(--soft);padding:2px 5px;border-radius:4px;word-break:break-word}
                .note{background:#fff8e6;border:1px solid #f0d58a;border-radius:8px;padding:10px 14px;font-size:13px;margin:12px 0}
                .delta{font-size:26px;font-weight:700}.up{color:var(--pass)}.down{color:var(--fail)}
                .muted{color:var(--muted)}ul{margin:6px 0;padding-left:20px}
                @media print{.wrap{padding:0}h2{break-after:avoid}}
                </style></head><body><div class="wrap">
                """);

        // ---------------------------------------------------------------- header
        h.append("<header><div class='eyebrow'>Security Configuration Audit</div><h1>Linux Hardening Assessment</h1><div class='meta'>")
         .append("<div>Host: <b>").append(esc(meta.host())).append("</b></div>")
         .append("<div>Operating system: <b>").append(esc(meta.os())).append("</b></div>")
         .append("<div>Report date: <b>").append(date).append("</b></div>")
         .append("<div>Baseline: <b>CIS-based Linux controls (").append(findings.size()).append(")</b></div>")
         .append("</div></header>");

        if (!meta.root()) h.append("<div class='note'><b>Limited scope:</b> the audit ran without root privileges, so some controls "
                + "could not be evaluated (marked ERROR). Re-run with <code>sudo</code> for complete results.</div>");
        if (!meta.auditedRoot().equals("/")) h.append("<div class='note'><b>Offline audit</b> of <code>").append(esc(meta.auditedRoot()))
                .append("</code>: service and firewall checks are based on configuration files only.</div>");

        // ---------------------------------------------------------------- executive summary
        h.append("<h2>1. Executive Summary</h2><div class='summary'>").append(gauge(s.percent()))
         .append("<div><div style='margin-bottom:6px'>Overall rating: <span class='rating' style='background:")
         .append(ratingColor(s.percent())).append("'>").append(s.rating()).append("</span></div><p style='margin:6px 0'>")
         .append(summaryText(findings, s)).append("</p><div class='stats'>")
         .append(stat(s.pass(), "Passed", "var(--pass)")).append(stat(s.fail(), "Failed", "var(--fail)"))
         .append(stat(s.warn(), "Partial", "var(--warn)")).append(stat(s.na() + s.error(), "Not applicable / not evaluated", "var(--na)"))
         .append("</div></div></div>");

        // ---------------------------------------------------------------- comparison
        int section = 2;
        if (prev != null) {
            h.append("<h2>").append(section++).append(". Before vs. After</h2>");
            double d = s.percent() - prev.score().percent();
            h.append("<div style='display:flex;gap:40px;flex-wrap:wrap;align-items:center'>")
             .append("<div><div class='muted'>Previous (").append(esc(prev.label())).append(")</div><div class='delta'>")
             .append(pct(prev.score().percent())).append("</div></div>")
             .append("<div><div class='muted'>Current</div><div class='delta'>").append(pct(s.percent())).append("</div></div>")
             .append("<div><div class='muted'>Change</div><div class='delta ").append(d >= 0 ? "up" : "down").append("'>")
             .append(d >= 0 ? "+" : "").append(String.format("%.1f pts", d)).append("</div></div></div>");

            List<String> fixed = new ArrayList<>(), regressed = new ArrayList<>();
            for (Finding f : findings) {
                String before = prev.statusById().get(f.check().id());
                if (before == null) continue;
                boolean wasBad = before.equals("FAIL") || before.equals("WARN");
                boolean isBad = f.status() == Status.FAIL || f.status() == Status.WARN;
                String label = "<code>" + f.check().id() + "</code> " + esc(f.check().title()) + " <span class='muted'>(" + before + " &rarr; " + f.status() + ")</span>";
                if (wasBad && f.status() == Status.PASS) fixed.add(label);
                if (before.equals("PASS") && isBad) regressed.add(label);
            }
            h.append("<p><b>Remediated (").append(fixed.size()).append("):</b></p>").append(list(fixed, "None"));
            h.append("<p><b>Regressed (").append(regressed.size()).append("):</b></p>").append(list(regressed, "None"));
        }

        // ---------------------------------------------------------------- by category
        h.append("<h2>").append(section++).append(". Compliance by Category</h2><div class='bars'>");
        Map<String, List<Finding>> byCat = new LinkedHashMap<>();
        for (Finding f : findings) byCat.computeIfAbsent(f.check().category(), k -> new ArrayList<>()).add(f);
        for (var e : byCat.entrySet()) {
            Score cs = Score.of(e.getValue());
            String col = cs.applicable() == 0 ? "var(--na)" : ratingColor(cs.percent());
            h.append("<div class='row'><div>").append(e.getKey()).append("</div><div class='track'><i style='width:")
             .append(String.format(Locale.ROOT, "%.1f", cs.percent())).append("%;background:").append(col).append("'></i></div><div>")
             .append(cs.applicable() == 0 ? "n/a" : pct(cs.percent())).append(" <span class='muted' style='font-size:11px'>")
             .append(cs.pass()).append("/").append(cs.applicable()).append("</span></div></div>");
        }
        h.append("</div>");

        // ---------------------------------------------------------------- findings
        List<Finding> issues = findings.stream()
                .filter(f -> f.status() == Status.FAIL || f.status() == Status.WARN)
                .sorted(Comparator.comparing((Finding f) -> f.check().severity()).reversed()
                        .thenComparing(f -> f.status() == Status.WARN)
                        .thenComparing(f -> f.check().id()))
                .toList();
        h.append("<h2>").append(section++).append(". Detailed Findings (").append(issues.size()).append(")</h2>");
        h.append("<p class='muted'>Each finding uses the standard audit structure: what we observed (condition), "
                + "what it should be (criteria), why it matters (risk), and how to fix it (recommendation). "
                + "Ordered by risk rating.</p>");
        if (issues.isEmpty()) h.append("<p>No findings: every applicable control passed.</p>");
        for (Finding f : issues) {
            var c = f.check();
            h.append("<div class='finding ").append(c.severity()).append("b'><div class='top'>")
             .append("<span class='pill ").append(c.severity()).append("'>").append(c.severity()).append(" RISK</span>")
             .append("<span class='pill ").append(f.status()).append("'>").append(f.status() == Status.WARN ? "PARTIAL" : "FAIL").append("</span>")
             .append("<span class='id'>").append(c.id()).append("</span><h3>").append(esc(c.title())).append("</h3></div><dl class='grid'>")
             .append("<dt>Condition</dt><dd>").append(esc(f.result().evidence())).append("</dd>")
             .append("<dt>Criteria</dt><dd>").append(esc(c.criteria())).append("</dd>")
             .append("<dt>Risk</dt><dd>").append(esc(c.risk())).append("</dd>")
             .append("<dt>Recommendation</dt><dd><code>").append(esc(c.remediation())).append("</code></dd>")
             .append("<dt>Framework</dt><dd>NIST CSF ").append(c.nist()).append(" &middot; ISO 27001 ").append(esc(c.iso())).append("</dd>")
             .append("</dl></div>");
        }

        List<Finding> errors = findings.stream().filter(f -> f.status() == Status.ERROR).toList();
        if (!errors.isEmpty()) {
            h.append("<h2>").append(section++).append(". Controls Not Evaluated (").append(errors.size()).append(")</h2><table><tr><th>ID</th><th>Control</th><th>Reason</th></tr>");
            for (Finding f : errors) h.append("<tr><td><code>").append(f.check().id()).append("</code></td><td>")
                    .append(esc(f.check().title())).append("</td><td>").append(esc(f.result().evidence())).append("</td></tr>");
            h.append("</table>");
        }

        // ---------------------------------------------------------------- framework mapping
        h.append("<h2>").append(section++).append(". NIST CSF 2.0 Coverage</h2><table><tr><th>Subcategory</th><th>Controls</th><th>Passed</th><th>Failed / partial</th><th>Score</th></tr>");
        Map<String, List<Finding>> byNist = new TreeMap<>();
        for (Finding f : findings) byNist.computeIfAbsent(f.check().nist(), k -> new ArrayList<>()).add(f);
        for (var e : byNist.entrySet()) {
            Score ns = Score.of(e.getValue());
            h.append("<tr><td><b>").append(e.getKey()).append("</b> <span class='muted'>").append(NIST_NAMES.getOrDefault(e.getKey(), ""))
             .append("</span></td><td>").append(e.getValue().size()).append("</td><td>").append(ns.pass()).append("</td><td>")
             .append(ns.fail() + ns.warn()).append("</td><td>").append(ns.applicable() == 0 ? "n/a" : pct(ns.percent())).append("</td></tr>");
        }
        h.append("</table>");

        // ---------------------------------------------------------------- full matrix
        h.append("<h2>").append(section++).append(". Control Matrix</h2><table><tr><th>ID</th><th>Control</th><th>Risk</th><th>Result</th><th>Evidence</th></tr>");
        for (Finding f : findings) {
            h.append("<tr><td><code>").append(f.check().id()).append("</code></td><td>").append(esc(f.check().title()))
             .append("</td><td><span class='pill ").append(f.check().severity()).append("'>").append(f.check().severity())
             .append("</span></td><td><span class='pill ").append(f.status()).append("'>")
             .append(f.status() == Status.NOT_APPLICABLE ? "N/A" : f.status()).append("</span></td><td class='muted'>")
             .append(esc(f.result().evidence())).append("</td></tr>");
        }
        h.append("</table>");

        // ---------------------------------------------------------------- methodology
        h.append("<h2>").append(section).append(". Scope &amp; Methodology</h2><ul>")
         .append("<li>Automated, <b>read-only</b> assessment: the tool reads configuration files, kernel parameters and file permissions and runs query-only commands. It changes nothing on the system.</li>")
         .append("<li>Controls are based on CIS Benchmark recommendations for Linux and mapped to NIST CSF 2.0 and ISO/IEC 27001:2022 Annex A.</li>")
         .append("<li>Scoring is weighted by risk (High = 3, Medium = 2, Low = 1). Partial results earn half credit. Not-applicable and not-evaluated controls are excluded.</li>")
         .append("<li>Ratings: Strong &ge; 90%, Satisfactory 75&ndash;89%, Needs Improvement 50&ndash;74%, Unsatisfactory &lt; 50%.</li>")
         .append("<li>Limitations: point-in-time snapshot, a subset of the full CIS Benchmark, and no review of application-level security or of policies and procedures. Some legitimate configurations (for example IP forwarding on a Docker host) should be documented as accepted risks rather than fixed.</li>")
         .append("<li>Privileges: ").append(meta.root() ? "run as root (complete evaluation)" : "run as a standard user (partial evaluation)").append(".</li>")
         .append("</ul></div></body></html>");

        Files.writeString(file, h.toString());
    }

    private static final Map<String, String> NIST_NAMES = Map.of(
            "PR.AA-01", "Identities & credentials managed", "PR.AA-03", "Users & services authenticated",
            "PR.AA-05", "Least-privilege access enforced", "PR.PS-01", "Configuration management applied",
            "PR.PS-02", "Software maintained & patched", "PR.PS-04", "Log records generated",
            "PR.PS-05", "Unauthorized software prevented", "PR.IR-01", "Networks protected from unauthorized access",
            "PR.DS-01", "Data at rest protected", "DE.CM-09", "Computing environment monitored");

    private static String summaryText(List<Finding> findings, Score s) {
        long highFails = findings.stream().filter(f -> f.status() == Status.FAIL && f.check().severity() == Severity.HIGH).count();
        long medFails = findings.stream().filter(f -> f.status() == Status.FAIL && f.check().severity() == Severity.MEDIUM).count();
        StringBuilder t = new StringBuilder();
        t.append(String.format("Of %d applicable controls, %d passed, %d partially met the criteria and %d failed, for a risk-weighted compliance score of <b>%s</b>. ",
                s.applicable(), s.pass(), s.warn(), s.fail(), pct(s.percent())));
        if (highFails > 0) t.append(String.format("<b>%d high-risk finding%s</b> should be remediated as a priority", highFails, highFails == 1 ? "" : "s"));
        else t.append("No high-risk controls failed");
        t.append(medFails > 0 ? String.format(", followed by %d medium-risk item%s.", medFails, medFails == 1 ? "" : "s") : ".");
        Map<String, Integer> catFails = new TreeMap<>();
        for (Finding f : findings) if (f.status() == Status.FAIL) catFails.merge(f.check().category(), 1, Integer::sum);
        catFails.entrySet().stream().max(Map.Entry.comparingByValue()).ifPresent(e ->
                t.append(" The most findings were in <b>").append(e.getKey()).append("</b> (").append(e.getValue()).append(")."));
        return t.toString();
    }

    private static String gauge(double p) {
        double r = 80, c = 2 * Math.PI * r, filled = c * p / 100;
        return String.format(Locale.ROOT, "<svg viewBox='0 0 200 200' width='190' role='img' aria-label='Score %.0f%%'>"
                + "<circle cx='100' cy='100' r='%.0f' fill='none' stroke='#eef1f4' stroke-width='18'/>"
                + "<circle cx='100' cy='100' r='%.0f' fill='none' stroke='%s' stroke-width='18' stroke-linecap='round' "
                + "stroke-dasharray='%.1f %.1f' transform='rotate(-90 100 100)'/>"
                + "<text x='100' y='108' text-anchor='middle' font-size='38' font-weight='700' fill='#1c2430'>%.0f%%</text>"
                + "<text x='100' y='132' text-anchor='middle' font-size='12' fill='#5d6b7a'>compliance</text></svg>",
                p, r, r, ratingColor(p).replace("var(--pass)", "#1e8e5a").replace("var(--warn)", "#c98a00").replace("var(--fail)", "#c8372d"),
                filled, c, p);
    }

    private static String ratingColor(double p) {
        return p >= 75 ? "var(--pass)" : p >= 50 ? "var(--warn)" : "var(--fail)";
    }

    private static String stat(int n, String label, String color) {
        return "<div class='stat'><b style='color:" + color + "'>" + n + "</b><span>" + label + "</span></div>";
    }

    private static String list(List<String> items, String empty) {
        if (items.isEmpty()) return "<p class='muted'>" + empty + "</p>";
        StringBuilder sb = new StringBuilder("<ul>");
        for (String i : items) sb.append("<li>").append(i).append("</li>");
        return sb.append("</ul>").toString();
    }

    private static String pct(double p) { return String.format("%.0f%%", p); }

    static String esc(String s) {
        return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;");
    }
}
