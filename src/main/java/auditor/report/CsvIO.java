package auditor.report;

import auditor.model.Finding;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

/**
 * findings.csv: opens in Excel, and is used as the "before" snapshot for --compare.
 * Columns: id, category, title, severity, status, evidence, nist, iso
 */
public final class CsvIO {

    private CsvIO() {}

    public static void write(List<Finding> findings, Path file) throws IOException {
        StringBuilder sb = new StringBuilder("id,category,title,severity,status,evidence,nist_csf,iso_27001\n");
        for (Finding f : findings) {
            var c = f.check();
            sb.append(String.join(",", c.id(), q(c.category()), q(c.title()), c.severity().name(),
                    f.status().name(), q(f.result().evidence()), c.nist(), q(c.iso()))).append('\n');
        }
        Files.writeString(file, sb.toString());
    }

    private static String q(String s) { return "\"" + s.replace("\"", "\"\"") + "\""; }

    public static List<String[]> read(Path file) throws IOException {
        List<String[]> rows = new ArrayList<>();
        List<String> lines = Files.readAllLines(file);
        for (int i = 1; i < lines.size(); i++) {
            if (lines.get(i).isBlank()) continue;
            rows.add(parse(lines.get(i)).toArray(String[]::new));
        }
        return rows;
    }

    /** Minimal RFC 4180 parser: handles quoted fields and doubled quotes. */
    private static List<String> parse(String line) {
        List<String> out = new ArrayList<>();
        StringBuilder cur = new StringBuilder();
        boolean inQ = false;
        for (int i = 0; i < line.length(); i++) {
            char ch = line.charAt(i);
            if (inQ) {
                if (ch == '"' && i + 1 < line.length() && line.charAt(i + 1) == '"') { cur.append('"'); i++; }
                else if (ch == '"') inQ = false;
                else cur.append(ch);
            } else if (ch == '"') inQ = true;
            else if (ch == ',') { out.add(cur.toString()); cur.setLength(0); }
            else cur.append(ch);
        }
        out.add(cur.toString());
        return out;
    }
}
