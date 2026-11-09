package auditor.report;

import auditor.model.Check.Severity;
import auditor.model.Finding;
import auditor.model.Result.Status;

import java.util.List;

/**
 * Weighted compliance score.
 *
 *   Each applicable control is worth its severity weight: HIGH 3, MEDIUM 2, LOW 1.
 *   PASS earns the full weight, WARN half, FAIL nothing.
 *   NOT_APPLICABLE and ERROR are left out of the calculation entirely.
 *
 * Weighting matters: fixing one HIGH finding should move the score more than fixing
 * one cosmetic LOW finding, just as it would in a real audit rating.
 */
public record Score(double percent, int pass, int warn, int fail, int na, int error) {

    public static Score of(List<Finding> findings) {
        double earned = 0, possible = 0;
        int p = 0, w = 0, f = 0, na = 0, e = 0;
        for (Finding x : findings) {
            int weight = x.check().severity().weight;
            switch (x.status()) {
                case PASS -> { p++; earned += weight; possible += weight; }
                case WARN -> { w++; earned += weight / 2.0; possible += weight; }
                case FAIL -> { f++; possible += weight; }
                case NOT_APPLICABLE -> na++;
                case ERROR -> e++;
            }
        }
        return new Score(possible == 0 ? 0 : 100 * earned / possible, p, w, f, na, e);
    }

    /** Recompute from a saved CSV (id, severity, status). */
    public static Score ofRows(List<String[]> rows) {
        double earned = 0, possible = 0;
        int p = 0, w = 0, f = 0, na = 0, e = 0;
        for (String[] r : rows) {
            int weight = Severity.valueOf(r[3]).weight;
            switch (Status.valueOf(r[4])) {
                case PASS -> { p++; earned += weight; possible += weight; }
                case WARN -> { w++; earned += weight / 2.0; possible += weight; }
                case FAIL -> { f++; possible += weight; }
                case NOT_APPLICABLE -> na++;
                case ERROR -> e++;
            }
        }
        return new Score(possible == 0 ? 0 : 100 * earned / possible, p, w, f, na, e);
    }

    public int applicable() { return pass + warn + fail; }

    /** Audit-style overall rating. */
    public String rating() {
        if (percent >= 90) return "Strong";
        if (percent >= 75) return "Satisfactory";
        if (percent >= 50) return "Needs Improvement";
        return "Unsatisfactory";
    }
}
