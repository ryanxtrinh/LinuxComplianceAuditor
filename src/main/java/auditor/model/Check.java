package auditor.model;

import auditor.system.SystemContext;

import java.util.function.Function;

/**
 * One security control to test.
 *
 * Written the way an auditor documents a control:
 *   criteria     - what "good" looks like (the standard we test against)
 *   risk         - what can go wrong if the control fails
 *   remediation  - how to fix it
 *   nist / iso   - which framework requirements this control supports
 */
public record Check(
        String id,
        String category,
        String title,
        Severity severity,
        String criteria,
        String risk,
        String remediation,
        String nist,   // NIST Cybersecurity Framework 2.0 subcategory
        String iso,    // ISO/IEC 27001:2022 Annex A control
        Function<SystemContext, Result> test
) {
    public enum Severity {
        LOW(1), MEDIUM(2), HIGH(3);
        public final int weight;
        Severity(int w) { weight = w; }
    }
}
