package auditor.report;

import auditor.model.Check;
import auditor.model.Check.Severity;
import auditor.model.Finding;
import auditor.model.Result;
import auditor.model.Result.Status;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class ScoreTest {

    private static Finding f(Severity sev, Status status) {
        Check c = new Check("T-01", "Test", "t", sev, "c", "r", "fix", "PR.PS-01", "A.8.9 x", ctx -> null);
        return new Finding(c, new Result(status, "evidence"));
    }

    @Test
    void severityWeightsTheScore() {
        // HIGH pass (3/3) + LOW fail (0/1) = 75%
        Score s = Score.of(List.of(f(Severity.HIGH, Status.PASS), f(Severity.LOW, Status.FAIL)));
        assertEquals(75.0, s.percent(), 1e-9);
        // Same counts, reversed severities = 25%
        Score r = Score.of(List.of(f(Severity.HIGH, Status.FAIL), f(Severity.LOW, Status.PASS)));
        assertEquals(25.0, r.percent(), 1e-9);
    }

    @Test
    void warnEarnsHalfCredit() {
        Score s = Score.of(List.of(f(Severity.MEDIUM, Status.WARN)));
        assertEquals(50.0, s.percent(), 1e-9);
        assertEquals(1, s.warn());
    }

    @Test
    void notApplicableAndErrorAreExcluded() {
        Score s = Score.of(List.of(
                f(Severity.HIGH, Status.PASS),
                f(Severity.HIGH, Status.NOT_APPLICABLE),
                f(Severity.HIGH, Status.ERROR)));
        assertEquals(100.0, s.percent(), 1e-9);
        assertEquals(1, s.applicable());
        assertEquals(1, s.na());
        assertEquals(1, s.error());
    }

    @Test
    void nothingApplicableScoresZero() {
        assertEquals(0.0, Score.of(List.of()).percent(), 1e-9);
        assertEquals(0.0, Score.of(List.of(f(Severity.LOW, Status.NOT_APPLICABLE))).percent(), 1e-9);
    }

    @Test
    void ratingBands() {
        assertEquals("Strong", new Score(90, 0, 0, 0, 0, 0).rating());
        assertEquals("Satisfactory", new Score(89.9, 0, 0, 0, 0, 0).rating());
        assertEquals("Satisfactory", new Score(75, 0, 0, 0, 0, 0).rating());
        assertEquals("Needs Improvement", new Score(50, 0, 0, 0, 0, 0).rating());
        assertEquals("Unsatisfactory", new Score(49.9, 0, 0, 0, 0, 0).rating());
    }

    @Test
    void scoreFromCsvRowsMatchesScoreFromFindings() {
        List<Finding> findings = List.of(
                f(Severity.HIGH, Status.PASS), f(Severity.MEDIUM, Status.WARN),
                f(Severity.LOW, Status.FAIL), f(Severity.MEDIUM, Status.NOT_APPLICABLE));
        List<String[]> rows = new ArrayList<>();
        for (Finding x : findings)
            rows.add(new String[]{"T-01", "Test", "t", x.check().severity().name(), x.status().name()});
        assertEquals(Score.of(findings), Score.ofRows(rows));
    }
}
