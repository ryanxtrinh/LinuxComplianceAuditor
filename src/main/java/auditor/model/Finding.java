package auditor.model;

/** A check together with its result: one row in the audit report. */
public record Finding(Check check, Result result) {
    public Result.Status status() { return result.status(); }
}
