package auditor.model;

/**
 * Outcome of a single check. "evidence" is what we actually observed on the system:
 * auditors never accept a pass or fail without evidence.
 */
public record Result(Status status, String evidence) {

    public enum Status {
        PASS,            // control in place
        FAIL,            // control missing or misconfigured
        WARN,            // partially in place / weaker than recommended
        NOT_APPLICABLE,  // e.g. SSH checks on a machine without an SSH server
        ERROR            // couldn't evaluate (usually: re-run with sudo)
    }

    public static Result pass(String ev)  { return new Result(Status.PASS, ev); }
    public static Result fail(String ev)  { return new Result(Status.FAIL, ev); }
    public static Result warn(String ev)  { return new Result(Status.WARN, ev); }
    public static Result na(String ev)    { return new Result(Status.NOT_APPLICABLE, ev); }
    public static Result error(String ev) { return new Result(Status.ERROR, ev); }

    public static Result of(boolean ok, String ev) { return ok ? pass(ev) : fail(ev); }
}
