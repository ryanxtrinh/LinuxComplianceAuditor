package auditor.system;

/** Thrown when a file can't be read without root, e.g. /etc/shadow. */
public class NeedsRootException extends RuntimeException {
    private static final long serialVersionUID = 1L;
    public NeedsRootException(String path) {
        super("Permission denied reading " + path + " (re-run with sudo)");
    }
}
