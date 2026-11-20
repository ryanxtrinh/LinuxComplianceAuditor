package auditor;

import auditor.system.SystemContext;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;

/**
 * Builds a throwaway directory that looks like a Linux root filesystem, so checks
 * can be exercised the same way as "--root /mnt/image" without touching the real system.
 */
public final class FakeRoot {

    private final Path dir;

    public FakeRoot() {
        try { dir = Files.createTempDirectory("fakeroot"); }
        catch (IOException e) { throw new UncheckedIOException(e); }
    }

    public FakeRoot file(String abs, String... lines) {
        try {
            Path p = dir.resolve(abs.substring(1));
            Files.createDirectories(p.getParent());
            Files.writeString(p, String.join("\n", lines) + "\n");
            return this;
        } catch (IOException e) { throw new UncheckedIOException(e); }
    }

    public Path path() { return dir; }

    /** Commands disabled, exactly like --root mode. */
    public SystemContext context() { return new SystemContext(dir, false); }
}
