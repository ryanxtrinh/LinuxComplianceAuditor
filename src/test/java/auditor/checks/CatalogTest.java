package auditor.checks;

import auditor.model.Check;
import org.junit.jupiter.api.Test;

import java.util.HashSet;
import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

/** Guards the control catalog itself: every control must be fully documented like an audit workpaper. */
class CatalogTest {

    private final List<Check> all = Catalog.all();

    @Test
    void hasSixtyThreeControls() {
        assertEquals(63, all.size());
    }

    @Test
    void idsAreUniqueAndWellFormed() {
        Set<String> seen = new HashSet<>();
        for (Check c : all) {
            assertTrue(c.id().matches("[A-Z]{2,3}-\\d{2}"), "bad id " + c.id());
            assertTrue(seen.add(c.id()), "duplicate id " + c.id());
        }
    }

    @Test
    void everyControlIsFullyDocumented() {
        for (Check c : all) {
            String id = c.id();
            assertFalse(c.category().isBlank(), id + " category");
            assertFalse(c.title().isBlank(), id + " title");
            assertFalse(c.criteria().isBlank(), id + " criteria");
            assertTrue(c.risk().length() > 20, id + " needs a real risk statement");
            assertFalse(c.remediation().isBlank(), id + " remediation");
            assertNotNull(c.severity(), id + " severity");
            assertNotNull(c.test(), id + " test");
        }
    }

    @Test
    void frameworkMappingsUseRealIdentifiers() {
        for (Check c : all) {
            assertTrue(c.nist().matches("(GV|ID|PR|DE|RS|RC)\\.[A-Z]{2}-\\d{2}"),
                    c.id() + " has bad NIST CSF 2.0 ref: " + c.nist());
            assertTrue(c.iso().matches("A\\.[5-8]\\.\\d+ .+"),
                    c.id() + " has bad ISO 27001:2022 Annex A ref: " + c.iso());
        }
    }

    @Test
    void catalogCannotBeModified() {
        assertThrows(UnsupportedOperationException.class, () -> all.remove(0));
    }
}
