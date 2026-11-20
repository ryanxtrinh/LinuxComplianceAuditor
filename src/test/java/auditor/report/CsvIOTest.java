package auditor.report;

import auditor.model.Check;
import auditor.model.Check.Severity;
import auditor.model.Finding;
import auditor.model.Result;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class CsvIOTest {

    @Test
    void roundTripsFieldsWithCommasAndQuotes() throws IOException {
        Check c = new Check("SSH-01", "SSH Server", "Root login, over \"SSH\"", Severity.HIGH,
                "c", "r", "fix", "PR.AA-05", "A.8.2 Privileged access rights", ctx -> null);
        Finding f = new Finding(c, Result.fail("PermitRootLogin = yes, set in \"sshd_config\""));

        Path file = Files.createTempFile("findings", ".csv");
        CsvIO.write(List.of(f), file);

        assertTrue(Files.readString(file).startsWith("id,category,title,severity,status,evidence,nist_csf,iso_27001\n"));

        List<String[]> rows = CsvIO.read(file);
        assertEquals(1, rows.size());
        String[] r = rows.get(0);
        assertEquals(8, r.length);
        assertEquals("SSH-01", r[0]);
        assertEquals("Root login, over \"SSH\"", r[2]);
        assertEquals("HIGH", r[3]);
        assertEquals("FAIL", r[4]);
        assertEquals("PermitRootLogin = yes, set in \"sshd_config\"", r[5]);
        assertEquals("A.8.2 Privileged access rights", r[7]);
    }

    @Test
    void blankLinesAreSkipped() throws IOException {
        Path file = Files.createTempFile("findings", ".csv");
        Files.writeString(file, "header\nA-01,x,y,LOW,PASS,e,n,i\n\n\nA-02,x,y,HIGH,FAIL,e,n,i\n");
        assertEquals(2, CsvIO.read(file).size());
    }
}
