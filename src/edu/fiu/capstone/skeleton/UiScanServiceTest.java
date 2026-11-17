package edu.fiu.capstone.skeleton;

import edu.fiu.capstone.ui.ScanService;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Checks the UI's scan service. Corpus expectations are derived, never hard-coded, so adding labeled samples
 * does not break this test: the UI must agree with DetectionEvaluation and with the EXPECT_* labels themselves.
 * Lives in this package because DetectionEvaluation.evaluate is package-private.
 * Run from the repository root: java -cp out edu.fiu.capstone.skeleton.UiScanServiceTest
 */
public final class UiScanServiceTest {
    private static int failures;

    public static void main(String[] args) throws Exception {
        Path root = Path.of("").toAbsolutePath();
        ScanService service = new ScanService();
        Map<String, ScanService.Score> corpus = service.corpusScores(root);

        checkCorpus(root, corpus.get("sql"), "sqli", new RegexSqliLens(), "EXPECT_SQLI");
        checkCorpus(root, corpus.get("command"), "command", new CommandInjectionLens(), "EXPECT_COMMAND");

        // Fixed expectations are fine here: this input and its answer are both defined by the test itself.
        String vulnerable = """
                class Dao {
                    java.sql.ResultSet find(java.sql.Connection connection, String name) throws Exception {
                        java.sql.Statement stmt = connection.createStatement();
                        // EXPECT_SQLI
                        java.sql.ResultSet rs = stmt.executeQuery("SELECT * FROM users WHERE name = '" + name + "'");
                        return rs;
                    }
                    void run(String input) throws Exception {
                        new ProcessBuilder("/bin/sh", "-c", "ls " + input).start(); // EXPECT_COMMAND
                    }
                    void safe(String input) throws Exception {
                        new ProcessBuilder("printf", "%s", input).start();
                    }
                }
                """;
        ScanService.Report report = service.scan(Map.of("Dao.java", vulnerable), Map.of());
        check("two findings", report.items().size() == 2, report.items());
        check("SQL finding has a repair proposal", report.items().stream()
                .anyMatch(i -> i.finding().cwe().equals("CWE-89") && i.outcome().isPatched()), report.items());
        check("command finding needs a human", report.items().stream()
                .anyMatch(i -> i.finding().cwe().equals("CWE-78") && !i.outcome().isPatched() && !i.guidance().isBlank()), report.items());
        check("labeled scan scores", new ScanService.Score(1, 0, 2, 0).equals(report.scores().get("sql"))
                && new ScanService.Score(1, 0, 2, 0).equals(report.scores().get("command")), report.scores());

        check("per-method cases name the method and its lines", report.cases().stream().anyMatch(c -> c.category().equals("sql")
                && c.method().equals("Dao.find") && c.outcome().equals("tp") && c.firstLine() == 2 && c.lastLine() == 7), report.cases());
        check("safe method is a true negative in both categories", report.cases().stream()
                .filter(c -> c.method().equals("Dao.safe") && c.outcome().equals("tn")).count() == 2, report.cases());

        Map<String, String> resources = new LinkedHashMap<>();
        ScanService.addResource(resources, "app/src/main/resources/db.properties", "x=1");
        check("resources/ files also get their classpath name", "x=1".equals(resources.get("db.properties")), resources.keySet());

        ScanService.Report unlabeled = service.scan(Map.of("A.java", "class A { void f() {} }"), Map.of());
        check("unlabeled scan has no scores", unlabeled.scores().isEmpty(), unlabeled.scores());

        Map<String, String> sources = new LinkedHashMap<>();
        ScanService.read(root, root.resolve("samples/command"), sources, new LinkedHashMap<>());
        check("directory keys are repository-relative", sources.containsKey("samples/command/CommandSamples.java"), sources.keySet());

        if (failures > 0) throw new AssertionError(failures + " UI scan check(s) failed");
        System.out.println("PASS: UI scan service matches DetectionEvaluation and sample labels");
    }

    /** The UI's corpus score must equal the team evaluator's, and its positives must equal the human labels. */
    private static void checkCorpus(Path root, ScanService.Score ui, String directory, SecurityLens lens, String marker)
            throws Exception {
        Path samples = root.resolve("samples").resolve(directory);
        DetectionEvaluation.Score expected = DetectionEvaluation.evaluate(samples, lens, marker);
        check(directory + " corpus was scored", ui != null, null);
        if (ui == null) return;
        check(directory + " matches DetectionEvaluation " + expected, ui.tp() == expected.tp() && ui.fp() == expected.fp()
                && ui.tn() == expected.tn() && ui.fn() == expected.fn(), ui);

        // Each sample labels a vulnerable method with exactly one marker comment.
        long labeled = 0;
        try (var files = Files.list(samples)) {
            for (Path file : files.filter(p -> p.toString().endsWith(".java")).toList()) {
                labeled += List.of(Files.readString(file).split("// " + marker, -1)).size() - 1;
            }
        }
        check(directory + " positives equal " + labeled + " labeled methods", ui.tp() + ui.fn() == labeled, ui);
        check(directory + " has negative cases", ui.tn() + ui.fp() > 0, ui);
    }

    private static void check(String name, boolean passed, Object detail) {
        if (!passed) {
            failures++;
            System.out.println("FAIL " + name + ": " + detail);
        }
    }
}
