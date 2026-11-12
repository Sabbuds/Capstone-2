package edu.fiu.capstone.skeleton;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

public class SecurityIntegrationTest {
    public static void main(String[] args) throws Exception {
        String source = """
            import java.sql.Statement;
            public class MixedCase {
                void run(Statement stmt, String input) throws Exception {
                    stmt.executeQuery("SELECT * FROM " + input);
                    new ProcessBuilder("sh", "-c", input).start();
                }
            }
            """;
        var findings = new SecurityAnalyzer().analyze("MixedCase.java", source);
        check(findings.size() == 2, "Expected both vulnerability classes");
        check(findings.get(0).cwe().equals("CWE-89") && findings.get(0).line() == 4, "SQL finding location");
        check(findings.get(1).cwe().equals("CWE-78") && findings.get(1).line() == 5, "Command finding location");

        Path directory = Files.createTempDirectory("capstone-integration-");
        Path input = directory.resolve("MixedCase.java");
        Path safe = directory.resolve("SafeCase.java");
        Path helper = directory.resolve("Helper.java"), caller = directory.resolve("Caller.java"), missing = directory.resolve("Missing.java");
        try {
            Files.writeString(input, source);
            Files.writeString(safe, "class SafeCase { void run(String data) throws Exception { new ProcessBuilder(\"printf\", data).start(); } }");
            String output = runCli(input.toString());
            check(output.contains("CWE-89") && output.contains("CWE-78"), "CLI must run both lenses");
            check(output.contains("require human review"), "Command repair must be a review outcome");
            check(Files.readString(input).equals(source), "CLI modified source");
            output = runCli("--detect-only", input.toString());
            check(output.contains("2 finding(s)") && !output.contains("repair refused"), "Detection-only mode");
            output = runCli("--detect-only", directory.toString());
            check(output.contains("MixedCase.java") && output.contains("SafeCase.java"), "Directory scan");
            check(output.contains("0 finding(s)"), "Safe command is a negative control");
            Files.writeString(helper, "class Helper {static String command(){return \"whoami\";}}");
            Files.writeString(caller, "class Caller {void run()throws Exception{Runtime.getRuntime().exec(Helper.command());}}");
            output = runCli("--detect-only", directory.toString());
            check(!output.contains("INCOMPLETE"), "Directory scanning must resolve helper source together");
            Files.writeString(missing, "class Missing {void run(){new Unavailable().execute();}}");
            output = runCli("--detect-only", missing.toString());
            check(output.contains("INCOMPLETE"), "Missing dependencies cannot be shown as a complete clean scan");
            check(new RegexSqliLens().analyze("MixedCase.java", source).size() == 1, "SQL lens isolation");
            check(new CommandInjectionLens().analyze("MixedCase.java", source).size() == 1, "Command lens isolation");
            System.out.println("PASS: Combined security analysis, CLI modes, locations and source preservation");
        } finally {
            Files.deleteIfExists(input);
            Files.deleteIfExists(safe);
            Files.deleteIfExists(helper);
            Files.deleteIfExists(caller);
            Files.deleteIfExists(missing);
            Files.deleteIfExists(directory);
        }
    }

    private static String runCli(String... args) throws Exception {
        PrintStream original = System.out;
        PrintStream originalError = System.err;
        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        try (PrintStream capture = new PrintStream(bytes, true, StandardCharsets.UTF_8)) {
            System.setOut(capture);
            System.setErr(capture);
            Main.main(args);
        } finally {
            System.setOut(original);
            System.setErr(originalError);
        }
        return bytes.toString(StandardCharsets.UTF_8);
    }

    private static void check(boolean condition, String message) {
        if (!condition) throw new AssertionError(message);
    }
}
