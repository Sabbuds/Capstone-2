
package edu.fiu.capstone.skeleton;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

public class CommandInjectionRepairTest {

    private static final SecurityLens lens =
        new CommandInjectionLens();

    private static final RepairStrategy repair =
        new CommandInjectionRepair();

    public static void main(String[] args) throws Exception {

        String[] commands = {
            "Runtime.getRuntime().exec(new String[]{\"sh\", \"-c\", \"cat \" + filename});",
            "Runtime.getRuntime().exec(new String[]{\"bash\", \"-c\", \"cat \" + filename});",
            "new ProcessBuilder(\"sh\", \"-c\", \"cat \" + filename).start();",
            "new ProcessBuilder(\"bash\", \"-c\", \"cat \" + filename).start();"
        };

        String[] labels = {
            "Runtime sh",
            "Runtime bash",
            "ProcessBuilder sh",
            "ProcessBuilder bash"
        };

        // TEST 1: Refuse an unverified target profile.
        System.clearProperty(
            "capstone.target.commandProfile"
        );

        String firstSource = sample(commands[0]);
        Finding firstFinding = detect(firstSource);

        RepairOutcome unconfigured =
            repair.attempt(firstFinding, firstSource);

        if (unconfigured.isPatched()) {
            throw new AssertionError(
                "Expected refusal without target profile"
            );
        }

        System.out.println(
            "PASS: Unverified target refused"
        );

        // The test declares the intended target profile.
        System.setProperty(
            "capstone.target.commandProfile",
            "linux-gnu-cat"
        );

        try {

            // TESTS 2-5: Detect, repair and compile
            // all four supported command patterns.
            for (int i = 0; i < commands.length; i++) {
                testRepair(labels[i], commands[i]);
            }

            // TEST 6: Refuse unsupported command.
            testUnsupportedCommand();

            // TEST 7: Refuse missing input.
            testMissingInput();

            System.out.println();
            System.out.println(
                "ALL COMMAND INJECTION REPAIR TESTS PASSED"
            );

        } finally {
            System.clearProperty(
                "capstone.target.commandProfile"
            );
        }
    }

    private static String sample(String command) {

        return "public class CommandSample {\n"
            + "    public void readFile(String filename)\n"
            + "            throws Exception {\n"
            + "        " + command + "\n"
            + "    }\n"
            + "}\n";
    }

    private static Finding detect(String source) {

        List<Finding> findings =
            lens.analyze("CommandSample.java", source);

        return findings.stream()
            .filter(f -> "CWE-78".equals(f.cwe()))
            .findFirst()
            .orElseThrow(() -> new AssertionError(
                "Expected CWE-78 command injection detection"
            ));
    }

    private static void testRepair(
            String label,
            String vulnerableCommand) throws Exception {

        String source = sample(vulnerableCommand);

        // Confirm the teammate's detector identifies CWE-78.
        Finding finding = detect(source);

        System.out.println(
            "PASS: " + label + " detected"
        );

        // Generate the patch.
        RepairOutcome outcome =
            repair.attempt(finding, source);

        if (!outcome.isPatched()) {
            throw new AssertionError(
                label + " repair refused: "
                + outcome.refusalReason()
            );
        }

        String patchedSource =
            outcome.patch().patched();

        String expected =
            "new ProcessBuilder(\"cat\", \"--\", filename).start();";

        if (!patchedSource.contains(expected)) {
            throw new AssertionError(
                label + " expected replacement missing"
            );
        }

        if (patchedSource.contains(vulnerableCommand)) {
            throw new AssertionError(
                label + " vulnerable command remains"
            );
        }

        System.out.println(
            "PASS: " + label + " repaired"
        );

        // Compile the generated Java source.
        compilePatchedCode(patchedSource);

        System.out.println(
            "PASS: " + label + " compiles"
        );
    }

    private static void compilePatchedCode(
            String patchedSource) throws Exception {

        Path tempDir =
            Files.createTempDirectory("command-repair-test-");

        Path repairedFile =
            tempDir.resolve("CommandSample.java");

        Files.writeString(
            repairedFile,
            patchedSource
        );

        Process compiler = new ProcessBuilder(
            "javac",
            "-d",
            tempDir.toString(),
            repairedFile.toString()
        )
        .redirectErrorStream(true)
        .start();

        String compilerOutput =
            new String(
                compiler.getInputStream().readAllBytes()
            );

        int exitCode = compiler.waitFor();

        if (exitCode != 0) {
            throw new AssertionError(
                "Repaired code failed compilation:\n"
                + compilerOutput
            );
        }
    }

    private static void testUnsupportedCommand() {

        String source = sample(
            "new ProcessBuilder(\"sh\", \"-c\", \"rm \" + filename).start();"
        );

        Finding finding = detect(source);

        RepairOutcome outcome =
            repair.attempt(finding, source);

        if (outcome.isPatched()) {
            throw new AssertionError(
                "Unsupported command should be refused"
            );
        }

        System.out.println(
            "PASS: Unsupported command refused"
        );
    }

    private static void testMissingInput() {

        RepairOutcome outcome =
            repair.attempt(null, null);

        if (outcome.isPatched()) {
            throw new AssertionError(
                "Missing input should be refused"
            );
        }

        System.out.println(
            "PASS: Missing input refused"
        );
    }
}