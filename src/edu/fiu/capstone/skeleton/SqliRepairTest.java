package edu.fiu.capstone.skeleton;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;




public class SqliRepairTest {
      public static void main(String[] args) throws Exception {

        String source = Files.readString(
            Path.of("samples/Vulnerabledao.txt")
        );

        SecurityLens lens = new RegexSqliLens();
        RepairStrategy repair = new NaiveSqliRepair();

        List<Finding> findings =
            lens.analyze("Vulnerabledao.txt", source);

        if (findings.size() != 5) {
            throw new AssertionError(
                "Expected 5 findings, got " + findings.size()
            );
        }

        System.out.println("PASS: Detected 5 SQL injection findings");
        Finding variableFinding = findings.get(4);

RepairOutcome outcome = repair.attempt(
    variableFinding, source
);

if (!outcome.isPatched()) {
    throw new AssertionError(
        "Expected variable-query repair, but it was refused"
    );
}

String patchedSource = outcome.patch().patched();

if (!patchedSource.contains(
        "java.sql.PreparedStatement __ps")) {
    throw new AssertionError(
        "Repair did not generate a PreparedStatement"
    );
}

if (!patchedSource.contains(
        "__ps.setString(1, username);")) {
    throw new AssertionError(
        "Repair did not bind the username parameter"
    );
}

System.out.println("PASS: Variable-query repair generated correctly");
List<Finding> remainingFindings =
    lens.analyze("VulnerableDao.java", patchedSource);

if (remainingFindings.size() != 4) {
    throw new AssertionError(
        "Expected 4 findings after repair, got "
        + remainingFindings.size()
    );
}

System.out.println(
    "PASS: SQL injection finding removed after repair"
);
Path tempDir = Files.createTempDirectory("sqli-repair-test-");

Path repairedFile = tempDir.resolve("VulnerableDao.java");

Files.writeString(repairedFile, patchedSource);

Process process = new ProcessBuilder(
    "javac",
    "-d",
    tempDir.toString(),
    repairedFile.toString()
)
    .redirectErrorStream(true)
    .start();

String compilerOutput =
    new String(process.getInputStream().readAllBytes());

int exitCode = process.waitFor();

if (exitCode != 0) {
    throw new AssertionError(
        "Generated repair failed compilation:\n"
        + compilerOutput
    );
}

System.out.println("PASS: Generated repaired Java code compiles");
    }
}
