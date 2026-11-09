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
   String updateSource = Files.readString(
    Path.of("samples/UpdateRepairSample.java")
);

List<Finding> updateFindings = lens.analyze(
    "UpdateRepairSample.java", updateSource
); 
if (updateFindings.size() != 1) {
    throw new AssertionError(
        "Expected 1 executeUpdate finding, got "
        + updateFindings.size()
    );
}

System.out.println("PASS: executeUpdate vulnerability detected");

RepairOutcome updateOutcome = repair.attempt(
    updateFindings.get(0), updateSource
);

if (!updateOutcome.isPatched()) {
    throw new AssertionError(
        "Expected executeUpdate repair to succeed"
    );
}

String repairedUpdate = updateOutcome.patch().patched();


if (!repairedUpdate.contains(
        "java.sql.PreparedStatement __ps")) {
    throw new AssertionError(
        "Repair did not generate a PreparedStatement"
    );
}

if (!repairedUpdate.contains("__ps.setString(1, username);")) {
    throw new AssertionError(
        "Repair did not bind the username"
    );
}

if (!repairedUpdate.contains("__ps.executeUpdate();")) {
    throw new AssertionError(
        "Repair did not preserve executeUpdate"
    );
}

System.out.println("PASS: executeUpdate repair generated correctly");

List<Finding> remainingUpdateFindings = lens.analyze(
    "UpdateRepairSample.java", repairedUpdate
);

if (!remainingUpdateFindings.isEmpty()) {
    throw new AssertionError(
        "SQL injection still detected after executeUpdate repair"
    );
}

System.out.println(
    "PASS: executeUpdate SQL injection finding removed"
);

Path updateFile = tempDir.resolve("UpdateRepairSample.java");

Files.writeString(updateFile, repairedUpdate);

Process updateProcess = new ProcessBuilder(
    "javac",
    "-d",
    tempDir.toString(),
    updateFile.toString()
)
    .redirectErrorStream(true)
    .start();

String updateCompilerOutput =
    new String(updateProcess.getInputStream().readAllBytes());

int updateExitCode = updateProcess.waitFor();

if (updateExitCode != 0) {
    throw new AssertionError(
        "executeUpdate repair failed compilation:\n"
        + updateCompilerOutput
    );
}

System.out.println("PASS: Repaired executeUpdate Java code compiles");

String largeUpdateSource = Files.readString(
    Path.of("samples/LargeUpdateRepairSample.java")
);

List<Finding> largeUpdateFindings = lens.analyze(
    "LargeUpdateRepairSample.java", largeUpdateSource
);

if (largeUpdateFindings.size() != 1) {
    throw new AssertionError(
        "Expected 1 executeLargeUpdate finding, got "
        + largeUpdateFindings.size()
    );
}

System.out.println(
    "PASS: executeLargeUpdate vulnerability detected"
);
RepairOutcome largeUpdateOutcome = repair.attempt(
    largeUpdateFindings.get(0), largeUpdateSource
);

if (!largeUpdateOutcome.isPatched()) {
    throw new AssertionError(
        "Expected executeLargeUpdate repair to succeed"
    );
}

String repairedLargeUpdate = largeUpdateOutcome.patch().patched();

if (!repairedLargeUpdate.contains("__ps.executeLargeUpdate();")) {
    throw new AssertionError(
        "Repair did not generate executeLargeUpdate"
    );
}

if (!repairedLargeUpdate.contains("__ps.setString(1, username);")) {
    throw new AssertionError(
        "Repair did not bind the username parameter"
    );
}

System.out.println("PASS: executeLargeUpdate repair succeeded");

List<Finding> remainingLargeUpdateFindings = lens.analyze(
    "LargeUpdateRepairSample.java",
    repairedLargeUpdate
);

if (!remainingLargeUpdateFindings.isEmpty()) {
    throw new AssertionError(
        "Expected 0 remaining SQL injection findings, got "
        + remainingLargeUpdateFindings.size()
    );
}

System.out.println(
    "PASS: executeLargeUpdate repair has 0 remaining SQL injection findings"
);

Path largeUpdateFile = tempDir.resolve("LargeUpdateRepairSample.java");

Files.writeString(largeUpdateFile, repairedLargeUpdate);

Process largeUpdateProcess = new ProcessBuilder(
    "javac",
    "-d",
    tempDir.toString(),
    largeUpdateFile.toString()
).redirectErrorStream(true).start();

String largeUpdateCompilerOutput =
    new String(largeUpdateProcess.getInputStream().readAllBytes());

int largeUpdateExitCode = largeUpdateProcess.waitFor();

if (largeUpdateExitCode != 0) {
    throw new AssertionError(
        "Repaired executeLargeUpdate code failed to compile:\n"
        + largeUpdateCompilerOutput
    );
}

System.out.println(
    "PASS: Repaired executeLargeUpdate Java code compiles"
);
String executeSource = """
    import java.sql.*;

    public class ExecuteRepairSample {
        public boolean checkUser(Connection conn, String username)
                throws SQLException {
            Statement stmt = conn.createStatement();
            boolean result = stmt.execute("SELECT * FROM users WHERE username = '" + username + "'");
            return result;
        }
    }
    """;

List<Finding> executeFindings = lens.analyze(
    "ExecuteRepairSample.java", executeSource
);

if (executeFindings.size() != 1) {
    throw new AssertionError(
        "Expected 1 execute finding, got "
        + executeFindings.size()
    );
}

System.out.println("PASS: execute vulnerability detected");

RepairOutcome executeOutcome = repair.attempt(
    executeFindings.get(0), executeSource
);

if (!executeOutcome.isPatched()) {
    throw new AssertionError(
        "Expected execute repair to succeed"
    );
}
String repairedExecute = executeOutcome.patch().patched();
if (!repairedExecute.contains(
        "java.sql.PreparedStatement __ps")) {
    throw new AssertionError(
        "PreparedStatement was not generated"
    );
}

if (!repairedExecute.contains("__ps.setString(1, username);")) {
    throw new AssertionError(
        "Username parameter was not bound"
    );
}

if (!repairedExecute.contains("__ps.execute();")) {
    throw new AssertionError(
        "PreparedStatement execute() was not generated"
    );
}

System.out.println("PASS: execute repair generated correctly");
List<Finding> remainingExecuteFindings = lens.analyze(
    "ExecuteRepairSample.java",
    repairedExecute
);

if (!remainingExecuteFindings.isEmpty()) {
    throw new AssertionError(
        "Expected 0 remaining SQL injection findings, got "
        + remainingExecuteFindings.size()
    );
}

System.out.println(
    "PASS: execute repair has 0 remaining SQL injection findings"
);

// Test addBatch() repair
String batchSource = """
    import java.sql.*;

    public class BatchRepairSample {
        public void deleteUser(Connection conn, String username)
                throws SQLException {
            Statement stmt = conn.createStatement();
            stmt.addBatch("DELETE FROM users WHERE username = '" + username + "'");
            stmt.executeBatch();
        }
    }
    """;

List<Finding> batchFindings =
    lens.analyze("BatchRepairSample.java", batchSource);

if (batchFindings.size() != 1) {
    throw new AssertionError(
        "Expected 1 addBatch vulnerability, found "
        + batchFindings.size()
    );
}

System.out.println("PASS: addBatch vulnerability detected");

RepairOutcome batchOutcome =
    repair.attempt(batchFindings.get(0), batchSource);

if (!batchOutcome.isPatched()) {
    throw new AssertionError("addBatch repair was refused");
}

String repairedBatch = batchOutcome.patch().patched();

if (!repairedBatch.contains("java.sql.PreparedStatement __ps")
        || !repairedBatch.contains("__ps.setString(1, username);")
        || !repairedBatch.contains("__ps.addBatch();")
        || !repairedBatch.contains("__ps.executeBatch();")) {
    throw new AssertionError(
        "addBatch repair generated incorrect code"
    );
}

System.out.println("PASS: addBatch repair generated correctly");

List<Finding> remainingBatchFindings =
    lens.analyze("BatchRepairSample.java", repairedBatch);

if (!remainingBatchFindings.isEmpty()) {
    throw new AssertionError(
        "Repaired addBatch code still contains "
        + remainingBatchFindings.size()
        + " SQL injection finding(s)"
    );
}

System.out.println("PASS: addBatch repair has no remaining SQL injection findings");

}
}
