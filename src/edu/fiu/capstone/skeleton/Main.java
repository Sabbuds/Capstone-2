package edu.fiu.capstone.skeleton;
 
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
 
/**
 * Runs the whole belt on one file: read, scan, report, attempt a repair.
 *
 * Nothing is written to disk. A repair is printed, never applied — in the real
 * system a patch only reaches a file after it passes the safety gates, and the
 * gates do not exist yet.
 */
public class Main {
 
    public static void main(String[] args) throws Exception {
        if (args.length != 1) {
            System.out.println("usage: java -cp out edu.fiu.capstone.skeleton.Main <file>");
            return;
        }
 
        Path path = Path.of(args[0]);
        String source = Files.readString(path);
        String fileName = path.getFileName().toString();
 
        SecurityLens lens = new RegexSqliLens();
        RepairStrategy repair = new NaiveSqliRepair();
 
        List<Finding> findings = lens.analyze(fileName, source);
 
        System.out.println("scanned " + fileName + " with lens '" + lens.id() + "'");
        System.out.println(findings.size() + " finding(s)");
        System.out.println();
 
        int n = 0;
        for (Finding f : findings) {
            n++;
            System.out.println("[" + n + "] " + f.cwe() + "  " + f.file() + ":" + f.line());
            System.out.println("    " + f.message());
            System.out.println("    > " + f.snippet());
            System.out.println();
 
            RepairOutcome outcome = repair.attempt(f, source);
 
            if (outcome.isPatched()) {
                System.out.println("    repair proposed by '" + repair.id() + "'");
                System.out.println("    " + outcome.patch().rationale());
                System.out.println();
                printNewLines(outcome.patch());
            } else {
                System.out.println("    repair refused: " + outcome.refusalReason());
            }
            System.out.println();
        }
    }
 
    /** Prints the lines of the patched file that are not in the original. */
    private static void printNewLines(Patch patch) {
        List<String> before = List.of(patch.original().split("\n", -1));
        String[] after = patch.patched().split("\n", -1);
 
        for (String line : after) {
            if (!line.isBlank() && !before.contains(line)) {
                System.out.println("    + " + line.strip());
            }
        }
    }
}
