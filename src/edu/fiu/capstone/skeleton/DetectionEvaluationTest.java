package edu.fiu.capstone.skeleton;

import java.nio.file.Files;
import java.util.List;

public class DetectionEvaluationTest {
    public static void main(String[] args) throws Exception {
        var directory = Files.createTempDirectory("capstone-evaluation-");
        var file = directory.resolve("Labeled.java");
        try {
            Files.writeString(file, """
                class Labeled {
                    void vulnerable() { /* code */ // EXPECT_TEST
                    }
                    void safe() { }
                }
                """);
            SecurityLens swapped = new SecurityLens() {
                public String id() { return "evaluation-test"; }
                public List<Finding> analyze(String name, String source) {
                    return List.of(new Finding("TEST", name, 4, "false alarm", ""));
                }
            };
            var score = DetectionEvaluation.evaluate(directory, swapped, "EXPECT_TEST");
            check(score.tp() == 0 && score.fp() == 1 && score.tn() == 0 && score.fn() == 1, "Confusion matrix");
            check(score.fnr().equals("100.00%") && score.fpr().equals("100.00%"), "Rate denominators");
            var precision = new DetectionEvaluation.Score(2, 1, 7, 1);
            check(precision.precision().equals("66.67%") && precision.fpr().equals("12.50%"), "Precision differs from FPR");
            check(new DetectionEvaluation.Score(0, 0, 0, 0).precision().equals("N/A"), "Empty denominator");
            System.out.println("PASS: Evaluation ground-truth matching, confusion matrix and metric denominators");
        } finally {
            Files.deleteIfExists(file);
            Files.deleteIfExists(directory);
        }
    }

    private static void check(boolean condition, String message) {
        if (!condition) throw new AssertionError(message);
    }
}
