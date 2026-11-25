package edu.fiu.capstone.skeleton;

/** Shared entry point for the Java suites used by the test script and local UI. */
public final class RegressionTests {
    public static void main(String[] args) throws Exception {
        SqliDetectionTest.main(args);
        CommandInjectionTest.main(args);
        DetectorContractTest.main(args);
        SqliRepairTest.main(args);
        CommandInjectionRepairTest.main(args);
        CommandInjectionRuntimeTest.main(args);
        SecurityIntegrationTest.main(args);
        DetectionEvaluationTest.main(args);
        UiScanServiceTest.main(args);
        DetectionEvaluation.main(args);
        System.out.println("All Java regression suites passed.");
    }
}
