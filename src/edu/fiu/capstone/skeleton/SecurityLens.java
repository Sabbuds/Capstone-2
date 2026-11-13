package edu.fiu.capstone.skeleton;

import java.util.List;

public interface SecurityLens {
    String id();
    List<Finding> analyze(String fileName, String sourceCode);

    default DetectionResult analyze(DetectionRequest request) {
        var findings = new java.util.ArrayList<Finding>();
        for (String name : request.entryFiles().stream().sorted().toList()) {
            findings.addAll(analyze(name, request.sources().get(name)));
        }
        return new DetectionResult(findings, List.of(new DetectionDiagnostic("", 0,
                DetectionDiagnostic.Severity.WARNING, "This lens does not expose project dependency analysis")));
    }
}
