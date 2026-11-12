package edu.fiu.capstone.skeleton;

import java.util.List;

public record DetectionResult(List<Finding> findings, List<DetectionDiagnostic> diagnostics) {
    public DetectionResult {
        findings = List.copyOf(findings);
        diagnostics = List.copyOf(diagnostics);
    }

    /** A clean finding list is conclusive only within documented models and with no diagnostics. */
    public boolean complete() {
        return diagnostics.isEmpty();
    }
}
