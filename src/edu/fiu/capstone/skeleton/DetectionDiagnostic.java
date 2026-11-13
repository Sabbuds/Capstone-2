package edu.fiu.capstone.skeleton;

/** A parse, dependency, or analysis limitation; never a vulnerability finding. */
public record DetectionDiagnostic(String file, long line, Severity severity, String message) {
    public enum Severity { ERROR, WARNING }
}
