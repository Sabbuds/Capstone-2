package edu.fiu.capstone.skeleton;

import java.util.List;

/** Combines supported security perspectives using the existing finding contract. */
public final class SecurityAnalyzer implements SecurityLens {

    @Override
    public String id() {
        return "sql-and-command-injection";
    }

    @Override
    public List<Finding> analyze(String fileName, String sourceCode) {
        return analyze(DetectionRequest.source(fileName, sourceCode)).findings();
    }

    @Override
    public DetectionResult analyze(DetectionRequest request) {
        return JavaSecurityAnalyzer.analyze(request, java.util.EnumSet.allOf(JavaSecurityAnalyzer.Check.class));
    }
}
