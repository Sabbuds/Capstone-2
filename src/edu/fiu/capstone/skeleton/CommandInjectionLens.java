package edu.fiu.capstone.skeleton;

import java.util.List;

/** Detects untrusted executables, command strings and explicit shell scripts. */
public class CommandInjectionLens implements SecurityLens {
    @Override
    public String id() {
        return "command-injection";
    }

    @Override
    public List<Finding> analyze(String fileName, String sourceCode) {
        return JavaSecurityAnalyzer.analyze(fileName, sourceCode, JavaSecurityAnalyzer.Check.COMMAND_INJECTION);
    }

    @Override
    public DetectionResult analyze(DetectionRequest request) {
        return JavaSecurityAnalyzer.analyze(request, java.util.Set.of(JavaSecurityAnalyzer.Check.COMMAND_INJECTION));
    }
}
