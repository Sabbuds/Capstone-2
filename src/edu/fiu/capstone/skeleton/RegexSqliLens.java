package edu.fiu.capstone.skeleton;

import java.util.List;

/** JDBC SQL-injection lens. Historical name and ID preserve caller compatibility. */
public class RegexSqliLens implements SecurityLens {
    @Override
    public String id() {
        return "regex-sqli";
    }

    @Override
    public List<Finding> analyze(String fileName, String sourceCode) {
        return JavaSecurityAnalyzer.analyze(fileName, sourceCode, JavaSecurityAnalyzer.Check.SQL_INJECTION);
    }

    @Override
    public DetectionResult analyze(DetectionRequest request) {
        return JavaSecurityAnalyzer.analyze(request, java.util.Set.of(JavaSecurityAnalyzer.Check.SQL_INJECTION));
    }
}
