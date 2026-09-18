package edu.fiu.capstone.skeleton;

import java.util.ArrayList;
import java.util.List;

public class RegexSqliLens implements SecurityLens{
    private static final String[] SINKS = {
        ".executeQuery(", ".executeUpdate(", ".execute("};
    
    @Override
    public String id() {
        return "regex-sqli";
    }

    @Override
    public List<Finding> analyze(String fileName, String sourceCode) {
        List<Finding> findings = new ArrayList<>();
        String[] lines = sourceCode.split("\n", -1);

        for (int i = 0; i < lines.length; i++) {
            String line = lines[i];
            for (String sink : SINKS) {
                int at = line.indexOf(sink);
                if (at < 0) {
                    continue;
                }

                int openParen = at + sink.length() - 1;
                String args = argumentText(line, openParen);
                if (args.contains("+") && args.contains("\"")) {
                    findings.add(new Finding("CWE-89", fileName, i + 1, "SQL query built by concatenating a string. User input could potentially change what the query meant", line.strip()));
                }
                break;
            }
        }
        return findings;
    }

    private static String argumentText(String line, int openParen) {
        int depth = 0;
        for (int i = openParen; i < line.length(); i++) {
            char c = line.charAt(i);
            if (c == '(') {
                depth++;
            } else if (c == ')') {
                depth--;
                if (depth == 0) {
                    return line.substring(openParen + 1, i);
                }
            }
        }
        return line.substring(openParen + 1);
    }
    
}
