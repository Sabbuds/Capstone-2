package edu.fiu.capstone.skeleton;
 
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
 
/**
 * Walking-skeleton repair. Handles exactly one shape:
 *
 *   ResultSet rs = stmt.executeQuery("... '" + value + "' ...");
 *
 * and rewrites it to a parameterised query. Everything else is refused with a
 * stated reason.
 *
 * Refusing is a real outcome, not a failure. Counting refusals and their reasons
 * is part of the final report — it is how the tool shows it knows the limits of
 * what it can safely rewrite.
 */
public class NaiveSqliRepair implements RepairStrategy {
 
    private static final String SINK = ".executeQuery(";
 
    private static final Pattern CONNECTION_DECL =
        Pattern.compile("\\bConnection\\s+(\\w+)");
 
    @Override
    public String id() {
        return "naive-sqli-parameterize";
    }
 
    @Override
    public RepairOutcome attempt(Finding finding, String sourceCode) {
        if (!"CWE-89".equals(finding.cwe())) {
            return RepairOutcome.refused("this strategy only handles CWE-89");
        }
 
        String[] lines = sourceCode.split("\n", -1);
        int idx = finding.line() - 1;
        if (idx < 0 || idx >= lines.length) {
            return RepairOutcome.refused("line " + finding.line() + " is outside the file");
        }
 
        String line = lines[idx];
        String indent = line.substring(0, line.length() - line.stripLeading().length());
        String body = line.strip();
 
        int sinkAt = body.indexOf(SINK);
        if (sinkAt < 0) {
            return RepairOutcome.refused("only handles .executeQuery(...)");
        }
        if (!body.endsWith(");")) {
            return RepairOutcome.refused("the statement does not end on this line");
        }
 
        String before = body.substring(0, sinkAt);
        String args = body.substring(sinkAt + SINK.length(), body.length() - 2);
 
        int eq = before.indexOf('=');
        if (eq < 0) {
            return RepairOutcome.refused("the result is not assigned to a variable");
        }
        String declaration = before.substring(0, eq + 1).strip();
 
 List<String> parts = splitTopLevelPlus(args);

// The query should alternate between SQL string literals and dynamic values.
// Example: literal + value + literal + value + literal
if (parts.size() < 3 || parts.size() % 2 == 0) {
    return RepairOutcome.refused(
        "expected alternating SQL literals and dynamic values");
}

// Store each dynamic value that will become a PreparedStatement parameter
List<String> values = new ArrayList<>();

for (int i = 0; i < parts.size(); i++) {

    if (i % 2 == 0) {
        // Even positions should be SQL string literals
        if (!isStringLiteral(parts.get(i))) {
            return RepairOutcome.refused(
                "expected SQL string literal at part " + i);
        }
    } else {
        // Odd positions should be dynamic values
        String value = parts.get(i).strip();

        if (value.isEmpty()) {
            return RepairOutcome.refused(
                "empty dynamic value at part " + i);
        }

        values.add(value);
    }
}
      
 StringBuilder sqlBuilder = new StringBuilder();

for (int i = 0; i < parts.size(); i++) {

    if (i % 2 == 0) {
        // Remove the surrounding Java double quotes
        String literal = parts.get(i);
        String inner = literal.substring(1, literal.length() - 1);

        // Remove SQL single quotes surrounding a dynamic value
        if (i < parts.size() - 1 && inner.endsWith("'")) {
            inner = inner.substring(0, inner.length() - 1);
        }

        if (i > 0 && inner.startsWith("'")) {
            inner = inner.substring(1);
        }

        sqlBuilder.append(inner);

    } else {
        // Replace each dynamic value with a parameter placeholder
        sqlBuilder.append("?");
    }
}
       

 
        String conn = findConnectionVariable(sourceCode);
        if (conn == null) {
            return RepairOutcome.refused("no Connection variable found in this file");
        }

 // Build the final parameterized SQL statement using the ? placeholders
        String sql = "\"" + sqlBuilder.toString() + "\"";
 
 // Build a new version of the source code containing the repaired query
        StringBuilder out = new StringBuilder();
        for (int i = 0; i < lines.length; i++) {
            if (i == idx) {
                 // Create the PreparedStatement using the parameterized SQL query
                out.append(indent)
                   .append("PreparedStatement __ps = ").append(conn)
                   .append(".prepareStatement(").append(sql).append(");\n");

 // Bind each dynamic value to its corresponding placeholder
        for (int paramIndex = 0; paramIndex < values.size(); paramIndex++) {
            out.append(indent)
               .append("__ps.setString(")
               .append(paramIndex + 1)
               .append(", ")
               .append(values.get(paramIndex))
               .append(");\n");
        }
// Execute the repaired query using the PreparedStatement
                out.append(indent)
                   .append(declaration).append(" __ps.executeQuery();");

            } else {
                out.append(lines[i]);
            }

            if (i < lines.length - 1) {
                out.append("\n");
            }

        }
 
        return RepairOutcome.patched(new Patch(
            finding.file(),
            sourceCode,
            out.toString(),
            "Replaced string concatenation with a parameterised query."));
    }
 
    /** Splits on '+' that sit outside string literals and parentheses. */
    private static List<String> splitTopLevelPlus(String s) {
        List<String> parts = new ArrayList<>();
        StringBuilder cur = new StringBuilder();
        boolean inString = false;
        int depth = 0;
 
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
 
            if (inString) {
                cur.append(c);
                if (c == '\\' && i + 1 < s.length()) {
                    cur.append(s.charAt(++i));
                } else if (c == '"') {
                    inString = false;
                }
                continue;
            }
 
            if (c == '"') {
                inString = true;
                cur.append(c);
            } else if (c == '(') {
                depth++;
                cur.append(c);
            } else if (c == ')') {
                depth--;
                cur.append(c);
            } else if (c == '+' && depth == 0) {
                parts.add(cur.toString().strip());
                cur.setLength(0);
            } else {
                cur.append(c);
            }
        }
        parts.add(cur.toString().strip());
        return parts;
    }
 
    private static boolean isStringLiteral(String s) {
        return s.length() >= 2 && s.startsWith("\"") && s.endsWith("\"");
    }
 
    private static String findConnectionVariable(String sourceCode) {
        Matcher m = CONNECTION_DECL.matcher(sourceCode);
        return m.find() ? m.group(1) : null;
    }
}