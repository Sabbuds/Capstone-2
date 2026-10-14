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
    return RepairOutcome.refused(
        "the result is not assigned to a variable"
    );
}

String declaration = before.substring(0, eq + 1).strip();

        // Check whether executeQuery uses a variable instead of direct SQL.
        boolean queryStoredInVariable = args.matches("[A-Za-z_$][\\w$]*");

        if (queryStoredInVariable) {
            String expression = findQueryExpression(
                sourceCode, args.strip(), idx
            );

            if (expression == null) {
                return RepairOutcome.refused(
                    "could not locate the SQL query variable"
                );
            }

            if (isQueryReassigned(sourceCode, args.strip(), idx)) {
                return RepairOutcome.refused(
                    "query variable is reassigned before execution"
                );
            }

            int declarationLine = findQueryDeclarationLine(
                sourceCode, args.strip(), idx
            );

            if (declarationLine < 0) {
                return RepairOutcome.refused(
                    "could not locate the query declaration"
                );
            }

            if (hasOtherQueryUses(
                    sourceCode, args.strip(), declarationLine, idx)) {
                return RepairOutcome.refused(
                    "query variable is used elsewhere"
                );
            }

            List<String> queryParts = splitTopLevelPlus(expression);

if (queryParts.size() != 3
        || !isStringLiteral(queryParts.get(0))
        || !isStringLiteral(queryParts.get(2))) {
    return RepairOutcome.refused(
        "unsupported variable-query expression"
    );
}

String value = queryParts.get(1).strip();

if (!value.matches("[A-Za-z_$][\\w$]*")) {
    return RepairOutcome.refused(
        "only simple variable parameters are supported"
    );
}
String firstLiteral = queryParts.get(0);
String lastLiteral = queryParts.get(2);

String prefix = firstLiteral.substring(
    1, firstLiteral.length() - 1
);

String suffix = lastLiteral.substring(
    1, lastLiteral.length() - 1
);

if (!prefix.endsWith("'") || !suffix.startsWith("'")) {
    return RepairOutcome.refused(
        "only quoted SQL string values are supported"
    );
}

String parameterizedSql =
    prefix.substring(0, prefix.length() - 1)
    + "?"
    + suffix.substring(1);
    Pattern stringParameter = Pattern.compile(
    "\\bString\\s+" + Pattern.quote(value) + "\\b"
);

if (!stringParameter.matcher(sourceCode).find()) {
    return RepairOutcome.refused(
        "parameter is not a recognized String variable"
    );
}
String conn = findConnectionVariable(sourceCode);

if (conn == null) {
    return RepairOutcome.refused(
        "no Connection variable found for the repair"
    );
}
if (Pattern.compile("\\b__ps\\b")
        .matcher(sourceCode).find()) {
    return RepairOutcome.refused(
        "PreparedStatement variable name already exists"
    );
}

// Build the replacement SQL declaration.
String repairedQueryLine =
    indent + "String " + args.strip()
    + " = \"" + parameterizedSql + "\";";

// Build the PreparedStatement code.
String preparedStatementCode =
    indent + "java.sql.PreparedStatement __ps = "
    + conn + ".prepareStatement(" + args.strip() + ");\n"
    + indent + "__ps.setString(1, " + value + ");\n"
    + indent + declaration + " __ps.executeQuery();";

String originalDeclaration = lines[declarationLine].strip();
String expectedDeclaration = "String " + args.strip() + " =";

if (!originalDeclaration.equals(expectedDeclaration)) {
    return RepairOutcome.refused(
        "only simple two-line query declarations are supported"
    );
}
    String[] patchedLines = lines.clone();

// Replace the original query declaration.
patchedLines[declarationLine] = repairedQueryLine;

// Handle a query declaration that spans two lines.
if (lines[declarationLine].strip().endsWith("=")) {
    if (declarationLine + 1 >= idx
            || !lines[declarationLine + 1].strip().equals(expression + ";")) {
        return RepairOutcome.refused(
            "unsupported multi-line query declaration"
        );
    }

    patchedLines[declarationLine + 1] = "";
}

// Replace the original SQL execution.
patchedLines[idx] = preparedStatementCode;

String patchedSource = String.join("\n", patchedLines);

    return RepairOutcome.patched(new Patch(
    finding.file(),
    sourceCode,
    patchedSource,
    "Replaced the variable-based SQL query with a parameterized PreparedStatement."
));
        }

      
 
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
 
   private static String findQueryExpression(
        String sourceCode, String variableName, int beforeLine) {

    String[] lines = sourceCode.split("\n", -1);

    Pattern assignment = Pattern.compile(
        "\\bString\\s+" + Pattern.quote(variableName)
        + "\\s*=\\s*(.*)"
    );

    for (int i = beforeLine - 1; i >= 0; i--) {
        Matcher matcher = assignment.matcher(lines[i]);

        if (matcher.find()) {
            String expression = matcher.group(1).strip();

            // Handle an expression starting on the next line.
            if (expression.isEmpty() && i + 1 < beforeLine) {
                expression = lines[i + 1].strip();
            }

            if (expression.endsWith(";")) {
                expression = expression.substring(
                    0, expression.length() - 1
                ).strip();
            }

            return expression.isEmpty() ? null : expression;
        }
    }

    return null;
}
private static boolean isQueryReassigned(
        String sourceCode, String variableName, int beforeLine) {

    String[] lines = sourceCode.split("\n", -1);

    Pattern assignment = Pattern.compile(
        "\\b" + Pattern.quote(variableName) + "\\s*=(?!=)"
    );

    int assignmentCount = 0;

    for (int i = 0; i < beforeLine; i++) {
        Matcher matcher = assignment.matcher(lines[i]);

        while (matcher.find()) {
            assignmentCount++;
        }
    }

    return assignmentCount > 1;
}
private static boolean hasOtherQueryUses(
        String sourceCode, String variableName, int declarationLine,
        int executionLine) {

    String[] lines = sourceCode.split("\n", -1);

    Pattern usage = Pattern.compile(
        "\\b" + Pattern.quote(variableName) + "\\b"
    );

    for (int i = declarationLine + 1; i < lines.length; i++) {
        if (i == executionLine) {
            continue;
        }

        if (usage.matcher(lines[i]).find()) {
            return true;
        }
    }

    return false;
}
private static int findQueryDeclarationLine(
        String sourceCode, String variableName, int beforeLine) {

    String[] lines = sourceCode.split("\n", -1);

    Pattern declaration = Pattern.compile(
        "\\bString\\s+" + Pattern.quote(variableName) + "\\s*="
    );

    for (int i = beforeLine - 1; i >= 0; i--) {
        if (declaration.matcher(lines[i]).find()) {
            return i;
        }
    }

    return -1;
}

    private static String findConnectionVariable(String sourceCode) {
        Matcher m = CONNECTION_DECL.matcher(sourceCode);
        return m.find() ? m.group(1) : null;
    }
}