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
 
private static final String QUERY_SINK = ".executeQuery(";
private static final String UPDATE_SINK = ".executeUpdate(";
private static final String LARGE_UPDATE_SINK = ".executeLargeUpdate(";
private static final String EXECUTE_SINK = ".execute(";
private static final String BATCH_SINK = ".addBatch(";
 
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
     if (body.contains(BATCH_SINK)) {
    String statementVariable = findBatchStatementVariable(body);

    if (statementVariable == null) {
        return RepairOutcome.refused(
            "could not identify the batch Statement variable"
        );
    }

    int executionLine = findBatchExecutionLine(
        lines, statementVariable, idx
    );

    if (executionLine < 0) {
        return RepairOutcome.refused(
            "could not find matching executeBatch() call"
        );
    }

    if (hasMultipleBatchCalls(lines, statementVariable)) {
    return RepairOutcome.refused(
        "multiple addBatch() calls are not supported"
    );
}


String batchConnection = findBatchConnection(
    lines, statementVariable, idx
);

if (batchConnection == null) {
    return RepairOutcome.refused(
        "could not identify the original Statement connection"
    );
}

if (executionLine != idx + 1) {
    return RepairOutcome.refused(
        "only consecutive addBatch() and executeBatch() calls are supported"
    );
}

String expectedExecution =
    statementVariable + ".executeBatch();";

if (!lines[executionLine].strip().equals(expectedExecution)) {
    return RepairOutcome.refused(
        "unsupported executeBatch() statement format"
    );
}

String expectedBatchPrefix = statementVariable + BATCH_SINK;

if (!body.startsWith(expectedBatchPrefix)
        || !body.endsWith(");")) {
    return RepairOutcome.refused(
        "unsupported addBatch() statement format"
    );
}

String batchArgs = body.substring(
    expectedBatchPrefix.length(),
    body.length() - 2
).strip();

List<String> batchParts = splitTopLevelPlus(batchArgs);

if (batchParts.size() != 3
        || !isStringLiteral(batchParts.get(0))
        || !isStringLiteral(batchParts.get(2))
        || !batchParts.get(1).matches("[A-Za-z_$][\\w$]*")) {
    return RepairOutcome.refused(
        "only single-parameter SQL concatenation is supported"
    );
}
String batchPrefix = batchParts.get(0);
String batchSuffix = batchParts.get(2);
String batchValue = batchParts.get(1).strip();

String prefixText = batchPrefix.substring(
    1, batchPrefix.length() - 1
);

String suffixText = batchSuffix.substring(
    1, batchSuffix.length() - 1
);

if (!prefixText.endsWith("'")
        || !suffixText.startsWith("'")) {
    return RepairOutcome.refused(
        "only quoted SQL string values are supported"
    );
}
Pattern batchStringParameter = Pattern.compile(
    "\\bString\\s+" + Pattern.quote(batchValue) + "\\b"
);

if (!batchStringParameter.matcher(sourceCode).find()) {
    return RepairOutcome.refused(
        "batch parameter is not a recognized String variable"
    );
}

String parameterizedBatchSql =
    prefixText.substring(0, prefixText.length() - 1)
    + "?"
    + suffixText.substring(1);

String batchSqlLiteral = "\"" + parameterizedBatchSql + "\"";

int batchDeclarationLine = findBatchDeclarationLine(
    lines, statementVariable, idx
);

if (batchDeclarationLine < 0) {
    return RepairOutcome.refused(
        "could not identify a unique Statement declaration"
    );
}
if (hasOtherStatementUses(
        lines, statementVariable, idx,
        executionLine, batchDeclarationLine)) {
    return RepairOutcome.refused(
        "Statement is used elsewhere; batch repair is unsafe"
    );
}

if (batchDeclarationLine != idx - 1) {
    return RepairOutcome.refused(
        "only consecutive Statement declaration and batch calls are supported"
    );
}

String declarationText = lines[batchDeclarationLine].strip();
String batchText = lines[idx].strip();
String executionText = lines[executionLine].strip();

if (declarationText.contains("{")
        || declarationText.contains("}")
        || batchText.contains("{")
        || batchText.contains("}")
        || executionText.contains("{")
        || executionText.contains("}")) {
    return RepairOutcome.refused(
        "batch repair does not support inline block boundaries"
    );
}
if (Pattern.compile("\\b__ps\\b")
        .matcher(sourceCode).find()) {
    return RepairOutcome.refused(
        "PreparedStatement variable name already exists"
    );
}
String repairedBatchDeclaration =
    indent + "java.sql.PreparedStatement __ps = "
    + batchConnection + ".prepareStatement("
    + batchSqlLiteral + ");";

String repairedBatchAddition =
    indent + "__ps.setString(1, " + batchValue + ");\n"
    + indent + "__ps.addBatch();";

String repairedBatchExecution =
    indent + "__ps.executeBatch();";

    if (!lines[batchDeclarationLine].startsWith(indent)
        || !lines[executionLine].startsWith(indent)
        || !lines[batchDeclarationLine]
            .substring(0, lines[batchDeclarationLine].length()
                - lines[batchDeclarationLine].stripLeading().length())
            .equals(indent)
        || !lines[executionLine]
            .substring(0, lines[executionLine].length()
                - lines[executionLine].stripLeading().length())
            .equals(indent)) {
    return RepairOutcome.refused(
        "batch statements must have matching indentation"
    );
}
String sourceBeforeBatch = String.join(
    "\n",
    java.util.Arrays.copyOfRange(lines, 0, batchDeclarationLine)
);

if (sourceBeforeBatch.matches(
        "(?s).*\\b(if|else|for|while|switch|try|catch|finally)\\s*\\([^)]*\\)\\s*\\{[^}]*$")) {
    return RepairOutcome.refused(
        "batch repair inside complex control flow is not supported"
    );
}
String[] patchedBatchLines = lines.clone();

patchedBatchLines[batchDeclarationLine] =
    repairedBatchDeclaration;

patchedBatchLines[idx] =
    repairedBatchAddition;

patchedBatchLines[executionLine] =
    repairedBatchExecution;

String patchedBatchSource =
    String.join("\n", patchedBatchLines);

    return RepairOutcome.patched(new Patch(
    finding.file(),
    sourceCode,
    patchedBatchSource,
    "Replaced vulnerable addBatch SQL with a parameterized PreparedStatement."
));

}
 
  boolean isLargeUpdate = body.contains(LARGE_UPDATE_SINK);
boolean isUpdate = body.contains(UPDATE_SINK);
boolean isExecute = body.contains(EXECUTE_SINK);

String sink = isLargeUpdate
    ? LARGE_UPDATE_SINK
    : isUpdate
        ? UPDATE_SINK
        : isExecute
            ? EXECUTE_SINK
            : QUERY_SINK;

int sinkAt = body.indexOf(sink);

if (sinkAt < 0) {
   return RepairOutcome.refused(
    "only handles .executeQuery(...), .executeUpdate(...), "
    + ".executeLargeUpdate(...), or .execute(...)"
);
}
        if (!body.endsWith(");")) {
            return RepairOutcome.refused("the statement does not end on this line");
        }
 
        String before = body.substring(0, sinkAt);
        String args = body.substring(sinkAt + sink.length(), body.length() - 2);
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
    + indent + declaration
+ (isLargeUpdate
    ? " __ps.executeLargeUpdate();"
    : isUpdate
        ? " __ps.executeUpdate();"
        : isExecute
            ? " __ps.execute();"
            : " __ps.executeQuery();");


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
    for (int i = 1; i < parts.size(); i += 2) {
    String previousLiteral = parts.get(i - 1);
    String nextLiteral = parts.get(i + 1);

    String prefix = previousLiteral.substring(
        1, previousLiteral.length() - 1
    );

    String suffix = nextLiteral.substring(
        1, nextLiteral.length() - 1
    );

    if (!prefix.endsWith("'") || !suffix.startsWith("'")) {
        return RepairOutcome.refused(
            "only quoted SQL values can be safely parameterized"
        );
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
       

 if (Pattern.compile("\\b__ps\\b")
        .matcher(sourceCode).find()) {
    return RepairOutcome.refused(
        "PreparedStatement variable name already exists"
    );
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
                   .append("java.sql.PreparedStatement __ps = ").append(conn)
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
   .append(declaration)
   .append(isLargeUpdate
       ? " __ps.executeLargeUpdate();"
       : isUpdate
           ? " __ps.executeUpdate();"
           : isExecute
               ? " __ps.execute();"
               : " __ps.executeQuery();");

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
    private static String findBatchStatementVariable(String body) {
    int sinkAt = body.indexOf(BATCH_SINK);

    if (sinkAt < 0) {
        return null;
    }

    String before = body.substring(0, sinkAt).strip();

    if (!before.matches("[A-Za-z_$][\\w$]*")) {
        return null;
    }

    return before;
}
private static int findBatchExecutionLine(
        String[] lines, String statementVariable, int batchLine) {

    Pattern execution = Pattern.compile(
        "\\b" + Pattern.quote(statementVariable)
        + "\\s*\\.\\s*executeBatch\\s*\\(\\s*\\)"
    );

    for (int i = batchLine + 1; i < lines.length; i++) {
        if (execution.matcher(lines[i]).find()) {
            return i;
        }
    }

    return -1;
}
private static boolean hasMultipleBatchCalls(
        String[] lines, String statementVariable) {

    Pattern batchCall = Pattern.compile(
        "\\b" + Pattern.quote(statementVariable)
        + "\\s*\\.\\s*addBatch\\s*\\("
    );

    int count = 0;

    for (String line : lines) {
        if (batchCall.matcher(line).find()) {
            count++;
        }
    }

    return count > 1;
}
private static boolean hasOtherStatementUses(
        String[] lines, String statementVariable,
        int batchLine, int executionLine,
        int batchDeclarationLine) {

    Pattern usage = Pattern.compile(
        "\\b" + Pattern.quote(statementVariable) + "\\b"
    );

    for (int i = 0; i < lines.length; i++) {
        if (i == batchLine || i == executionLine) {
            continue;
        }

        String line = lines[i].strip();

       // Ignore only the identified Statement declaration.
if (i == batchDeclarationLine) {
    continue;
}

        if (usage.matcher(line).find()) {
            return true;
        }
    }

    return false;
}
private static String findBatchConnection(
        String[] lines, String statementVariable,
        int batchLine) {

    Pattern declaration = Pattern.compile(
        "^(?:java\\.sql\\.)?Statement\\s+"
        + Pattern.quote(statementVariable)
        + "\\s*=\\s*([A-Za-z_$][\\w$]*)"
        + "\\.createStatement\\s*\\(\\s*\\)\\s*;"
    );

    for (int i = batchLine - 1; i >= 0; i--) {
        Matcher matcher = declaration.matcher(lines[i].strip());

        if (matcher.matches()) {
            return matcher.group(1);
        }
    }

    return null;
}
private static int findBatchDeclarationLine(
        String[] lines, String statementVariable,
        int batchLine) {

    Pattern declaration = Pattern.compile(
        "^(?:java\\.sql\\.)?Statement\\s+"
        + Pattern.quote(statementVariable)
        + "\\s*=\\s*[A-Za-z_$][\\w$]*"
        + "\\.createStatement\\s*\\(\\s*\\)\\s*;"
    );

    int foundLine = -1;

    for (int i = 0; i < batchLine; i++) {
        if (declaration.matcher(lines[i].strip()).matches()) {
            if (foundLine != -1) {
                return -1;
            }
            foundLine = i;
        }
    }

    return foundLine;
}

}