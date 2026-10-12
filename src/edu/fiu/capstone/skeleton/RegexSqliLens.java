
package edu.fiu.capstone.skeleton;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class RegexSqliLens implements SecurityLens {

    private static final Pattern SINK = Pattern.compile(
            "\\.\\s*(?:executeQuery|executeUpdate|execute)\\s*\\("
    );

    private static final Pattern ASSIGNMENT = Pattern.compile(
            "\\b(?:String\\s+|StringBuilder\\s+|StringBuffer\\s+)?"
                    + "([A-Za-z_$][\\w$]*)\\s*=(?!=)"
    );

    private static final Pattern SQL_KEYWORD = Pattern.compile(
            "(?i)\\b(SELECT|INSERT|UPDATE|DELETE|REPLACE|MERGE)\\b"
    );

    private static final Pattern IDENTIFIER = Pattern.compile(
            "\\b[A-Za-z_$][\\w$]*\\b"
    );

    @Override
    public String id() {
        return "regex-sqli";
    }

    @Override
    public List<Finding> analyze(String fileName, String sourceCode) {
        List<Finding> findings = new ArrayList<>();

        // Remove comments without changing source positions.
        String cleaned = removeComments(sourceCode);

        // Mask literals to identify executable code safely.
        String codeOnly = maskLiterals(cleaned);

        Matcher sinks = SINK.matcher(codeOnly);

        while (sinks.find()) {
            int openParen = sinks.end() - 1;
            int closeParen = findMatchingParen(cleaned, openParen);

            if (closeParen < 0) {
                continue;
            }

            String arguments = cleaned.substring(
                    openParen + 1, closeParen
            );

            Map<String, Boolean> variableState =
                    variableStatesBefore(
                            codeOnly, cleaned, sinks.start()
                    );

            boolean risky = isPotentialSqlInjection(arguments);

            // Check whether the sink uses a variable previously identified
            // as potentially containing an unsafe SQL query.
            if (!risky) {
                String argumentCode = maskLiterals(arguments);
                Matcher identifiers = IDENTIFIER.matcher(argumentCode);

                while (identifiers.find()) {
                    String name = identifiers.group();

                    if (Boolean.TRUE.equals(variableState.get(name))) {
                        risky = true;
                        break;
                    }
                }
            }

            if (risky) {
                int line = 1;

                for (int i = 0; i < sinks.start(); i++) {
                    if (sourceCode.charAt(i) == '\n') {
                        line++;
                    }
                }

                int lineStart = sourceCode.lastIndexOf(
                        '\n', Math.max(0, sinks.start() - 1)
                ) + 1;

                int lineEnd = sourceCode.indexOf('\n', sinks.start());

                if (lineEnd < 0) {
                    lineEnd = sourceCode.length();
                }

                findings.add(new Finding(
                        "CWE-89",
                        fileName,
                        line,
                        "SQL execution may use dynamically constructed query data. "
                                + "Verify the data flow and use parameterized queries.",
                        sourceCode.substring(lineStart, lineEnd).strip()
                ));
            }
        }

        return findings;
    }

    /**
     * Tracks simple variable assignments and StringBuilder operations
     * before a SQL execution sink.
     *
     * This is a heuristic and does not model Java scopes, branches,
     * loops, or complete data flow.
     */
    private static Map<String, Boolean> variableStatesBefore(
            String codeOnly, String cleaned, int sinkPosition) {

        Map<String, Boolean> riskyState = new HashMap<>();
        Map<String, Boolean> sqlState = new HashMap<>();
        Map<String, Boolean> builderState = new HashMap<>();

        int statementStart = 0;

        for (int i = 0; i < sinkPosition; i++) {
            if (codeOnly.charAt(i) != ';') {
                continue;
            }

            processStatement(
                    codeOnly.substring(statementStart, i),
                    cleaned.substring(statementStart, i),
                    riskyState,
                    sqlState,
                    builderState
            );

            statementStart = i + 1;
        }

        // Handle a final statement without a semicolon before the sink.
        if (statementStart < sinkPosition) {
            processStatement(
                    codeOnly.substring(statementStart, sinkPosition),
                    cleaned.substring(statementStart, sinkPosition),
                    riskyState,
                    sqlState,
                    builderState
            );
        }

        return riskyState;
    }

    /**
     * Updates the tracked state for one statement.
     */
    private static void processStatement(
            String statementCode,
            String statement,
            Map<String, Boolean> riskyState,
            Map<String, Boolean> sqlState,
            Map<String, Boolean> builderState) {

        String trimmedCode = statementCode.trim();

        if (trimmedCode.isEmpty()) {
            return;
        }

        // Process StringBuilder.append(...) and StringBuffer.append(...).
        trackBuilderAppend(
                statement, riskyState, sqlState, builderState
        );

        Matcher assignment = ASSIGNMENT.matcher(statementCode);

        if (!assignment.find()) {
            return;
        }

        String name = assignment.group(1);

        int expressionStart = assignment.end();

        String expression = statement.substring(expressionStart).trim();
        String expressionCode =
                statementCode.substring(expressionStart).trim();

        boolean isBuilder = expression.contains("new StringBuilder")
                || expression.contains("new StringBuffer");

        // A builder is tracked separately because append() mutates it.
        if (isBuilder) {
            boolean hasSql = SQL_KEYWORD.matcher(expression).find();

            builderState.put(name, hasSql);
            sqlState.put(name, hasSql);
            riskyState.put(name, false);
            return;
        }

        boolean sqlLike = SQL_KEYWORD.matcher(expression).find();
        boolean inheritedRisk = false;

        Matcher identifiers = IDENTIFIER.matcher(expressionCode);

        while (identifiers.find()) {
            String identifier = identifiers.group();

            if (Boolean.TRUE.equals(sqlState.get(identifier))) {
                sqlLike = true;
            }

            if (Boolean.TRUE.equals(riskyState.get(identifier))) {
                inheritedRisk = true;
            }
        }

        boolean concatenated = hasDynamicConcatenation(expression);
        boolean concatCall = hasDynamicConcatCall(expression);

        boolean risky = inheritedRisk
                || (sqlLike && (concatenated || concatCall));

        // A reassignment replaces the previous state for that variable.
        riskyState.put(name, risky);
        sqlState.put(name, sqlLike);
        builderState.remove(name);
    }

    /**
     * Tracks calls such as query.append(username).
     */
    private static void trackBuilderAppend(
            String statement,
            Map<String, Boolean> riskyState,
            Map<String, Boolean> sqlState,
            Map<String, Boolean> builderState) {

        Pattern appendPattern = Pattern.compile(
                "\\b([A-Za-z_$][\\w$]*)\\s*\\.\\s*append\\s*\\("
        );

        Matcher matcher = appendPattern.matcher(statement);

        while (matcher.find()) {
            String name = matcher.group(1);

            if (!Boolean.TRUE.equals(builderState.get(name))) {
                continue;
            }

            int openParen = statement.indexOf('(', matcher.start());
            int closeParen = findMatchingParen(statement, openParen);

            if (closeParen < 0) {
                continue;
            }

            String argument = statement.substring(
                    openParen + 1, closeParen
            ).trim();

            boolean dynamicArgument = !argument.isEmpty()
                    && !isStringLiteral(argument);

            if (dynamicArgument
                    && Boolean.TRUE.equals(sqlState.get(name))) {
                riskyState.put(name, true);
            }

            // Preserve the builder's SQL context after append().
            sqlState.put(name, true);
        }
    }

    /**
     * Detects a SQL-looking expression that combines a string literal
     * and a dynamic expression with the + operator.
     */
    private static boolean isPotentialSqlInjection(String expression) {
        if (!SQL_KEYWORD.matcher(expression).find()) {
            return false;
        }

        return hasDynamicConcatenation(expression);
    }

    private static boolean hasDynamicConcatenation(String expression) {
        List<String> parts = splitOnPlusOutsideLiterals(expression);

        if (parts.size() < 2) {
            return false;
        }

        boolean hasStringLiteral = false;
        boolean hasDynamicPart = false;

        for (String part : parts) {
            String trimmed = part.trim();

            if (isStringLiteral(trimmed)) {
                hasStringLiteral = true;
            } else if (!trimmed.isEmpty()) {
                hasDynamicPart = true;
            }
        }

        return hasStringLiteral && hasDynamicPart;
    }

    /**
     * Detects expressions such as:
     * "SELECT * FROM users WHERE name = '".concat(username)
     */
    private static boolean hasDynamicConcatCall(String expression) {
        Pattern concatPattern = Pattern.compile(
                "\\.\\s*concat\\s*\\("
        );

        Matcher matcher = concatPattern.matcher(expression);

        while (matcher.find()) {
            int openParen = expression.indexOf('(', matcher.start());
            int closeParen = findMatchingParen(expression, openParen);

            if (closeParen < 0) {
                continue;
            }

            String receiver = expression.substring(
                    0, matcher.start()
            ).trim();

            String argument = expression.substring(
                    openParen + 1, closeParen
            ).trim();

            boolean receiverHasSql =
                    SQL_KEYWORD.matcher(receiver).find();

            if (receiverHasSql
                    && !argument.isEmpty()
                    && !isStringLiteral(argument)) {
                return true;
            }

            // Also recognize concatenation on a previously constructed
            // SQL expression, including an expression held in a variable.
            if (!argument.isEmpty()
                    && !isStringLiteral(argument)
                    && receiverHasSql) {
                return true;
            }
        }

        return false;
    }

    private static List<String> splitOnPlusOutsideLiterals(
            String expression) {

        List<String> parts = new ArrayList<>();

        int start = 0;
        char quote = 0;

        for (int i = 0; i < expression.length(); i++) {
            char c = expression.charAt(i);

            if (quote != 0) {
                if (c == '\\') {
                    i++;
                } else if (c == quote) {
                    quote = 0;
                }
            } else if (c == '"' || c == '\'') {
                quote = c;
            } else if (c == '+') {
                parts.add(expression.substring(start, i));
                start = i + 1;
            }
        }

        parts.add(expression.substring(start));

        return parts;
    }

    private static boolean isStringLiteral(String expression) {
        if (expression.length() < 2
                || expression.charAt(0) != '"'
                || expression.charAt(expression.length() - 1) != '"') {
            return false;
        }

        boolean escaped = false;

        for (int i = 1; i < expression.length() - 1; i++) {
            char c = expression.charAt(i);

            if (escaped) {
                escaped = false;
            } else if (c == '\\') {
                escaped = true;
            }
        }

        return !escaped;
    }

    /**
     * Removes comments while preserving character positions and line breaks.
     * String and character literals are left intact.
     */
    private static String removeComments(String source) {
        StringBuilder result = new StringBuilder(source);
        int i = 0;

        while (i < result.length()) {
            char c = result.charAt(i);

            if (c == '"' || c == '\'') {
                i = skipLiteral(result, i, c);
                continue;
            }

            if (c == '/' && i + 1 < result.length()) {
                char next = result.charAt(i + 1);

                if (next == '/') {
                    int end = i;

                    while (end < result.length()
                            && result.charAt(end) != '\n'
                            && result.charAt(end) != '\r') {
                        end++;
                    }

                    blankRange(result, i, end);
                    i = end;
                    continue;
                }

                if (next == '*') {
                    int close = result.indexOf("*/", i + 2);
                    int end = close < 0
                            ? result.length()
                            : close + 2;

                    blankRange(result, i, end);
                    i = end;
                    continue;
                }
            }

            i++;
        }

        return result.toString();
    }

    private static int skipLiteral(
            CharSequence source, int start, char quote) {

        int i = start + 1;

        while (i < source.length()) {
            char c = source.charAt(i);

            if (c == '\\') {
                i += 2;
            } else if (c == quote) {
                return i + 1;
            } else {
                i++;
            }
        }

        return source.length();
    }

    private static void blankRange(
            StringBuilder source, int start, int end) {

        for (int i = start; i < end; i++) {
            char c = source.charAt(i);

            if (c != '\n' && c != '\r') {
                source.setCharAt(i, ' ');
            }
        }
    }

    /**
     * Masks string and character literals while preserving positions.
     */
    private static String maskLiterals(String source) {
        StringBuilder result = new StringBuilder(source);
        int i = 0;

        while (i < result.length()) {
            char c = result.charAt(i);

            if (c == '"' || c == '\'') {
                int end = skipLiteral(result, i, c);
                blankRange(result, i, end);
                i = end;
            } else {
                i++;
            }
        }

        return result.toString();
    }

    /**
     * Finds a matching closing parenthesis while ignoring parentheses
     * inside literals.
     */
    private static int findMatchingParen(
            String source, int openParen) {

        int depth = 0;
        int i = openParen;

        while (i < source.length()) {
            char c = source.charAt(i);

            if (c == '"' || c == '\'') {
                i = skipLiteral(source, i, c);
                continue;
            }

            if (c == '(') {
                depth++;
            } else if (c == ')') {
                depth--;

                if (depth == 0) {
                    return i;
                }
            }

            i++;
        }

        return -1;
    }
}
