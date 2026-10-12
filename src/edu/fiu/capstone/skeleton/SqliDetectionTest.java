package edu.fiu.capstone.skeleton;

import java.util.ArrayList;
import java.util.List;

public class SqliDetectionTest {

    private static int passed = 0;
    private static int failed = 0;

    public static void main(String[] args) {
        SecurityLens lens = new RegexSqliLens();

        // Original regression tests
        test(lens, "Direct concatenation",
            "stmt.executeQuery(\"SELECT * FROM users WHERE name = '\" + username + \"'\");", 1);

        test(lens, "Static SQL",
            "stmt.executeQuery(\"SELECT * FROM users\");", 0);

        test(lens, "PreparedStatement",
            "PreparedStatement ps = conn.prepareStatement(\"SELECT * FROM users WHERE name = ?\");", 0);

        test(lens, "Query stored in variable",
            "String query = \"SELECT * FROM users WHERE name = '\" + username + \"'\";\nstmt.executeQuery(query);", 1);

        test(lens, "Multiline execution",
            "stmt.executeQuery(\n    \"SELECT * FROM users WHERE name = '\" + username + \"'\"\n);", 1);

        test(lens, "Ordinary string concatenation",
            "String message = \"Hello \" + username;", 0);

        test(lens, "Static query stored in variable",
            "String query = \"SELECT * FROM users\";\nstmt.executeQuery(query);", 0);

        test(lens, "Prepared statement execution",
            "PreparedStatement ps = conn.prepareStatement(\"SELECT * FROM users WHERE name = ?\");\nps.setString(1, username);\nps.executeQuery();", 0);

        test(lens, "Reassigned variable with SQL concatenation",
            "String query = \"SELECT * FROM users\";\nquery = \"SELECT * FROM users WHERE name = '\" + username + \"'\";\nstmt.executeQuery(query);", 1);

        test(lens, "Safe variable reassignment",
            "String query = \"SELECT * FROM users\";\nquery = \"SELECT * FROM orders\";\nstmt.executeQuery(query);", 0);

        test(lens, "SQL execution inside line comment",
            "// stmt.executeQuery(\"SELECT * FROM users WHERE name = '\" + username + \"'\");", 0);

        test(lens, "SQL execution inside block comment",
            "/* stmt.executeQuery(\"SELECT * FROM users WHERE name = '\" + username + \"'\"); */", 0);

        test(lens, "Comment markers inside SQL string",
            "stmt.executeQuery(\"SELECT * FROM users WHERE note = '-- comment'\");", 0);

        test(lens, "Fake SQL call inside string",
            "String example = \"stmt.executeQuery(\\\"SELECT * FROM users\\\")\";", 0);

        // New tests: additional execution methods
        test(lens, "executeUpdate with concatenation",
            "stmt.executeUpdate(\"UPDATE users SET name = '\" + username + \"'\");", 1);

        test(lens, "execute with concatenation",
            "stmt.execute(\"DELETE FROM users WHERE name = '\" + username + \"'\");", 1);

        // New tests: multiple assignments and data flow
        test(lens, "Query assembled from SQL prefix",
            "String prefix = \"SELECT * FROM users WHERE name = '\";\nString query = prefix + username + \"'\";\nstmt.executeQuery(query);", 1);

        test(lens, "Query copied through another variable",
            "String query = \"SELECT * FROM users WHERE name = '\" + username + \"'\";\nString finalQuery = query;\nstmt.executeQuery(finalQuery);", 1);

        // New tests: alternative query construction
        test(lens, "String.concat query construction",
            "String query = \"SELECT * FROM users WHERE name = '\".concat(username);\nstmt.executeQuery(query);", 1);

        test(lens, "StringBuilder query construction",
            "StringBuilder query = new StringBuilder(\"SELECT * FROM users WHERE name = '\");\nquery.append(username);\nquery.append(\"'\");\nstmt.executeQuery(query.toString());", 1);

        // New tests: safe patterns
        test(lens, "Concatenation unrelated to SQL execution",
            "String message = \"Welcome \" + username;\nstmt.executeQuery(\"SELECT * FROM users\");", 0);

        test(lens, "PreparedStatement with dynamic parameter",
            "PreparedStatement ps = conn.prepareStatement(\"SELECT * FROM users WHERE name = ?\");\nps.setString(1, username);\nResultSet rs = ps.executeQuery();", 0);

        // New tests: misleading source text
        test(lens, "SQL-looking text in comment",
            "// SELECT * FROM users WHERE name = '\" + username\nstmt.executeQuery(\"SELECT * FROM users\");", 0);

        test(lens, "SQL call text in ordinary string",
            "String message = \"executeQuery(SELECT * FROM users WHERE name = '\" + username;", 0);

        System.out.println();
        System.out.println("Tests completed: " + passed + "/" + (passed + failed) + " passed.");

        if (failed > 0) {
            throw new AssertionError(failed + " test(s) failed.");
        }
    }

    private static void test(
            SecurityLens lens, String name, String source, int expected) {

        List<Finding> findings = lens.analyze("Test.java", source);
        int actual = findings.size();

        if (actual == expected) {
            passed++;
            System.out.printf("PASS | %-42s | expected=%d, actual=%d%n",
                    name, expected, actual);
        } else {
            failed++;
            System.out.printf("FAIL | %-42s | expected=%d, actual=%d%n",
                    name, expected, actual);
        }
    }
}