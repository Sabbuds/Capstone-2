package sqli;

import java.sql.Statement;

public class StringTransforms {
    void constantReplacement(Statement stmt) throws Exception {
        stmt.executeQuery("SELECT * FROM $TABLE".replace("$TABLE", "users"));
    }

    void unsafeReplacement(Statement stmt, String table) throws Exception {
        stmt.executeQuery("SELECT * FROM $TABLE".replace("$TABLE", table)); // EXPECT_SQLI
    }

    void escapingIsNotProof(Statement stmt, String input) throws Exception {
        String value = input.replace("'", "''");
        stmt.executeQuery("SELECT * FROM users WHERE name = '" + value + "'"); // EXPECT_SQLI
    }

    void constantSubstring(Statement stmt) throws Exception {
        stmt.executeQuery("XXSELECT * FROM users".substring(2));
    }

    void unsafeSubstring(Statement stmt, String input) throws Exception {
        stmt.executeQuery(input.substring(2)); // EXPECT_SQLI
    }

    void numericBuilderLength(Statement stmt, String input) throws Exception {
        StringBuilder value = new StringBuilder(input);
        stmt.executeQuery("SELECT * FROM users WHERE id = " + value.length());
    }

    void numericStringLength(Statement stmt, String input) throws Exception {
        stmt.executeQuery("SELECT * FROM users WHERE id = " + input.length());
    }

    void constantCharacter(Statement stmt) throws Exception {
        stmt.executeQuery("SELECT * FROM users WHERE id = " + "1".charAt(0));
    }

    void unsafeCharacter(Statement stmt, String input) throws Exception {
        stmt.executeQuery("SELECT '" + input.charAt(0) + "'"); // EXPECT_SQLI
    }
}
