package sqli;

import java.sql.Statement;

public class BuilderFormats {
    void reversedFormat(Statement stmt, String input) throws Exception {
        StringBuilder format = new StringBuilder("s% MORF * TCELES");
        format.reverse();
        stmt.executeQuery(String.format(format.toString(), input)); // EXPECT_SQLI
    }

    void insertedFormat(Statement stmt, String input) throws Exception {
        StringBuilder format = new StringBuilder("SELECT * FROM %");
        format.insert(format.length(), "s");
        stmt.executeQuery(String.format(format.toString(), input)); // EXPECT_SQLI
    }

    void codePointFormat(Statement stmt, String input) throws Exception {
        StringBuilder format = new StringBuilder("SELECT * FROM %");
        format.appendCodePoint(115);
        stmt.executeQuery(String.format(format.toString(), input)); // EXPECT_SQLI
    }

    void constantReversedFormat(Statement stmt) throws Exception {
        StringBuilder format = new StringBuilder("s% MORF * TCELES");
        format.reverse();
        stmt.executeQuery(String.format(format.toString(), "users"));
    }

    void replacementFormat(Statement stmt, String input) throws Exception {
        StringBuilder format = new StringBuilder("SELECT * FROM %x");
        format.setCharAt(format.length() - 1, 's');
        stmt.executeQuery(String.format(format.toString(), input)); // EXPECT_SQLI
    }

    void slicedFormat(Statement stmt, String input) throws Exception {
        StringBuilder format = new StringBuilder("%SELECT * FROM %s");
        stmt.executeQuery(String.format(format.substring(1), input)); // EXPECT_SQLI
    }

    void reversedNumericFormat(Statement stmt, int id) throws Exception {
        StringBuilder format = new StringBuilder("d% = di EREHW sresu MORF * TCELES");
        format.reverse();
        stmt.executeQuery(String.format(format.toString(), id));
    }
}
