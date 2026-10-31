package sqli;

import java.sql.Statement;
import java.util.StringJoiner;

public class JoinQueries {
    void constantJoin(Statement stmt) throws Exception {
        stmt.executeQuery(String.join(" ", "SELECT *", "FROM users"));
    }

    void unsafeJoin(Statement stmt, String table) throws Exception {
        stmt.executeQuery(String.join(" ", "SELECT * FROM", table)); // EXPECT_SQLI
    }

    void constantJoiner(Statement stmt) throws Exception {
        StringJoiner query = new StringJoiner(" ");
        query.add("SELECT * FROM").add("users");
        stmt.executeQuery(query.toString());
    }

    void unsafeJoiner(Statement stmt, String table) throws Exception {
        StringJoiner query = new StringJoiner(" ", "SELECT * FROM ", "");
        query.add(table);
        stmt.executeQuery(query.toString()); // EXPECT_SQLI
    }

    void unsafeMergedJoiner(Statement stmt, String table) throws Exception {
        StringJoiner query = new StringJoiner(" ").add("SELECT * FROM");
        StringJoiner suffix = new StringJoiner(" ").add(table);
        query.merge(suffix);
        stmt.executeQuery(query.toString()); // EXPECT_SQLI
    }

    void constantIterableJoin(Statement stmt) throws Exception {
        stmt.executeQuery(String.join(" ", java.util.List.of("SELECT * FROM", "users")));
    }
}
