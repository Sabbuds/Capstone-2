package sqli;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.Statement;

public class BoundQueries {
    void boundValue(Connection conn, String input) throws Exception {
        try (PreparedStatement query = conn.prepareStatement("SELECT * FROM users WHERE name = ?")) {
            query.setString(1, input);
            query.executeQuery();
        }
    }

    void unsafeTable(Connection conn, String table) throws Exception {
        try (PreparedStatement query = conn.prepareStatement("SELECT * FROM " + table)) { // EXPECT_SQLI
            query.executeQuery();
        }
    }

    void unsafeBatch(Statement stmt, String input) throws Exception {
        stmt.addBatch("DELETE FROM users WHERE name = '" + input + "'"); // EXPECT_SQLI
        stmt.executeBatch();
    }

    void unsafeStoredProcedure(Connection conn, String procedure) throws Exception {
        conn.prepareCall("{call " + procedure + "()}"); // EXPECT_SQLI
    }

    void fixedTableChoice(Connection conn, boolean archived, String input) throws Exception {
        String table = archived ? "archived_users" : "users";
        try (PreparedStatement query = conn.prepareStatement("SELECT * FROM " + table + " WHERE name = ?")) {
            query.setString(1, input);
            query.executeQuery();
        }
    }
}
