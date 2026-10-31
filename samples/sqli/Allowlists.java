package sqli;

import java.sql.Statement;
import java.util.Set;

public class Allowlists {
    void enforcedAllowlist(Statement stmt, String table) throws Exception {
        if (!Set.of("users", "orders").contains(table)) throw new IllegalArgumentException();
        stmt.executeQuery("SELECT * FROM " + table);
    }

    void ignoredCheck(Statement stmt, String table) throws Exception {
        Set.of("users", "orders").contains(table);
        stmt.executeQuery("SELECT * FROM " + table); // EXPECT_SQLI
    }

    void untrustedAllowlist(Statement stmt, Set<String> allowed, String table) throws Exception {
        if (allowed.contains(table)) {
            stmt.executeQuery("SELECT * FROM " + table); // EXPECT_SQLI
        }
    }

    void fixedNumericValue(Statement stmt, String input) throws Exception {
        int id = Integer.parseInt(input);
        stmt.executeQuery("SELECT * FROM users WHERE id = " + id);
    }

    void unreachableQuery(Statement stmt, String input) throws Exception {
    }
}
