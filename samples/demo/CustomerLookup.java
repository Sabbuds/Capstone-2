package demo;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.Statement;

/** Demo: SQL injection. Two findings the tool repairs, one it correctly refuses, one safe method. */
public class CustomerLookup {

    // Repaired automatically: the value becomes a bound ? parameter.
    public void findByEmail(Connection conn, String email) throws Exception {
        Statement stmt = conn.createStatement();
        // EXPECT_SQLI
        ResultSet rs = stmt.executeQuery("SELECT * FROM customers WHERE email = '" + email + "'");
        while (rs.next()) {
            System.out.println(rs.getString("name"));
        }
    }

    // Repaired automatically: both values become bound parameters.
    public void updateTier(Connection conn, String customerId, String tier) throws Exception {
        Statement stmt = conn.createStatement();
        // EXPECT_SQLI
        int updated = stmt.executeUpdate("UPDATE customers SET tier = '" + tier + "' WHERE id = '" + customerId + "'");
        System.out.println(updated + " row(s) updated");
    }

    // Refused: a column name cannot be a ? parameter. The fix is an allowlist, which needs a human.
    public void listSorted(Connection conn, String sortColumn) throws Exception {
        Statement stmt = conn.createStatement();
        // EXPECT_SQLI
        ResultSet rs = stmt.executeQuery("SELECT * FROM customers ORDER BY " + sortColumn);
        while (rs.next()) {
            System.out.println(rs.getString("name"));
        }
    }

    // Safe: already parameterized, so it is not flagged.
    public void findById(Connection conn, int customerId) throws Exception {
        PreparedStatement ps = conn.prepareStatement("SELECT * FROM customers WHERE id = ?");
        ps.setInt(1, customerId);
        ResultSet rs = ps.executeQuery();
        while (rs.next()) {
            System.out.println(rs.getString("name"));
        }
    }
}
