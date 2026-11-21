package demo;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.Statement;

/** Demo: clean code. The scanner should report zero findings for this file. */
public class SafeReports {

    public void ordersForCustomer(Connection conn, String customerId) throws Exception {
        PreparedStatement ps = conn.prepareStatement("SELECT * FROM orders WHERE customer_id = ?");
        ps.setString(1, customerId);
        ResultSet rs = ps.executeQuery();
        while (rs.next()) {
            System.out.println(rs.getString("id"));
        }
    }

    public void totalOrders(Connection conn) throws Exception {
        Statement stmt = conn.createStatement();
        ResultSet rs = stmt.executeQuery("SELECT COUNT(*) FROM orders");
        if (rs.next()) {
            System.out.println(rs.getInt(1) + " orders");
        }
    }

    public void sortedOrders(Connection conn, String sortColumn) throws Exception {
        String column = switch (sortColumn) {
            case "date" -> "order_date";
            case "total" -> "total";
            default -> "id";
        };
        Statement stmt = conn.createStatement();
        ResultSet rs = stmt.executeQuery("SELECT * FROM orders ORDER BY " + column);
        while (rs.next()) {
            System.out.println(rs.getString("id"));
        }
    }
}
