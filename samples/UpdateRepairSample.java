import java.sql.Connection;
import java.sql.Statement;

public class UpdateRepairSample {

    public int deleteUser(Connection conn, String username)
            throws Exception {

        Statement stmt = conn.createStatement();

        int rows = stmt.executeUpdate("DELETE FROM users WHERE name = '" + username + "'");

        return rows;
    }
}