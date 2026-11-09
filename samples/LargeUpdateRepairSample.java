 import java.sql.Connection;
import java.sql.Statement;

public class LargeUpdateRepairSample {

    public long deleteUser(Connection conn, String username)
            throws Exception {

        Statement stmt = conn.createStatement();

        long rows = stmt.executeLargeUpdate("DELETE FROM users WHERE name = '" + username + "'");

        return rows;
    }
}

