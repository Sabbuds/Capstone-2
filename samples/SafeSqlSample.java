import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.Statement;

public class SafeSqlSample {

    public void findUsers(Connection conn) throws Exception {
        String query = "SELECT * FROM users";

        try (Statement stmt = conn.createStatement();
             ResultSet rs = stmt.executeQuery(query)) {

            while (rs.next()) {
                System.out.println(rs.getString("name"));
            }
        }
    }
}