import java.sql.Connection;
import java.sql.ResultSet;

public class RepairedDao {
    public void findUserByName(Connection conn, String username)
            throws Exception {

        String query = "SELECT * FROM users WHERE name = ?";

        java.sql.PreparedStatement __ps =
            conn.prepareStatement(query);

        __ps.setString(1, username);

        ResultSet rs = __ps.executeQuery();

        while (rs.next()) {
            System.out.println(rs.getString("email"));
        }
    }
    
}
