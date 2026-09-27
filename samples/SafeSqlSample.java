public class SafeSqlSample {

    public void findUsers() {
        String query = "SELECT * FROM users";
        stmt.executeQuery(query);
    }
}