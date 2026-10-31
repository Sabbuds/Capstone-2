package sqli;

import java.sql.Statement;

public class AliasesAndSnapshots {
    void copiedStringCharacters(Statement stmt, String input) throws Exception {
        char[] query = {'S', 'E', 'L', 'E', 'C', 'T', ' ', '1'};
        input.getChars(0, Math.min(input.length(), query.length), query, 0);
        stmt.executeQuery(new String(query)); // EXPECT_SQLI
    }

    void copiedBuilderCharacters(Statement stmt, String input) throws Exception {
        char[] query = {'S', 'E', 'L', 'E', 'C', 'T', ' ', '1'};
        StringBuilder buffer = new StringBuilder(input);
        buffer.getChars(0, Math.min(buffer.length(), query.length), query, 0);
        stmt.executeQuery(new String(query)); // EXPECT_SQLI
    }

    void snapshotBeforeMutation(Statement stmt, String input) throws Exception {
        StringBuilder buffer = new StringBuilder("SELECT 1");
        String snapshot = buffer.toString();
        buffer.append(input);
        stmt.executeQuery(snapshot);
    }

    void snapshotAfterMutation(Statement stmt, String input) throws Exception {
        StringBuilder buffer = new StringBuilder("SELECT * FROM ");
        StringBuilder alias = buffer;
        alias.append(input);
        stmt.executeQuery(buffer.toString()); // EXPECT_SQLI
    }

    void constantCharacterCopy(Statement stmt) throws Exception {
        char[] query = new char[8];
        "SELECT 1".getChars(0, 8, query, 0);
        stmt.executeQuery(new String(query));
    }

    void castBuilderAlias(Statement stmt, String input) throws Exception {
        StringBuilder buffer = new StringBuilder("SELECT * FROM ");
        Object alias = buffer;
        ((StringBuilder) alias).append(input);
        stmt.executeQuery(buffer.toString()); // EXPECT_SQLI
    }

    void castArrayAlias(Statement stmt, String input) throws Exception {
        char[] query = {'S', 'E', 'L', 'E', 'C', 'T', ' ', '1'};
        Object alias = query;
        new StringBuilder(input).getChars(0, Math.min(input.length(), query.length), (char[]) alias, 0);
        stmt.executeQuery(new String(query)); // EXPECT_SQLI
    }
}
