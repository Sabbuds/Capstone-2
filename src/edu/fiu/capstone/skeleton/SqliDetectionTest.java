package edu.fiu.capstone.skeleton;

import java.util.List;
import java.util.TreeSet;
import java.nio.file.Files;
import java.nio.file.Path;

public class SqliDetectionTest {

    private static int passed = 0;
    private static int failed = 0;

    public static void main(String[] args) throws Exception {
        SecurityLens lens = new RegexSqliLens();

        // Original regression tests
        test(lens, "Direct concatenation",
            "stmt.executeQuery(\"SELECT * FROM users WHERE name = '\" + username + \"'\");", 1);

        test(lens, "Static SQL",
            "stmt.executeQuery(\"SELECT * FROM users\");", 0);

        test(lens, "PreparedStatement",
            "PreparedStatement ps = conn.prepareStatement(\"SELECT * FROM users WHERE name = ?\");", 0);

        test(lens, "Query stored in variable",
            "String query = \"SELECT * FROM users WHERE name = '\" + username + \"'\";\nstmt.executeQuery(query);", 1);

        test(lens, "Multiline execution",
            "stmt.executeQuery(\n    \"SELECT * FROM users WHERE name = '\" + username + \"'\"\n);", 1);

        test(lens, "Ordinary string concatenation",
            "String message = \"Hello \" + username;", 0);

        test(lens, "Static query stored in variable",
            "String query = \"SELECT * FROM users\";\nstmt.executeQuery(query);", 0);

        test(lens, "Prepared statement execution",
            "PreparedStatement ps = conn.prepareStatement(\"SELECT * FROM users WHERE name = ?\");\nps.setString(1, username);\nps.executeQuery();", 0);

        test(lens, "Reassigned variable with SQL concatenation",
            "String query = \"SELECT * FROM users\";\nquery = \"SELECT * FROM users WHERE name = '\" + username + \"'\";\nstmt.executeQuery(query);", 1);

        test(lens, "Safe variable reassignment",
            "String query = \"SELECT * FROM users\";\nquery = \"SELECT * FROM orders\";\nstmt.executeQuery(query);", 0);

        test(lens, "SQL execution inside line comment",
            "// stmt.executeQuery(\"SELECT * FROM users WHERE name = '\" + username + \"'\");", 0);

        test(lens, "SQL execution inside block comment",
            "/* stmt.executeQuery(\"SELECT * FROM users WHERE name = '\" + username + \"'\"); */", 0);

        test(lens, "Comment markers inside SQL string",
            "stmt.executeQuery(\"SELECT * FROM users WHERE note = '-- comment'\");", 0);

        test(lens, "Fake SQL call inside string",
            "String example = \"stmt.executeQuery(\\\"SELECT * FROM users\\\")\";", 0);

        // New tests: additional execution methods
        test(lens, "executeUpdate with concatenation",
            "stmt.executeUpdate(\"UPDATE users SET name = '\" + username + \"'\");", 1);

        test(lens, "execute with concatenation",
            "stmt.execute(\"DELETE FROM users WHERE name = '\" + username + \"'\");", 1);

        // New tests: multiple assignments and data flow
        test(lens, "Query assembled from SQL prefix",
            "String prefix = \"SELECT * FROM users WHERE name = '\";\nString query = prefix + username + \"'\";\nstmt.executeQuery(query);", 1);

        test(lens, "Query copied through another variable",
            "String query = \"SELECT * FROM users WHERE name = '\" + username + \"'\";\nString finalQuery = query;\nstmt.executeQuery(finalQuery);", 1);

        // New tests: alternative query construction
        test(lens, "String.concat query construction",
            "String query = \"SELECT * FROM users WHERE name = '\".concat(username);\nstmt.executeQuery(query);", 1);

        test(lens, "StringBuilder query construction",
            "StringBuilder query = new StringBuilder(\"SELECT * FROM users WHERE name = '\");\nquery.append(username);\nquery.append(\"'\");\nstmt.executeQuery(query.toString());", 1);

        // New tests: safe patterns
        test(lens, "Concatenation unrelated to SQL execution",
            "String message = \"Welcome \" + username;\nstmt.executeQuery(\"SELECT * FROM users\");", 0);

        test(lens, "PreparedStatement with dynamic parameter",
            "PreparedStatement ps = conn.prepareStatement(\"SELECT * FROM users WHERE name = ?\");\nps.setString(1, username);\nResultSet rs = ps.executeQuery();", 0);

        // New tests: misleading source text
        test(lens, "SQL-looking text in comment",
            "// SELECT * FROM users WHERE name = '\" + username\nstmt.executeQuery(\"SELECT * FROM users\");", 0);

        test(lens, "SQL call text in ordinary string",
            "String message = \"executeQuery(SELECT * FROM users WHERE name = '\" + username;", 0);

        detectionEdgeCases(lens);
        sampleTests(lens, Path.of(args.length == 0 ? "samples/sqli" : args[0]));

        System.out.println();
        System.out.println("Tests completed: " + passed + "/" + (passed + failed) + " passed.");

        if (failed > 0) {
            throw new AssertionError(failed + " test(s) failed.");
        }
    }

    private static void sampleTests(SecurityLens lens, Path directory) throws Exception {
        try (var files = Files.list(directory)) {
            List<Path> samples = files.filter(p -> p.toString().endsWith(".java")).sorted().toList();
            if (samples.isEmpty()) throw new AssertionError("No SQL detection samples in " + directory);
            for (Path sample : samples) {
                String source = Files.readString(sample);
                TreeSet<Integer> expected = new TreeSet<>();
                String[] lines = source.split("\\R", -1);
                for (int i = 0; i < lines.length; i++) {
                    if (lines[i].contains("// EXPECT_SQLI")) expected.add(i + 1);
                }
                List<Finding> findings = lens.analyze(sample.getFileName().toString(), source);
                TreeSet<Integer> actual = new TreeSet<>();
                boolean correct = true;
                for (Finding finding : findings) {
                    actual.add(finding.line());
                    correct &= finding.cwe().equals("CWE-89")
                            && finding.file().equals(sample.getFileName().toString())
                            && finding.line() > 0 && finding.line() <= lines.length
                            && finding.snippet().equals(lines[finding.line() - 1].strip());
                }
                correct &= actual.equals(expected) && findings.size() == expected.size();
                if (correct) passed++; else failed++;
                System.out.printf("%s | Sample %-35s | expected lines=%s, actual=%s%n",
                        correct ? "PASS" : "FAIL", sample.getFileName(), expected, actual);
            }
        }
    }

    private static void detectionEdgeCases(SecurityLens lens) {
        test(lens, "Inline concat call",
            "stmt.executeQuery(\"SELECT * FROM users WHERE name = \".concat(name));", 1);
        test(lens, "Variable concat call",
            "String q = \"SELECT * FROM users WHERE name = \"; q = q.concat(name); stmt.executeQuery(q);", 1);
        test(lens, "Two variable concatenation",
            "String prefix = \"SELECT * FROM users WHERE name = \"; String q = prefix + name; stmt.executeQuery(q);", 1);
        test(lens, "Compound assignment",
            "String q = \"SELECT * FROM users WHERE name = \"; q += name; stmt.executeQuery(q);", 1);
        test(lens, "Dynamic query preparation",
            "conn.prepareStatement(\"SELECT * FROM users WHERE name = \" + name);", 1);
        test(lens, "Dynamic stored procedure preparation",
            "conn.prepareCall(\"{call \" + procedure + \"()}\");", 1);
        test(lens, "Dynamic batch",
            "stmt.addBatch(\"INSERT INTO users VALUES ('\" + name + \"')\"); stmt.executeBatch();", 1);
        test(lens, "Dynamic large update",
            "stmt.executeLargeUpdate(\"UPDATE users SET name = '\" + name + \"'\");", 1);
        test(lens, "Whole query from input", "stmt.executeQuery(request.getParameter(\"query\"));", 1);
        test(lens, "Unknown SQL argument", "stmt.executeQuery(query);", 1);
        test(lens, "DDL query", "stmt.execute(\"DROP TABLE \" + table);", 1);
        test(lens, "CTE query", "stmt.execute(\"WITH t AS (SELECT 1) SELECT * FROM \" + table);", 1);
        test(lens, "Constant variable concatenation",
            "String table = \"users\"; stmt.executeQuery(\"SELECT * FROM \" + table);", 0);
        test(lens, "Constant concatenation",
            "stmt.executeQuery(\"SELECT * \" + \"FROM users\");", 0);
        test(lens, "Parenthesized constant",
            "stmt.executeQuery((\"SELECT * FROM users\"));", 0);
        test(lens, "Escaped quote followed by input",
            "stmt.executeQuery(\"SELECT \\\"name\\\" FROM users WHERE name = \" + name);", 1);
        test(lens, "Literal quote across concat",
            "stmt.executeQuery(\"SELECT '\" + name + \"'\");", 1);
        test(lens, "Inline StringBuilder chain",
            "stmt.executeQuery(new StringBuilder(\"SELECT * FROM \" ).append(table).toString());", 1);
        test(lens, "Empty builder then query",
            "StringBuilder q = new StringBuilder(); q.append(\"SELECT * FROM \" ); q.append(table); stmt.executeQuery(q.toString());", 1);
        test(lens, "Builder initial dynamic value",
            "StringBuilder q = new StringBuilder(\"SELECT * FROM \" + table); stmt.executeQuery(q.toString());", 1);
        test(lens, "Builder chained mutation",
            "StringBuilder q = new StringBuilder(); q.append(\"SELECT * FROM \" ).append(table); stmt.executeQuery(q.toString());", 1);
        test(lens, "Builder alias mutation",
            "StringBuilder q = new StringBuilder(\"SELECT * FROM \" ); StringBuilder alias = q; alias.append(table); stmt.executeQuery(q.toString());", 1);
        test(lens, "Builder snapshot stays constant",
            "StringBuilder q = new StringBuilder(\"SELECT * FROM users\"); String snapshot = q.toString(); q.append(name); stmt.executeQuery(snapshot);", 0);
        test(lens, "Builder constant appends",
            "StringBuilder q = new StringBuilder(); q.append(\"SELECT * FROM \" ).append(\"users\"); stmt.executeQuery(q.toString());", 0);
        test(lens, "StringBuffer mutation",
            "StringBuffer q = new StringBuffer(\"SELECT * FROM \" ); q.append(table); stmt.executeQuery(q.toString());", 1);
        test(lens, "String format",
            "stmt.executeQuery(String.format(\"SELECT * FROM users WHERE name = '%s'\", name));", 1);
        test(lens, "String formatted",
            "stmt.executeQuery(\"SELECT * FROM %s\".formatted(table));", 1);
        test(lens, "Constant format",
            "stmt.executeQuery(String.format(\"SELECT * FROM %s\", \"users\"));", 0);
        test(lens, "SQL text block",
            "stmt.executeQuery(\"\"\"\nSELECT * FROM users\nWHERE name = '\n\"\"\" + name);", 1);
        test(lens, "Static SQL text block",
            "stmt.executeQuery(\"\"\"\nSELECT * FROM users\n\"\"\");", 0);
        test(lens, "Call text inside text block",
            "String example = \"\"\"\nstmt.executeQuery(\"SELECT * FROM \" + table);\n\"\"\";", 0);
        test(lens, "Prepared dynamic query reported once",
            "PreparedStatement ps = conn.prepareStatement(\"SELECT * FROM \" + table); ps.executeQuery();", 1);
        test(lens, "Prepared safe bindings",
            "PreparedStatement ps = conn.prepareStatement(\"SELECT * FROM users WHERE name = ?\"); ps.setString(1, name); ps.addBatch(); ps.executeBatch();", 0);
        test(lens, "SQL overload ignores generated key columns",
            "stmt.executeUpdate(\"INSERT INTO users DEFAULT VALUES\", columns);", 0);
        test(lens, "Unsafe SQL overload",
            "stmt.executeUpdate(\"UPDATE \" + table + \" SET active = 1\", columns);", 1);
        test(lens, "Safe overwrite removes risk",
            "String q = \"SELECT * FROM \" + table; q = \"SELECT * FROM users\"; stmt.executeQuery(q);", 0);
        test(lens, "Conditional unsafe overwrite",
            "String q = \"SELECT * FROM \" + table; if (flag) q = \"SELECT * FROM users\"; stmt.executeQuery(q);", 1);
        test(lens, "Conditional input branch",
            "String q = \"SELECT * FROM users\"; if (flag) q = \"SELECT * FROM \" + table; stmt.executeQuery(q);", 1);
        test(lens, "Both branches overwrite safely",
            "String q = name; if (flag) q = \"SELECT 1\"; else q = \"SELECT 2\"; stmt.executeQuery(q);", 0);
        test(lens, "Finite table allowlist",
            "String table; if (flag) table = \"users\"; else table = \"orders\"; stmt.executeQuery(\"SELECT * FROM \" + table);", 0);
        test(lens, "Ternary allowlist",
            "String table = flag ? \"users\" : \"orders\"; stmt.executeQuery(\"SELECT * FROM \" + table);", 0);
        test(lens, "Ternary input",
            "String table = flag ? input : \"users\"; stmt.executeQuery(\"SELECT * FROM \" + table);", 1);
        test(lens, "Loop may not overwrite",
            "String q = \"SELECT * FROM \" + table; while (flag) q = \"SELECT 1\"; stmt.executeQuery(q);", 1);
        test(lens, "Loop carries input to next iteration",
            "String q = \"SELECT 1\"; while (flag) { stmt.executeQuery(q); q = \"SELECT * FROM \" + table; }", 1);
        test(lens, "Nested scope preserves outer query",
            "String q = \"SELECT * FROM \" + table; { String q = \"SELECT 1\"; } stmt.executeQuery(q);", 1);
        test(lens, "Nested scope safe outer query",
            "String q = \"SELECT 1\"; { String q = \"SELECT * FROM \" + table; } stmt.executeQuery(q);", 0);
        test(lens, "No state leakage across methods",
            "class Dao { void a() { String q = \"SELECT * FROM \" + input; } void b() { String q = \"SELECT 1\"; stmt.executeQuery(q); } }", 0);
        test(lens, "Fields visible to methods",
            "class Dao { String q = \"SELECT * FROM \" + input; void run() { stmt.executeQuery(q); } }", 1);
        test(lens, "Field access through this",
            "class Dao { String q = \"SELECT * FROM \" + input; void run() { stmt.executeQuery(this.q); } }", 1);
        test(lens, "Numeric parameter",
            "class Dao { void run(int id) { stmt.executeQuery(\"SELECT * FROM users WHERE id = \" + id); } }", 0);
        test(lens, "Numeric parsing",
            "stmt.executeQuery(\"SELECT * FROM users WHERE id = \" + Integer.parseInt(input));", 0);
        test(lens, "Numeric literal", "stmt.executeQuery(\"SELECT * FROM users WHERE id = \" + 42);", 0);
        test(lens, "String parameter",
            "class Dao { void run(String id) { stmt.executeQuery(\"SELECT * FROM users WHERE id = \" + id); } }", 1);
        test(lens, "Typed executor is not a SQL sink",
            "class Job { void run(java.util.concurrent.Executor executor, Runnable task) { executor.execute(task); } }", 0);
        test(lens, "Typed unrelated query method",
            "class Job { void run(SearchClient client, String input) { client.executeQuery(\"SELECT \" + input); } }", 0);
        test(lens, "JDBC statement accepts whole query",
            "class Dao { void run(java.sql.Statement stmt, String input) { stmt.execute(input); } }", 1);
        test(lens, "Multiple independent findings",
            "stmt.executeQuery(\"SELECT * FROM \" + first); stmt.executeQuery(\"SELECT * FROM \" + second);", 2);
        test(lens, "Comments inside call",
            "stmt /* comment */ . executeQuery(\"SELECT * FROM \" /* comment */ + table);", 1);
        test(lens, "String replace is not SQL sanitization",
            "stmt.executeQuery(\"SELECT * FROM users WHERE name = '\" + input.replace(\"'\", \"''\") + \"'\");", 1);
        test(lens, "Switch keeps unsafe case",
            "String q = \"SELECT 1\"; switch (choice) { case 1: q = input; break; default: q = \"SELECT 2\"; } stmt.executeQuery(q);", 1);
        test(lens, "Switch without default keeps original",
            "String q = input; switch (choice) { case 1: q = \"SELECT 1\"; break; } stmt.executeQuery(q);", 1);
        test(lens, "Switch table allowlist",
            "String table; switch (choice) { case 1: table = \"users\"; break; default: table = \"orders\"; } stmt.executeQuery(\"SELECT * FROM \" + table);", 0);
        test(lens, "Switch expression allowlist",
            "String table = switch (choice) { case 1 -> \"users\"; default -> \"orders\"; }; stmt.executeQuery(\"SELECT * FROM \" + table);", 0);
        test(lens, "Switch expression input",
            "String table = switch (choice) { case 1 -> input; default -> \"orders\"; }; stmt.executeQuery(\"SELECT * FROM \" + table);", 1);
        test(lens, "Switch expression yield",
            "String table = switch (choice) { case 1 -> { yield \"users\"; } default -> { yield \"orders\"; } }; stmt.executeQuery(\"SELECT * FROM \" + table);", 0);
        test(lens, "Try catch keeps unsafe success path",
            "String q = \"SELECT 1\"; try { q = input; } catch (Exception e) { q = \"SELECT 2\"; } stmt.executeQuery(q);", 1);
        test(lens, "Exception can precede overwrite",
            "String q = input; try { mayThrow(); q = \"SELECT 1\"; } catch (Exception e) { } stmt.executeQuery(q);", 1);
        test(lens, "Exception can preserve intermediate value",
            "String q = \"SELECT 1\"; try { q = input; mayThrow(); q = \"SELECT 2\"; } catch (Exception e) { stmt.executeQuery(q); }", 1);
        test(lens, "Finally overwrites all paths",
            "String q = input; try { mayThrow(); } catch (Exception e) { q = input; } finally { q = \"SELECT 1\"; } stmt.executeQuery(q);", 0);
        test(lens, "Builder setCharAt introduces input",
            "StringBuilder q = new StringBuilder(\"SELECT * FROM users\"); q.setCharAt(0, input); stmt.executeQuery(q.toString());", 1);
        test(lens, "Builder replace introduces input",
            "StringBuilder q = new StringBuilder(\"SELECT * FROM users\"); q.replace(0, 1, input); stmt.executeQuery(q.toString());", 1);
        test(lens, "Builder clear removes input",
            "StringBuilder q = new StringBuilder(input); q.setLength(0); q.append(\"SELECT 1\"); stmt.executeQuery(q.toString());", 0);
        test(lens, "For loop input", "String q = \"SELECT 1\"; for (int i=0; i<2; i++) { stmt.executeQuery(q); q=input; }", 1);
        test(lens, "Enhanced for input", "for (String q : queries) { stmt.executeQuery(q); }", 1);
        test(lens, "Do while overwrite runs at least once",
            "String q = input; do { q=\"SELECT 1\"; } while (flag); stmt.executeQuery(q);", 0);
        test(lens, "Lambda detection",
            "Runnable task = () -> stmt.executeQuery(\"SELECT * FROM \" + input);", 1);
        test(lens, "Constant helper return",
            "class Dao { String sql() { return \"SELECT 1\"; } void run() { stmt.executeQuery(sql()); } }", 0);
        test(lens, "Helper argument propagation",
            "class Dao { String sql(String table) { return \"SELECT * FROM \" + table; } void run() { stmt.executeQuery(sql(\"users\")); } }", 0);
        test(lens, "Unsafe helper argument",
            "class Dao { String sql(String table) { return \"SELECT * FROM \" + table; } void run(String input) { stmt.executeQuery(sql(input)); } }", 1);
        test(lens, "Numeric helper return",
            "class Dao { int id(String input) { return Integer.parseInt(input); } void run(String input) { stmt.executeQuery(\"SELECT * FROM users WHERE id = \" + id(input)); } }", 0);
        test(lens, "Unused format argument is safe",
            "stmt.executeQuery(String.format(\"SELECT 1\", input));", 0);
        test(lens, "Numeric format conversion is safe",
            "stmt.executeQuery(String.format(\"SELECT * FROM users WHERE id = %d\", input));", 0);
        test(lens, "Format argument index",
            "stmt.executeQuery(String.format(\"SELECT * FROM %2$s\", input, \"users\"));", 0);
        test(lens, "Format reused argument",
            "stmt.executeQuery(String.format(\"SELECT * FROM %2$s WHERE name = '%<s'\", \"users\", input));", 1);
        test(lens, "String copy of numeric remains numeric-safe",
            "class Dao { void run(int id) { String s = Integer.toString(id); stmt.executeQuery(\"SELECT * FROM users WHERE id = \" + s); } }", 0);
        test(lens, "Comparison boolean is safe",
            "stmt.executeQuery(\"SELECT * FROM users WHERE active = \" + (input == null));", 0);
        test(lens, "Unknown helper builder mutation",
            "StringBuilder q = new StringBuilder(\"SELECT 1\"); fill(q, input); stmt.executeQuery(q.toString());", 1);
        test(lens, "Array initializer nested SQL call",
            "Object[] result = { stmt.executeQuery(\"SELECT * FROM \" + input) };", 1);
        test(lens, "Possible builder alias survives branch",
            "StringBuilder q = new StringBuilder(\"SELECT 1\"); StringBuilder alias = q; if (flag) q = new StringBuilder(\"SELECT 2\"); alias.append(input); stmt.executeQuery(q.toString());", 1);
        test(lens, "Array element mutation",
            "String[] queries = {\"SELECT 1\"}; queries[0] = input; stmt.executeQuery(queries[0]);", 1);
        test(lens, "Array constant allowlist",
            "String[] tables = {\"users\", \"orders\"}; stmt.executeQuery(\"SELECT * FROM \" + tables[index]);", 0);
        test(lens, "Typed numeric method result",
            "int id = service.getId(); stmt.executeQuery(\"SELECT * FROM users WHERE id = \" + id);", 0);
        test(lens, "Typed numeric reassignment",
            "int id = 1; id = service.getId(); stmt.executeQuery(\"SELECT * FROM users WHERE id = \" + id);", 0);
        test(lens, "Field mutation across methods",
            "class Dao { String q = \"SELECT 1\"; void run() { stmt.executeQuery(q); } void set(String input) { q = input; } }", 1);
        test(lens, "Uninitialized field set across methods",
            "class Dao { String q; void run() { stmt.executeQuery(q); } void set(String input) { q = input; } }", 1);
        test(lens, "Constructor constant field",
            "class Dao { String q; Dao() { q = \"SELECT 1\"; } void run() { stmt.executeQuery(q); } }", 0);
        test(lens, "Constant helper inside try",
            "class Dao { String sql() { return \"SELECT 1\"; } void run() { String q = \"SELECT 1\"; try { q = sql(); } catch(Exception e) { stmt.executeQuery(q); } } }", 0);
        test(lens, "Short circuit must preserve input",
            "String q = input; boolean ignored = flag && ((q = \"SELECT 1\") != null); stmt.executeQuery(q);", 1);
        test(lens, "Recursive helper terminates",
            "class Dao { String sql(String input) { return flag ? input : sql(input); } void run(String input) { stmt.executeQuery(sql(input)); } }", 1);
        test(lens, "Break retains unsafe loop exit",
            "String q = \"SELECT 1\"; while (flag) { if (choice) { q = input; break; } q = \"SELECT 2\"; } stmt.executeQuery(q);", 1);
        test(lens, "Continue carries input to next iteration",
            "String q = \"SELECT 1\"; while (flag) { stmt.executeQuery(q); if (choice) { q = input; continue; } q = \"SELECT 2\"; }", 1);
        test(lens, "Returning branch cannot reach sink",
            "String q = \"SELECT 1\"; if (flag) { q = input; return; } stmt.executeQuery(q);", 0);
        test(lens, "Throwing branch cannot reach sink",
            "String q = \"SELECT 1\"; if (flag) { q = input; throw new RuntimeException(); } stmt.executeQuery(q);", 0);
        test(lens, "Do while break keeps query",
            "String q = input; do { if (flag) break; q = \"SELECT 1\"; } while (again); stmt.executeQuery(q);", 1);
        test(lens, "Character cast can inject syntax",
            "class Dao { void run(int input) { stmt.executeQuery(\"SELECT '\" + (char) input + \"'\"); } }", 1);
        test(lens, "Code point builder mutation",
            "class Dao { void run(int input) { StringBuilder q = new StringBuilder(\"SELECT '\"); q.appendCodePoint(input); q.append(\"'\"); stmt.executeQuery(q.toString()); } }", 1);
        test(lens, "Qualified constant field",
            "class Dao { static final String SQL = \"SELECT 1\"; void run() { stmt.executeQuery(Dao.SQL); } }", 0);
        test(lens, "Lambda return does not stop outer scan",
            "Runnable task = () -> { return; }; stmt.executeQuery(\"SELECT * FROM \" + input);", 1);
        test(lens, "Labeled break preserves outer exit",
            "String q = \"SELECT 1\"; outer: while(flag) { while(other) { q = input; break outer; } q = \"SELECT 2\"; } stmt.executeQuery(q);", 1);
        test(lens, "Labeled continue carries input",
            "String q = \"SELECT 1\"; outer: while(flag) { stmt.executeQuery(q); while(other) { q = input; continue outer; } q = \"SELECT 2\"; }", 1);
        test(lens, "Local unrelated method is not a sink",
            "class Search { void executeQuery(String input) { log(input); } void run(String input) { executeQuery(input); } }", 0);
        test(lens, "SQL wrapper reports actual sink once",
            "class Dao { void executeQuery(String input) { stmt.executeQuery(input); } void run(String input) { executeQuery(input); } }", 1);
        test(lens, "JDBC subinterface",
            "interface CustomStatement extends java.sql.Statement {} class Dao { void run(CustomStatement stmt, String input) throws Exception { stmt.executeQuery(\"SELECT * FROM \" + input); } }", 1);
        test(lens, "JDBC subtype chain",
            "interface A extends java.sql.Statement {} interface B extends A {} class Dao { void run(B stmt, String input) throws Exception { stmt.execute(input); } }", 1);
        test(lens, "PreparedStatement subinterface",
            "interface CustomPrepared extends java.sql.PreparedStatement {} class Dao { void run(CustomPrepared stmt, String input) throws Exception { stmt.executeQuery(\"SELECT * FROM \" + input); } }", 1);
        test(lens, "Connection subinterface",
            "interface CustomConnection extends java.sql.Connection {} class Dao { void run(CustomConnection conn, String input) throws Exception { conn.prepareStatement(\"SELECT * FROM \" + input); } }", 1);
        test(lens, "Unrelated Statement name",
            "class Statement { void executeQuery(String text) {} } class Dao { void run(Statement stmt, String input) { stmt.executeQuery(\"SELECT * FROM \" + input); } }", 0);
        test(lens, "Unrelated Integer name",
            "class Integer { static String parseInt(String input) { return input; } } class Dao { void run(java.sql.Statement stmt, String input) throws Exception { stmt.executeQuery(\"SELECT * FROM \" + Integer.parseInt(input)); } }", 1);
        test(lens, "External constant helper",
            "class Constants { static String table() { return \"users\"; } } class Dao { void run(java.sql.Statement stmt) throws Exception { stmt.executeQuery(\"SELECT * FROM \" + Constants.table()); } }", 0);
        test(lens, "External helper declared later",
            "class Dao { void run(java.sql.Statement stmt) throws Exception { stmt.executeQuery(\"SELECT * FROM \" + Constants.table()); } } class Constants { static String table() { return \"users\"; } }", 0);
        test(lens, "External helper argument",
            "class Builder { static String sql(String table) { return \"SELECT * FROM \" + table; } } class Dao { void run(java.sql.Statement stmt) throws Exception { stmt.executeQuery(Builder.sql(\"users\")); } }", 0);
        test(lens, "External helper input",
            "class Builder { static String sql(String table) { return \"SELECT * FROM \" + table; } } class Dao { void run(java.sql.Statement stmt, String input) throws Exception { stmt.executeQuery(Builder.sql(input)); } }", 1);
        test(lens, "External constant field helper",
            "class Constants { static final String TABLE = \"users\"; static String table() { return TABLE; } } class Dao { void run(java.sql.Statement stmt) throws Exception { stmt.executeQuery(\"SELECT * FROM \" + Constants.table()); } }", 0);
        test(lens, "External qualified constant field",
            "class Constants { static final String TABLE = \"users\"; } class Dao { void run(java.sql.Statement stmt) throws Exception { stmt.executeQuery(\"SELECT * FROM \" + Constants.TABLE); } }", 0);
        test(lens, "Resolved helper overload",
            "class Builder { static String sql(String table) { return \"SELECT * FROM \" + table; } static String sql(int id) { return \"SELECT 1\"; } } class Dao { void run(java.sql.Statement stmt) throws Exception { stmt.executeQuery(Builder.sql(1)); } }", 0);
        test(lens, "Unreachable false branch",
            "class Dao { void run(java.sql.Statement stmt, String input) throws Exception { if (false) stmt.executeQuery(\"SELECT * FROM \" + input); } }", 0);
        test(lens, "Unreachable else branch",
            "class Dao { void run(java.sql.Statement stmt, String input) throws Exception { if (true) {} else stmt.executeQuery(\"SELECT * FROM \" + input); } }", 0);
        test(lens, "False branch cannot taint query",
            "String q = \"SELECT 1\"; if (false) q = input; stmt.executeQuery(q);", 0);
        test(lens, "True branch replaces input",
            "String q = input; if (true) q = \"SELECT 1\"; stmt.executeQuery(q);", 0);
        test(lens, "Constant boolean variable",
            "boolean flag = false; if (flag) stmt.executeQuery(\"SELECT * FROM \" + input);", 0);
        test(lens, "Constant comparison branch",
            "if (1 == 2) stmt.executeQuery(\"SELECT * FROM \" + input);", 0);
        test(lens, "False while condition",
            "while (false) { stmt.executeQuery(\"SELECT * FROM \" + input); }", 0);
        test(lens, "False for condition",
            "for (; false;) { stmt.executeQuery(\"SELECT * FROM \" + input); }", 0);
        test(lens, "Do while false still executes",
            "do { stmt.executeQuery(\"SELECT * FROM \" + input); } while (false);", 1);
        test(lens, "Constant ternary excludes input",
            "stmt.executeQuery(true ? \"SELECT 1\" : input);", 0);
        test(lens, "Short circuit skips unsafe call",
            "boolean ignored = false && stmt.execute(\"SELECT * FROM \" + input);", 0);
        test(lens, "Short circuit skips false overwrite",
            "String q = input; boolean ignored = false && ((q = \"SELECT 1\") != null); stmt.executeQuery(q);", 1);
        test(lens, "Guarded exact table allowlist",
            "if (!\"users\".equals(table)) throw new IllegalArgumentException(); stmt.executeQuery(\"SELECT * FROM \" + table);", 0);
        test(lens, "Guarded multiple table allowlist",
            "if (!\"users\".equals(table) && !\"orders\".equals(table)) return; stmt.executeQuery(\"SELECT * FROM \" + table);", 0);
        test(lens, "Nonrestrictive allowlist check",
            "if (\"users\".equals(table)) log(table); stmt.executeQuery(\"SELECT * FROM \" + table);", 1);
        test(lens, "Immutable Set allowlist guard",
            "class Dao { void run(java.sql.Statement stmt, String table) throws Exception { if (!java.util.Set.of(\"users\", \"orders\").contains(table)) throw new IllegalArgumentException(); stmt.executeQuery(\"SELECT * FROM \" + table); } }", 0);
        test(lens, "Immutable List allowlist variable",
            "class Dao { void run(java.sql.Statement stmt, String table) throws Exception { java.util.List<String> allowed = java.util.List.of(\"users\", \"orders\"); if (allowed.contains(table)) stmt.executeQuery(\"SELECT * FROM \" + table); } }", 0);
        test(lens, "Untrusted collection cannot validate input",
            "class Dao { void run(java.sql.Statement stmt, String table, java.util.Set<String> allowed) throws Exception { if (allowed.contains(table)) stmt.executeQuery(\"SELECT * FROM \" + table); } }", 1);
        test(lens, "Nonrestrictive collection check",
            "class Dao { void run(java.sql.Statement stmt, String table) throws Exception { java.util.Set.of(\"users\").contains(table); stmt.executeQuery(\"SELECT * FROM \" + table); } }", 1);
        test(lens, "Allowlist alternative does not restrict input",
            "String table = input; if (\"users\".equals(table) || flag) stmt.executeQuery(\"SELECT * FROM \" + table);", 1);
        test(lens, "Floating point promotion keeps reachable sink",
            "if (16777217L == 16777216f) stmt.executeQuery(\"SELECT * FROM \" + input);", 1);
        test(lens, "Signed zero comparison keeps reachable sink",
            "if (-0.0 == 0.0) stmt.executeQuery(\"SELECT * FROM \" + input);", 1);
        test(lens, "Boxed equality is not numeric equality",
            "Integer a = 1000; Integer b = 1000; if (a != b) stmt.executeQuery(\"SELECT * FROM \" + input);", 1);
        test(lens, "Numeric lookalike constructor is untrusted",
            "class Integer { Integer(String input) {} public String toString() { return input; } String input; } class Dao { void run(java.sql.Statement stmt, String input) throws Exception { stmt.executeQuery(\"SELECT * FROM \" + new Integer(input)); } }", 1);
        test(lens, "Varargs helper constants",
            "class Builder { static String sql(String... tables) { return \"SELECT * FROM \" + tables[0]; } } class Dao { void run(java.sql.Statement stmt) throws Exception { stmt.executeQuery(Builder.sql(\"users\", \"orders\")); } }", 0);
        test(lens, "Varargs helper input",
            "class Builder { static String sql(String... tables) { return \"SELECT * FROM \" + tables[0]; } } class Dao { void run(java.sql.Statement stmt, String input) throws Exception { stmt.executeQuery(Builder.sql(input, \"orders\")); } }", 1);
        test(lens, "Empty varargs helper",
            "class Builder { static String sql(String... tables) { return \"SELECT 1\"; } } class Dao { void run(java.sql.Statement stmt) throws Exception { stmt.executeQuery(Builder.sql()); } }", 0);
        test(lens, "Explicit array for varargs helper",
            "class Builder { static String sql(String... tables) { return \"SELECT * FROM \" + tables[0]; } } class Dao { void run(java.sql.Statement stmt) throws Exception { stmt.executeQuery(Builder.sql(new String[] {\"users\", \"orders\"})); } }", 0);
        test(lens, "Case insensitive literal allowlist",
            "String table = input; if (!\"users\".equalsIgnoreCase(table)) return; stmt.executeQuery(\"SELECT * FROM \" + table);", 0);
        test(lens, "Actual input remains on feasible branch",
            "if (true) stmt.executeQuery(\"SELECT * FROM \" + input);", 1);
        test(lens, "Locale format constant arguments",
            "stmt.executeQuery(String.format(java.util.Locale.ROOT, \"SELECT * FROM %s\", \"users\"));", 0);
        test(lens, "Locale format input",
            "stmt.executeQuery(String.format(java.util.Locale.ROOT, \"SELECT * FROM %s\", input));", 1);
        test(lens, "Format explicit constant varargs array",
            "stmt.executeQuery(String.format(\"SELECT %s FROM %s\", new Object[] {\"name\", \"users\"}));", 0);
        test(lens, "Format explicit unsafe varargs array",
            "stmt.executeQuery(String.format(\"SELECT %s FROM %s\", new Object[] {\"name\", input}));", 1);
        test(lens, "Cross class helper inside exception path",
            "class Dao { void run(java.sql.Statement stmt) throws Exception { String q = \"SELECT 1\"; try { q = Constants.sql(); } catch(Exception e) { stmt.executeQuery(q); } } } class Constants { static String sql() { return \"SELECT 1\"; } }", 0);
        test(lens, "Narrowing numeric cast keeps reachable sink",
            "if ((byte)256 == 0) stmt.executeQuery(\"SELECT * FROM \" + input);", 1);

        try {
            lens.analyze("Broken.java", "stmt.executeQuery(\"unterminated);");
            throw new AssertionError("Malformed source was silently accepted");
        } catch (IllegalArgumentException expected) {
            // A parse failure must not look like a clean security scan.
        }

        List<Finding> findings = lens.analyze("Location.java",
            "// header\r\nString q = \"SELECT * FROM \" + input;\r\nstmt.executeQuery(q);\r\n");
        if (findings.size() != 1 || findings.get(0).line() != 3
                || !findings.get(0).file().equals("Location.java")
                || !findings.get(0).cwe().equals("CWE-89")
                || !findings.get(0).snippet().equals("stmt.executeQuery(q);")) {
            throw new AssertionError("Finding location/contract changed: " + findings);
        }
    }

    private static void test(
            SecurityLens lens, String name, String source, int expected) {

        List<Finding> findings = lens.analyze("Test.java", source);
        int actual = findings.size();

        if (actual == expected) {
            passed++;
            System.out.printf("PASS | %-42s | expected=%d, actual=%d%n",
                    name, expected, actual);
        } else {
            failed++;
            System.out.printf("FAIL | %-42s | expected=%d, actual=%d%n",
                    name, expected, actual);
        }
    }
}
