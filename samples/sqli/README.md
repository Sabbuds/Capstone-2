# SQL detection regression samples

These original, synthetic samples exercise Java/JDBC detection. They are not
an independent benchmark and do not establish real-world error rates.

Each `// EXPECT_SQLI` marks exactly one expected finding on that line. Every
other SQL call is a negative control. `SqliDetectionTest` reads every Java file
in this directory and compares exact finding locations against those markers.
Samples are parsed and type-checked; no database calls or sample methods run.

From the repository root, after compiling the detector:

```powershell
& "$jdk\java.exe" -cp out edu.fiu.capstone.skeleton.SqliDetectionTest
```

When running from elsewhere, pass this directory's absolute path as the first
argument to `SqliDetectionTest`.

The character-copy samples are vulnerable because input can change query
syntax. A long input is not required: for example, replacing `SELECT 1` with
`SELECT 2` changes the statement while fitting the destination buffer.
