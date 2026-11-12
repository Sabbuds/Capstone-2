# Capstone security analysis

SQL injection (CWE-89) and command injection (CWE-78) detection for Java 17
source, running on JDK 17 or 21. Both detectors share parsing, symbol resolution
and data-flow analysis. Scanned code is never executed; annotation processing
and bytecode generation are disabled. No third-party runtime dependencies are
required.

## Build and test

From PowerShell in this repository:

```powershell
.\scripts\test.ps1
# Or select an installed JDK:
.\scripts\test.ps1 -JavaHome 'C:\Program Files\Java\jdk-21.0.12'
```

The script compiles with `--release 17 -Xlint:all` and runs both detection
suites, detector-contract tests, existing SQL repair tests, CLI integration
and evaluation tests. CI runs the same script on JDK 17 and 21. Command sample
methods are never invoked.

## Run detection

After building, with your selected JDK's `java` on PATH:

```powershell
java -cp out edu.fiu.capstone.skeleton.Main --detect-only samples\Vulnerabledao.txt
java -cp out edu.fiu.capstone.skeleton.Main --detect-only samples\command
java -cp out edu.fiu.capstone.skeleton.Main --detect-only --classpath 'lib\servlet-api.jar;lib\spring-jdbc.jar' path\to\project
```

Supply one source file or a directory. A directory is analyzed as one source
bundle, enabling calls between files. Build/cache directories are skipped.
Directory scans also supply `.properties`, `.sh` and `.bat` text resources,
including aliases relative to `resources/` directories. Conflicting aliases
fail explicitly. Dependency jars/directories use the OS classpath separator.

Findings retain the original filename, line and snippet. Missing types,
unmodeled operations and analysis limits produce diagnostics and an
`Analysis INCOMPLETE` message. Syntax errors and unreadable inputs fail
explicitly. **CLI exit status alone is not a clean-scan indicator:** incomplete
analysis can still exit successfully. Check structured diagnostics even when
there are no findings.

Omitting `--detect-only` also displays existing repair proposals. The CLI never
modifies scanned files. SQL repair implementation and reporting contracts remain
the team's responsibility; no command repair is generated.

## Detector API and team handoff

```java
SecurityLens detector = new SecurityAnalyzer(); // both detectors, one parse
DetectionResult result = detector.analyze(new DetectionRequest(
    Map.of("Controller.java", controllerSource, "Dao.java", daoSource),
    Set.of("Controller.java"),       // entry files to inspect
    List.of(Path.of("lib/api.jar")), // optional dependency jars/directories
    Map.of("app.properties", configurationText) // optional text resources
));
List<Finding> findings = result.findings();
List<DetectionDiagnostic> diagnostics = result.diagnostics();
boolean analysisComplete = result.complete();
```

Use real filenames and supply available dependencies. All methods in entry
files are inspected; other supplied sources support symbol resolution and
reachable helper analysis. Findings can point into helper files: preserve their
reported paths. Resources use classpath-style names. Analysis does not read
arbitrary application files or execute reflection.

`new DetectionRequest(sources)` selects every supplied file as an entry.
`DetectionRequest.source(name, text)` creates a single-file request. Use
`RegexSqliLens` for SQL only or `CommandInjectionLens` for commands only. The
historical SQL class name and lens ID remain compatible.

The existing `analyze(String fileName, String sourceCode)` method still returns
`List<Finding>` for older callers. It discards diagnostics for compatibility;
new integrations should use `DetectionResult`. Result collections are immutable.
`complete()` means no compiler/model diagnostics within the supported analysis
contract. It is not a proof that arbitrary Java code is secure.

| Class | Responsibility |
| --- | --- |
| `JavaSources` | Parsing, dependency resolution and compiler resources |
| `JavaSecurityAnalyzer` | Control flow, source calls, object state and sinks |
| `FlowValue` | Abstract values, alias/state copying and branch joins |
| `LibraryModels` | Modeled JDK strings, collections, processes and paths |
| Detector adapters | Small public SQL, command and combined entry points |

## Supported detection behavior

The engine follows assignments, aliases, constants, finite literal choices,
branches, switches, loops, exception paths, arrays, builders, lists, maps,
properties and available source helpers. It carries constructor arguments and
object fields across files and resolves known source-backed interface
implementations. Findings identify execution/preparation sinks, rather than
every string concatenation or unused process builder.

SQL models cover JDBC execution, queries, updates, large updates, batches and
statement preparation; Spring JDBC query/update/execute families; and
JPA/Hibernate query construction. Separately bound parameter values are negative
controls. Preparing SQL already constructed from unsafe input still warns.
Type information distinguishes SQL APIs from unrelated methods with similar
names. Unresolved APIs remain conservative and expose dependency/model diagnostics
where appropriate.

Command models cover `Runtime.exec`, `ProcessBuilder.start` and `startPipeline`,
command replacement/backing-list mutation, executable selection, environment
mutation, explicit Unix/Windows shells, PowerShell and common interpreter/launcher
forms. Unsafe writes to known shell/interpreter process stdin are checked.
A fixed ordinary executable with separate data arguments is a negative control.
Numeric conversion does not make input-selected executables or environments
safe. String-form `Runtime.exec` tokenization is modeled separately from shells.

Supplied properties resources and bounded source-backed reflective construction
are modeled. Unknown runtime types, unavailable code, unsupported callbacks,
ambiguous reflection and missing resources cannot be assumed safe: diagnostics
expose these boundaries. Arbitrary third-party libraries, concurrency, native
behavior, complete interpreter/script semantics and tool-specific option
injection (CWE-88) are outside this detector contract. Separate arguments can
still carry application-specific risks.

Work is bounded to 200,000 steps per check, expression depth 256 and 64 active
helper calls. A limit returns a diagnostic and findings collected so far.
Unsupported behavior must not be presented as a complete clean scan. No finite
static analyzer guarantees zero false positives and negatives for arbitrary code.

## Verification recorded 2026-11-11

The final code passed on installed JDK 17 and JDK 21:

- 198 SQL detection checks.
- 72 command detection checks.
- 72 detector-contract checks, including source bundles, classpaths, resources,
  object/collection flow, diagnostics, limits and source locations.
- Existing SQL repair tests, CLI/source-preservation integration tests and
  confusion-matrix/metric-denominator tests.

The synthetic development corpus reports SQL TP=22, TN=17 and command TP=6,
TN=4, with no false positives or negatives. These are regression data, not
independent estimates of real-world accuracy.

### Reproduce the public benchmark subset

```powershell
.\scripts\fetch-benchmark.ps1
java -cp out edu.fiu.capstone.skeleton.PublicBenchmarkEvaluation development
java -cp out edu.fiu.capstone.skeleton.PublicBenchmarkEvaluation validation
```

The fetch script downloads original [OWASP Benchmark Java](https://github.com/OWASP-Benchmark/BenchmarkJava)
v1.2 sources, expected labels, six supporting source files, three resources and
the GPL-2.0 license at commit `db99977cbf6b30236089a691136d718aa7bb6935`.
They remain in ignored `.benchmark-cache`; sources are not vendored into samples
or executed. SHA-256 manifests verify source/support/resource inputs.

Selection v3 takes the first 20 IDs per category/label combination
(`sqli`/`cmdi`, positive/negative): 80 cases. The first 15 per group form 60
development cases; the next five form 20 fresh validation cases. Previously
inspected cases were moved into development. Final validation ran after freezing
detector changes and was not used for subsequent tuning. Helper sources and
resources are supplied, but servlet/framework dependencies are not. Earlier
standalone measurements used different inputs and are not an identical-input
comparison.

| Split | Detector | TP | FP | TN | FN | Incomplete analyses |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| Development | SQL | 15 | 0 | 15 | 0 | 30/30 |
| Development | Command | 15 | 0 | 15 | 0 | 30/30 |
| Fresh validation | SQL | 5 | 0 | 5 | 0 | 10/10 |
| Fresh validation | Command | 5 | 0 | 5 | 0 | 10/10 |

All cases remain in scores, including incomplete analyses. Every benchmark
analysis had dependency/model diagnostics: the table measures finding
predictions, not certified clean scans. This small ID-selected subset is neither
random nor the full benchmark. Do not claim universal accuracy from it.
FNR is `FN/(TP+FN)`, FPR is `FP/(FP+TN)`, precision is `TP/(TP+FP)`;
empty denominators are `N/A`.

Application behavior preservation after repairs is unmeasured. Existing repair
tests check transformations and compilation; the team should run application
behavior tests before accepting proposals. No identical-input comparison against
another analyzer is claimed.
