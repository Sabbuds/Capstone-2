# Capstone security analysis

SQL injection (CWE-89) and command injection (CWE-78) detection for Java 17
source, running on JDK 17 or 21. Both detectors share parsing, symbol resolution
and data-flow analysis. Scanned code is never executed; annotation processing
and bytecode generation are disabled. No third-party runtime dependencies are
required.

**AI disclosure:** We used AI coding assistance to help implement, refactor and test the project.

## Start the UI on Windows

Install a JDK 17 or 21. From PowerShell in this repository, run:

```powershell
.\scripts\ui.ps1
# Or select your JDK and another port:
.\scripts\ui.ps1 -JavaHome 'C:\Program Files\Java\jdk-21.0.12' -Port 8080
```

Open http://localhost:8080. Stop the server with Ctrl+C. The app runs locally.
Node.js is only needed for browser tests.

Select a built-in sample, upload files, upload a folder, or drag a folder onto
the page. Supply UTF-8 Java 17 source files ending in `.java`. Include related
classes together for cross-file analysis. Supporting `.properties`, `.sh` and
`.bat` files are accepted with Java sources. Compiled `.class` files, dependency
JARs and ZIP archives are not source uploads. The encoded upload limit is 8 MB.
Build folders and unsupported files in a folder upload are skipped.

Under **Project dependencies**, enter one JAR or compiled class directory per
line. These paths refer to the computer running the scanner. Absolute paths and
paths relative to this repository are supported, including paths with spaces.
Dependencies apply to both sample scans and uploads. Missing paths produce a
visible error. Available dependencies improve type resolution, while compiler
and model diagnostics continue to indicate incomplete analysis.

Review findings, open **Show proposed change**, and select **With proposals** to
preview the combined changes for a file. **Download proposed file** saves that
preview under the original source filename. Copy it into a separate checkout
and run the target application's tests before accepting the changes. Overlapping
proposals are excluded from the combined file with a visible count. Remaining
manual findings still need developer attention. HTML and JSON reports describe
proposals and preserve diagnostics and dependency paths.

Command repair requires an explicit target profile. For applications that use
GNU `cat` on Linux, start the UI with:

```powershell
.\scripts\ui.ps1 -CommandProfile linux-gnu-cat
```

This enables proposals for the supported `sh`/`bash` `cat` patterns. Other
command findings receive manual guidance. The profile describes the scanned
application's intended runtime, regardless of the Windows scanner host.

## Build and test everything

Install Node.js 20+ with npm and Microsoft Edge in addition to the JDK. Run:

```powershell
.\scripts\test.ps1
# Or choose the installed JDK:
.\scripts\test.ps1 -JavaHome 'C:\Program Files\Java\jdk-21.0.12'
```

This single command compiles with `--release 17 -Xlint:all`, runs SQL and command
detection, detector contracts, both repair suites, harmless Java child-process
runtime checks, CLI integration, evaluation and UI service tests. It then runs
the browser tests in headless Edge using temporary local servers. The first run
installs the locked browser test dependency with `npm ci`. Internet access is
needed for that installation. Test servers and temporary source fixtures are
cleaned up afterward. Browser screenshots and report downloads stay in ignored
`.benchmark-cache/ui-tests/`.

Browser checks exercise uploads, dependency resolution, safe and vulnerable
samples, repair previews, downloaded-source compilation and rescanning, reports,
error recovery, themes and mobile layout. CI runs the same command on JDK 17
and 21. To rerun only the browser checks after compiling:

```powershell
npm run test:ui
```

Set `JAVA_HOME` to your JDK for that standalone command. `BROWSER_EXECUTABLE`
can select a different installed Chromium-based browser by absolute path.

## Project layout

| Location | Purpose |
| --- | --- |
| `ui/index.html` | Browser interface, previews and downloads |
| `src/edu/fiu/capstone/ui/` | Local server and scan/repair service |
| `src/edu/fiu/capstone/skeleton/` | Detectors, repair strategies, shared contracts and Java tests |
| `samples/demo/` | Small UI demo examples with predictable findings |
| `samples/sqli/`, `samples/command/` | Labeled detector regression samples |
| Other files in `samples/` | SQL repair, safe and legacy input fixtures used by tests and the UI |
| `scripts/` | Launch, full test, browser test and optional benchmark commands |

Build output, downloaded benchmark sources and Node dependencies are ignored.
The existing fixture filenames remain usable by the tests and the sample picker.

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

Omitting `--detect-only` displays SQL repair proposals. The UI also integrates
the command repair strategy when the supported target profile is supplied.

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

## Latest verification recorded 2026-11-19

On the final UI implementation, both JDK 17 and JDK 21 passed the 342 detector
checks, both repair suites, runtime argument checks, CLI integration, evaluation
and UI service tests. All 19 browser checks passed on both JDKs using Edge.
Downloaded SQL and command proposal files compiled and rescanned successfully.
The SQL download regression also covers multiple proposals in one method,
Unicode and CRLF preservation. Dependency directories and JARs resolved through
the upload UI. Screenshots were checked at desktop and mobile widths.

CI is configured to run the same checks for future pushes and pull requests.
Application-specific behavior after applying a proposal still requires that
application's own tests.

## Detector baseline recorded 2026-11-11

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
tests check transformations, downloaded-source compilation and rescanning.
Runtime checks verify literal argument handling with harmless Java child
processes. Run application behavior tests before accepting proposals. No
identical-input comparison against another analyzer is claimed.

## Credits and third-party licenses

Our team wrote the scanner, repair strategies, web interface, charts, reports,
synthetic examples and project tests, with AI coding assistance. The project
uses the following software and evaluation material. The license names apply
to the identified components and versions. Each component retains its own
license and bundled third-party notices.

| Piece and source | License | Use in this project |
| --- | --- | --- |
| [Team application and synthetic samples](https://github.com/Sabbuds/Capstone-2/tree/UI) | **Written by our team**, with AI coding assistance | Detection, repair proposals, UI, custom charts, reporting, demonstration fixtures and tests. |
| [Oracle JDK 21.0.12](https://www.oracle.com/downloads/licenses/no-fee-license.html) | Oracle No-Fee Terms and Conditions (NFTC), as included with the local installation | Runs the local scanner. Compiler APIs parse Java source and the built-in HTTP server serves the UI. |
| [Eclipse Temurin JDK 17 and 21](https://adoptium.net/docs/faq) | GNU GPL version 2 with the Classpath Exception | Java runtimes and compilers used by GitHub Actions compatibility tests. |
| [Playwright Core 1.65.1](https://github.com/microsoft/playwright/blob/main/LICENSE) | Apache License 2.0 | Browser automation for upload, repair-preview, download, report and layout tests. This is a development dependency. |
| [Node.js](https://github.com/nodejs/node/blob/main/LICENSE) | MIT, with additional notices for bundled components | Runs the browser-test script. CI uses Node.js 22. |
| [npm CLI](https://github.com/npm/cli/blob/latest/LICENSE) | Artistic License 2.0, with additional notices for dependencies | Installs locked development dependencies and runs browser tests. |
| [Microsoft Edge](https://explore.microsoft.com/edge/terms) | Microsoft Edge Software License Terms | Browser used for the local UI and automated browser tests. |
| [GitHub and GitHub Actions](https://docs.github.com/en/site-policy/github-terms/github-terms-of-service) | GitHub Terms of Service and applicable product terms | Repository hosting, pull requests and automated test execution. |
| [actions/checkout v6](https://github.com/actions/checkout/blob/v6/LICENSE) | MIT | Checks out the repository on test runners. |
| [actions/setup-java v5](https://github.com/actions/setup-java/blob/v5/LICENSE) | MIT | Installs and selects Temurin JDK 17 and 21 in CI. |
| [actions/setup-node v4](https://github.com/actions/setup-node/blob/v4/LICENSE) | MIT | Configures Node.js for browser tests in CI. |
| [OWASP Benchmark Java v1.2](https://github.com/OWASP-Benchmark/BenchmarkJava/tree/db99977cbf6b30236089a691136d718aa7bb6935), including original Java cases, helper sources, resources and expected labels | GNU GPL version 2. The fetch script retains the upstream [LICENSE](https://github.com/OWASP-Benchmark/BenchmarkJava/blob/db99977cbf6b30236089a691136d718aa7bb6935/LICENSE). | External labeled evaluation material downloaded into the ignored benchmark cache. The source revision is pinned and SHA-256 manifests verify downloaded inputs. |
| [OpenAI Codex](https://openai.com/policies/terms-of-use/) | Applicable OpenAI terms | AI coding assistance during implementation, refactoring, testing and documentation. |

The UI uses system fonts and project-authored charts and symbols.
Keep this list current when dependencies or demo assets change.
