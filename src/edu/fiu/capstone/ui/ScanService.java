package edu.fiu.capstone.ui;

import com.sun.source.tree.ClassTree;
import com.sun.source.tree.CompilationUnitTree;
import com.sun.source.tree.MethodTree;
import com.sun.source.util.JavacTask;
import com.sun.source.util.TreeScanner;
import com.sun.source.util.Trees;
import edu.fiu.capstone.skeleton.CommandInjectionRepair;
import edu.fiu.capstone.skeleton.DetectionDiagnostic;
import edu.fiu.capstone.skeleton.DetectionRequest;
import edu.fiu.capstone.skeleton.DetectionResult;
import edu.fiu.capstone.skeleton.Finding;
import edu.fiu.capstone.skeleton.NaiveSqliRepair;
import edu.fiu.capstone.skeleton.RepairOutcome;
import edu.fiu.capstone.skeleton.RepairStrategy;
import edu.fiu.capstone.skeleton.SecurityAnalyzer;
import java.io.IOException;
import java.net.URI;
import java.nio.file.FileVisitResult;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.SimpleFileVisitor;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import javax.tools.JavaFileObject;
import javax.tools.SimpleJavaFileObject;
import javax.tools.ToolProvider;

/**
 * Runs detection plus repair for the UI and scores detection against EXPECT_* labels.
 * Scanned code is never executed or modified; repairs are returned as proposals only.
 */
public final class ScanService {
    /** A labeled category: findings with {@code cwe} are expected only in methods marked with {@code marker}. */
    public record Category(String key, String label, String cwe, String marker) {}

    public static final List<Category> CATEGORIES = List.of(
            new Category("sql", "SQL injection", "CWE-89", "EXPECT_SQLI"),
            new Category("command", "Command injection", "CWE-78", "EXPECT_COMMAND"));

    /** System property that declares the target command environment; enables the command-injection repair. */
    public static final String COMMAND_PROFILE_PROPERTY = "capstone.target.commandProfile";

    /** Method-level confusion matrix, matching {@code DetectionEvaluation}'s methodology. */
    public record Score(int tp, int fp, int tn, int fn) {
        static final Score EMPTY = new Score(0, 0, 0, 0);
        Score plus(Score other) {
            return new Score(tp + other.tp, fp + other.fp, tn + other.tn, fn + other.fn);
        }
    }

    /** One labeled method in one category, and whether the detector agreed with its label. */
    public record LabeledCase(String category, String file, String method, long firstLine, long lastLine, String outcome) {}

    /** One finding and what happened when a repair was attempted. */
    public record Item(Finding finding, RepairOutcome outcome, String strategy, String guidance) {}

    /** Labeled cases are empty when nothing scanned carries an EXPECT_* marker. */
    public record Report(Map<String, String> sources, List<Item> items, List<DetectionDiagnostic> diagnostics,
                         List<LabeledCase> cases) {
        public boolean complete() { return diagnostics.isEmpty(); }
        /** Scores keyed by {@link Category#key()}; a category is absent when it has no labeled cases. */
        public Map<String, Score> scores() { return tally(cases); }
    }

    private static final Set<String> EXCLUDED = Set.of(".git", ".benchmark-cache", "out", "target",
            "build", "node_modules", ".gradle");

    private static final Map<String, String> GUIDANCE = Map.of(
            "CWE-89", "Use a PreparedStatement with ? placeholders and bind every untrusted value with setString/setInt. "
                    + "Table or column names cannot be bound: check them against a fixed allowlist instead.",
            "CWE-78", "Use a fixed executable with separate arguments (no sh -c / cmd /c), validate input against an "
                    + "allowlist and keep the environment fixed. Run functionality and security tests before accepting a patch.");

    /** The declared command profile, or null when command repair is disabled. */
    public static String commandProfile() {
        String profile = System.getProperty(COMMAND_PROFILE_PROPERTY);
        return profile == null || profile.isBlank() ? null : profile;
    }

    public Report scan(Map<String, String> sources, Map<String, String> resources) {
        return scan(sources, resources, List.of());
    }

    public Report scan(Map<String, String> sources, Map<String, String> resources, List<Path> classpath) {
        DetectionResult result = new SecurityAnalyzer().analyze(
                new DetectionRequest(sources, sources.keySet(), classpath, resources));
        List<Item> items = new ArrayList<>();
        for (Finding finding : result.findings()) items.add(repair(finding, sources.get(finding.file())));
        return new Report(sources, items, result.diagnostics(), label(sources, result.findings()));
    }

    private static Item repair(Finding finding, String source) {
        RepairStrategy strategy = switch (finding.cwe()) {
            case "CWE-89" -> new NaiveSqliRepair();
            case "CWE-78" -> new CommandInjectionRepair();
            default -> null;
        };
        String guidance = GUIDANCE.getOrDefault(finding.cwe(), "Review this finding manually.");
        if (strategy == null) return new Item(finding, RepairOutcome.refused("No repair strategy for " + finding.cwe()), "", guidance);
        if (source == null) return new Item(finding, RepairOutcome.refused("Finding is in a file that was not scanned"), strategy.id(), guidance);
        RepairOutcome outcome;
        try {
            outcome = strategy.attempt(finding, source);
        } catch (RuntimeException e) {
            outcome = RepairOutcome.refused("Repair strategy failed: " + e.getMessage());
        }
        return new Item(finding, outcome, strategy.id(), guidance);
    }

    /** Reads a file, or a directory as one bundle, the same way the CLI does. Keys are paths relative to {@code root}. */
    public static void read(Path root, Path target, Map<String, String> sources, Map<String, String> resources) throws IOException {
        if (!Files.isDirectory(target)) {
            sources.put(relative(root, target), Files.readString(target));
            return;
        }
        List<Path> files = new ArrayList<>();
        Files.walkFileTree(target, new SimpleFileVisitor<>() {
            @Override public FileVisitResult preVisitDirectory(Path directory, BasicFileAttributes attributes) {
                return !directory.equals(target) && EXCLUDED.contains(directory.getFileName().toString())
                        ? FileVisitResult.SKIP_SUBTREE : FileVisitResult.CONTINUE;
            }
            @Override public FileVisitResult visitFile(Path file, BasicFileAttributes attributes) {
                if (attributes.isRegularFile()) files.add(file);
                return FileVisitResult.CONTINUE;
            }
        });
        for (Path file : files.stream().sorted().toList()) {
            String name = target.relativize(file).toString().replace('\\', '/');
            if (name.endsWith(".java")) sources.put(relative(root, file), Files.readString(file));
            else if (isResource(name)) addResource(resources, name, Files.readString(file));
        }
        if (sources.isEmpty()) throw new IllegalArgumentException("No Java source files in " + relative(root, target));
    }

    public static boolean isResource(String name) {
        return name.endsWith(".properties") || name.endsWith(".sh") || name.endsWith(".bat");
    }

    /** Adds a project resource under its path and, inside a resources/ directory, under its classpath name too. */
    public static void addResource(Map<String, String> resources, String name, String content) {
        resources.put(name, content);
        int at = name.startsWith("resources/") ? 0 : name.indexOf("/resources/") + 1;
        if (at > 0 || name.startsWith("resources/")) {
            String key = name.substring(at + "resources/".length());
            String previous = resources.putIfAbsent(key, content);
            if (previous != null && !previous.equals(content)) throw new IllegalArgumentException("Ambiguous resource: " + key);
        }
    }

    private static String relative(Path root, Path file) {
        return root.relativize(file).toString().replace('\\', '/');
    }

    /** Development-corpus cases: each labeled sample directory scanned as its own bundle. */
    public List<LabeledCase> corpusCases(Path root) throws IOException {
        List<LabeledCase> cases = new ArrayList<>();
        for (String directory : List.of("samples/sqli", "samples/command")) {
            Path path = root.resolve(directory);
            if (!Files.isDirectory(path)) continue;
            Map<String, String> sources = new LinkedHashMap<>(), resources = new LinkedHashMap<>();
            read(root, path, sources, resources);
            cases.addAll(scan(sources, resources).cases());
        }
        return cases;
    }

    public Map<String, Score> corpusScores(Path root) throws IOException {
        return tally(corpusCases(root));
    }

    public static Map<String, Score> tally(List<LabeledCase> cases) {
        Map<String, Score> scores = new LinkedHashMap<>();
        for (LabeledCase c : cases) {
            Score one = switch (c.outcome()) {
                case "tp" -> new Score(1, 0, 0, 0);
                case "fp" -> new Score(0, 1, 0, 0);
                case "tn" -> new Score(0, 0, 1, 0);
                default -> new Score(0, 0, 0, 1);
            };
            scores.merge(c.category(), one, Score::plus);
        }
        return scores;
    }

    /**
     * For each file containing a category's marker, every method body is one labeled case: positive when the
     * method contains {@code // MARKER}, predicted positive when a finding of that CWE falls inside the method.
     */
    static List<LabeledCase> label(Map<String, String> sources, List<Finding> findings) {
        List<LabeledCase> cases = new ArrayList<>();
        for (var entry : sources.entrySet()) {
            String source = entry.getValue();
            List<Category> labeled = CATEGORIES.stream().filter(c -> source.contains("// " + c.marker())).toList();
            if (labeled.isEmpty()) continue;
            for (Method method : methods(source)) {
                String body = source.substring((int) method.start(), (int) method.end());
                for (Category category : labeled) {
                    boolean expected = body.contains("// " + category.marker());
                    boolean actual = findings.stream().anyMatch(f -> f.file().equals(entry.getKey())
                            && f.cwe().equals(category.cwe()) && f.line() >= method.firstLine() && f.line() <= method.lastLine());
                    String outcome = expected && actual ? "tp" : expected ? "fn" : actual ? "fp" : "tn";
                    cases.add(new LabeledCase(category.key(), entry.getKey(), method.name(), method.firstLine(), method.lastLine(), outcome));
                }
            }
        }
        return cases;
    }

    private record Method(String name, long start, long end, long firstLine, long lastLine) {}

    /** Every method with a body, named Class.method (constructors use the class name). */
    private static List<Method> methods(String source) {
        var compiler = ToolProvider.getSystemJavaCompiler();
        if (compiler == null) throw new IllegalStateException("Scoring requires a JDK, not a JRE");
        var input = new SimpleJavaFileObject(URI.create("string:///Sample.java"), JavaFileObject.Kind.SOURCE) {
            @Override public CharSequence getCharContent(boolean ignored) { return source; }
        };
        List<Method> result = new ArrayList<>();
        try (var manager = compiler.getStandardFileManager(null, null, null)) {
            JavacTask task = (JavacTask) compiler.getTask(null, manager, diagnostic -> { }, List.of("-proc:none"), null, List.of(input));
            CompilationUnitTree unit = task.parse().iterator().next();
            var positions = Trees.instance(task).getSourcePositions();
            Deque<String> classes = new ArrayDeque<>();
            new TreeScanner<Void, Void>() {
                @Override public Void visitClass(ClassTree type, Void ignored) {
                    String name = type.getSimpleName().toString();
                    classes.push(name.isEmpty() ? "(anonymous)" : name);
                    try {
                        return super.visitClass(type, ignored);
                    } finally {
                        classes.pop();
                    }
                }
                @Override public Void visitMethod(MethodTree method, Void ignored) {
                    if (method.getBody() != null) {
                        long start = positions.getStartPosition(unit, method), end = positions.getEndPosition(unit, method);
                        if (start >= 0 && end > start) {
                            String owner = classes.isEmpty() ? "" : classes.peek();
                            String name = method.getName().contentEquals("<init>") ? owner : owner + "." + method.getName();
                            result.add(new Method(name, start, end,
                                    unit.getLineMap().getLineNumber(start), unit.getLineMap().getLineNumber(end - 1)));
                        }
                    }
                    return super.visitMethod(method, ignored);
                }
            }.scan(unit, null);
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }
        return result;
    }
}
