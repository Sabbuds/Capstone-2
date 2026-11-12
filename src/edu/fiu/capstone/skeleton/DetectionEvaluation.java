package edu.fiu.capstone.skeleton;

import com.sun.source.tree.CompilationUnitTree;
import com.sun.source.tree.MethodTree;
import com.sun.source.util.JavacTask;
import com.sun.source.util.TreeScanner;
import com.sun.source.util.Trees;
import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import javax.tools.SimpleJavaFileObject;
import javax.tools.ToolProvider;

/** Method-level measurements on labeled development samples, not an independent benchmark. */
public final class DetectionEvaluation {
    record Score(int tp, int fp, int tn, int fn) {
        String fnr() { return rate(fn, tp + fn); }
        String fpr() { return rate(fp, fp + tn); }
        String precision() { return rate(tp, tp + fp); }
        private static String rate(int value, int total) {
            return total == 0 ? "N/A" : String.format(Locale.ROOT, "%.2f%%", 100.0 * value / total);
        }
    }

    public static void main(String[] args) throws Exception {
        Path root = Path.of(args.length == 0 ? "samples" : args[0]);
        System.out.println("DEVELOPMENT CORPUS ONLY: labeled methods; these are not independent benchmark rates.");
        print("SQL injection", evaluate(root.resolve("sqli"), new RegexSqliLens(), "EXPECT_SQLI"));
        print("Command injection", evaluate(root.resolve("command"), new CommandInjectionLens(), "EXPECT_COMMAND"));
        System.out.println("Repair-induced functionality regression rate: NOT MEASURED; compilation alone is insufficient.");
    }

    private static void print(String name, Score score) {
        System.out.printf("%s: TP=%d FP=%d TN=%d FN=%d FNR=%s FPR=%s precision=%s%n",
                name, score.tp(), score.fp(), score.tn(), score.fn(), score.fnr(), score.fpr(), score.precision());
    }

    static Score evaluate(Path directory, SecurityLens lens, String marker) throws Exception {
        int tp = 0, fp = 0, tn = 0, fn = 0;
        var compiler = ToolProvider.getSystemJavaCompiler();
        if (compiler == null) throw new IllegalStateException("Evaluation requires JDK 17+");
        try (var files = Files.list(directory)) {
            List<Path> samples = files.filter(p -> p.toString().endsWith(".java")).sorted().toList();
            if (samples.isEmpty()) throw new IllegalArgumentException("No Java samples in " + directory);
            for (Path sample : samples) {
                String source = Files.readString(sample);
                var findings = lens.analyze(sample.getFileName().toString(), source);
                var input = new SimpleJavaFileObject(URI.create("string:///Sample.java"), javax.tools.JavaFileObject.Kind.SOURCE) {
                    @Override public CharSequence getCharContent(boolean ignored) { return source; }
                };
                try (var manager = compiler.getStandardFileManager(null, null, null)) {
                    JavacTask task = (JavacTask) compiler.getTask(null, manager, null, List.of("-proc:none"), null, List.of(input));
                    CompilationUnitTree unit = task.parse().iterator().next();
                    var positions = Trees.instance(task).getSourcePositions();
                    List<MethodTree> methods = new ArrayList<>();
                    new TreeScanner<Void, Void>() {
                        @Override public Void visitMethod(MethodTree method, Void ignored) {
                            if (method.getBody() != null) methods.add(method);
                            return super.visitMethod(method, ignored);
                        }
                    }.scan(unit, null);
                    if (methods.isEmpty()) throw new IllegalArgumentException("Sample has no labeled methods: " + sample);
                    for (MethodTree method : methods) {
                        int start = (int) positions.getStartPosition(unit, method);
                        int end = (int) positions.getEndPosition(unit, method);
                        boolean expected = source.substring(start, end).contains("// " + marker);
                        long firstLine = unit.getLineMap().getLineNumber(start);
                        long lastLine = unit.getLineMap().getLineNumber(end - 1);
                        boolean actual = findings.stream().anyMatch(f -> f.line() >= firstLine && f.line() <= lastLine);
                        if (expected && actual) tp++;
                        else if (expected) fn++;
                        else if (actual) fp++;
                        else tn++;
                    }
                }
            }
        }
        return new Score(tp, fp, tn, fn);
    }
}
