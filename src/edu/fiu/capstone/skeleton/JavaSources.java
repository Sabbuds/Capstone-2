package edu.fiu.capstone.skeleton;

import com.sun.source.tree.CompilationUnitTree;
import com.sun.source.util.JavacTask;
import com.sun.source.util.Trees;
import java.io.IOException;
import java.net.URI;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.IdentityHashMap;
import java.util.List;
import java.util.Map;
import javax.tools.Diagnostic;
import javax.tools.DiagnosticCollector;
import javax.tools.JavaFileObject;
import javax.tools.SimpleJavaFileObject;
import javax.tools.StandardJavaFileManager;
import javax.tools.StandardLocation;
import javax.tools.ToolProvider;

/** Owns compiler resources. Source processing and bytecode generation are disabled. */
final class JavaSources implements AutoCloseable {
    record Source(String name, String text, int offset, CompilationUnitTree unit) {}
    final StandardJavaFileManager manager;
    final JavacTask task;
    final Trees trees;
    final List<CompilationUnitTree> units;
    final Map<CompilationUnitTree, Source> sources = new IdentityHashMap<>();
    final List<DetectionDiagnostic> diagnostics = new ArrayList<>();
    final DetectionRequest request;

    private JavaSources(DetectionRequest request, String prefix, String suffix) throws IOException {
        this.request = request;
        var compiler = ToolProvider.getSystemJavaCompiler();
        if (compiler == null) throw new IllegalStateException("Java security analysis requires JDK 17+");
        manager = compiler.getStandardFileManager(null, null, null);
        try {
            manager.setLocationFromPaths(StandardLocation.SOURCE_PATH, List.of());
            if (!request.classpath().isEmpty()) {
                for (var entry : request.classpath()) {
                    if (!Files.exists(entry)) throw new IllegalArgumentException("Missing classpath entry: " + entry);
                }
                manager.setLocationFromPaths(StandardLocation.CLASS_PATH, request.classpath());
            }
            var collector = new DiagnosticCollector<JavaFileObject>();
            Map<URI, String> names = new java.util.HashMap<>();
            List<JavaFileObject> inputs = new ArrayList<>();
            for (String name : request.sources().keySet().stream().sorted().toList()) {
                String text = prefix + request.sources().get(name) + suffix;
                var input = new SimpleJavaFileObject(URI.create("string:///input" + inputs.size() + "/Source.java"), JavaFileObject.Kind.SOURCE) {
                    @Override public CharSequence getCharContent(boolean ignored) { return text; }
                    @Override public boolean isNameCompatible(String simpleName, Kind kind) {
                        if (simpleName.equals("package-info") || simpleName.equals("module-info")) {
                            return name.replace('\\', '/').endsWith(simpleName + ".java");
                        }
                        return kind == Kind.SOURCE;
                    }
                };
                names.put(input.toUri(), name);
                inputs.add(input);
            }
            task = (JavacTask) compiler.getTask(null, manager, collector,
                    List.of("-proc:none", "-implicit:none", "--release", "17"), null, inputs);
            units = new ArrayList<>();
            task.parse().forEach(units::add);
            if (collector.getDiagnostics().stream().anyMatch(d -> d.getKind() == Diagnostic.Kind.ERROR)) {
                var error = collector.getDiagnostics().stream().filter(d -> d.getKind() == Diagnostic.Kind.ERROR).findFirst().orElseThrow();
                throw new IllegalArgumentException("Cannot parse " + names.get(error.getSource().toUri()) + ":"
                        + Math.max(1, error.getLineNumber() - prefix.chars().filter(c -> c == '\n').count()) + ": "
                        + error.getMessage(java.util.Locale.ROOT));
            }
            task.analyze();
            trees = Trees.instance(task);
            for (var unit : units) {
                String name = names.get(unit.getSourceFile().toUri());
                sources.put(unit, new Source(name, request.sources().get(name), prefix.length(), unit));
            }
            for (var diagnostic : collector.getDiagnostics()) {
                if (diagnostic.getKind() != Diagnostic.Kind.ERROR && diagnostic.getKind() != Diagnostic.Kind.WARNING
                        && diagnostic.getKind() != Diagnostic.Kind.MANDATORY_WARNING) continue;
                String name = diagnostic.getSource() == null ? "" : names.getOrDefault(diagnostic.getSource().toUri(), "");
                long prefixLines = prefix.chars().filter(c -> c == '\n').count();
                diagnostics.add(new DetectionDiagnostic(name, Math.max(1, diagnostic.getLineNumber() - prefixLines),
                        diagnostic.getKind() == Diagnostic.Kind.ERROR ? DetectionDiagnostic.Severity.ERROR
                                : DetectionDiagnostic.Severity.WARNING, diagnostic.getMessage(java.util.Locale.ROOT)));
            }
        } catch (IOException | RuntimeException e) {
            manager.close();
            throw e;
        }
    }

    static JavaSources parse(DetectionRequest request) throws IOException {
        String[] prefixes = {"", "class __SecurityInput {\n", "class __SecurityInput { void __scan() {\n"};
        String[] suffixes = {"", "\n}", "\n} }"};
        IllegalArgumentException error = null;
        for (int i = 0; i < (request.sources().size() == 1 ? prefixes.length : 1); i++) {
            try { return new JavaSources(request, prefixes[i], suffixes[i]); }
            catch (IllegalArgumentException e) { if (error == null) error = e; }
        }
        throw error;
    }

    @Override public void close() throws IOException { manager.close(); }
}
