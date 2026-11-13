package edu.fiu.capstone.skeleton;

import java.io.File;
import java.io.IOException;
import java.nio.file.*;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.*;

/** Scans source bundles and prints findings/proposals. Application sources are never modified. */
public class Main {
    private static final Set<String> EXCLUDED = Set.of(".git", ".benchmark-cache", "out", "target",
            "build", "node_modules", ".gradle");

    public static void main(String[] args) throws Exception {
        boolean detectOnly = false;
        List<Path> classpath = new ArrayList<>();
        Path input = null;
        for (int i = 0; i < args.length; i++) {
            switch (args[i]) {
                case "--detect-only" -> detectOnly = true;
                case "--classpath" -> {
                    if (++i == args.length) throw new IllegalArgumentException("--classpath requires a value");
                    for (String entry : args[i].split(java.util.regex.Pattern.quote(File.pathSeparator))) {
                        if (!entry.isBlank()) classpath.add(Path.of(entry));
                    }
                }
                case "--help" -> { usage(); return; }
                default -> {
                    if (args[i].startsWith("--") || input != null) throw new IllegalArgumentException("Unexpected argument: " + args[i]);
                    input = Path.of(args[i]);
                }
            }
        }
        if (input == null) { usage(); return; }
        Map<String, String> sources = new LinkedHashMap<>(), resources = new LinkedHashMap<>();
        if (Files.isDirectory(input)) readProject(input, sources, resources);
        else sources.put(input.toString(), Files.readString(input));
        if (sources.isEmpty()) throw new IllegalArgumentException("No Java source files in " + input);

        SecurityLens lens = new SecurityAnalyzer();
        var result = lens.analyze(new DetectionRequest(sources, sources.keySet(), classpath, resources));
        if (!result.complete()) {
            System.out.println("Analysis INCOMPLETE: dependency or model diagnostics follow; zero findings is not a clean bill of health.");
            for (var diagnostic : result.diagnostics()) {
                System.err.println(diagnostic.severity() + " " + diagnostic.file() + ":" + diagnostic.line() + " " + diagnostic.message());
            }
        }
        for (var entry : sources.entrySet()) {
            List<Finding> findings = result.findings().stream().filter(f -> f.file().equals(entry.getKey())).toList();
            print(entry.getKey(), entry.getValue(), lens.id(), findings, detectOnly);
        }
    }

    private static void usage() {
        System.out.println("usage: java -cp out edu.fiu.capstone.skeleton.Main [--detect-only] [--classpath <jars/directories>] <file-or-directory>");
    }

    private static void readProject(Path root, Map<String, String> sources, Map<String, String> resources) throws IOException {
        List<Path> files = new ArrayList<>();
        Files.walkFileTree(root, new SimpleFileVisitor<>() {
            @Override public FileVisitResult preVisitDirectory(Path directory, BasicFileAttributes attributes) {
                return !directory.equals(root) && EXCLUDED.contains(directory.getFileName().toString())
                        ? FileVisitResult.SKIP_SUBTREE : FileVisitResult.CONTINUE;
            }
            @Override public FileVisitResult visitFile(Path file, BasicFileAttributes attributes) {
                if (attributes.isRegularFile()) files.add(file);
                return FileVisitResult.CONTINUE;
            }
        });
        for (Path file : files.stream().sorted().toList()) {
            String name = root.relativize(file).toString().replace('\\', '/');
            if (name.endsWith(".java")) sources.put(file.toString(), Files.readString(file));
            else if (name.endsWith(".properties") || name.endsWith(".sh") || name.endsWith(".bat")) {
                String content = Files.readString(file);
                resources.put(name, content);
                int resourceRoot = name.startsWith("resources/") ? 0 : name.indexOf("/resources/") + 1;
                if (resourceRoot == 0 && !name.startsWith("resources/")) resourceRoot = -1;
                if (resourceRoot >= 0) {
                    String key = name.substring(resourceRoot + "resources/".length());
                    String previous = resources.putIfAbsent(key, content);
                    if (previous != null && !previous.equals(content)) throw new IllegalArgumentException("Ambiguous resource: " + key);
                }
            }
        }
    }

    private static void print(String fileName, String source, String lensId, List<Finding> findings, boolean detectOnly) {
        System.out.println("scanned " + fileName + " with lens '" + lensId + "'");
        System.out.println(findings.size() + " finding(s)\n");
        RepairStrategy repair = new NaiveSqliRepair();
        int number = 0;
        for (Finding finding : findings) {
            System.out.println("[" + (++number) + "] " + finding.cwe() + "  " + finding.file() + ":" + finding.line());
            System.out.println("    " + finding.message());
            System.out.println("    > " + finding.snippet() + "\n");
            if (detectOnly) continue;
            RepairOutcome outcome = "CWE-89".equals(finding.cwe()) ? repair.attempt(finding, source)
                    : RepairOutcome.refused("Command-injection fixes require human review. Use a fixed executable, separate arguments "
                    + "and an allowlisted environment; run functionality and security tests before accepting a patch.");
            if (outcome.isPatched()) {
                System.out.println("    repair proposed by '" + repair.id() + "'");
                System.out.println("    " + outcome.patch().rationale() + "\n");
                printNewLines(outcome.patch());
            } else System.out.println("    repair refused: " + outcome.refusalReason());
            System.out.println();
        }
    }

    private static void printNewLines(Patch patch) {
        List<String> before = List.of(patch.original().split("\n", -1));
        for (String line : patch.patched().split("\n", -1)) {
            if (!line.isBlank() && !before.contains(line)) System.out.println("    + " + line.strip());
        }
    }
}
