package edu.fiu.capstone.skeleton;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.HashMap;
import java.util.Set;

/** File-level evaluation against original upstream labels. No benchmark code is executed. */
public final class PublicBenchmarkEvaluation {
    public static void main(String[] args) throws Exception {
        String split = args.length == 0 ? "validation" : args[0];
        boolean standalone = args.length > 1 && args[1].equals("standalone");
        if (!List.of("development", "validation", "all").contains(split)) {
            throw new IllegalArgumentException("Split must be development, validation or all");
        }
        Path root = Path.of(".benchmark-cache");
        Path manifest = root.resolve("manifest.csv");
        if (!Files.isRegularFile(manifest)) throw new IllegalStateException("Run scripts/fetch-benchmark.ps1 first");
        System.out.println("OWASP Benchmark 1.2, commit " + Files.readString(root.resolve("revision.txt")).replace("\uFEFF", "").strip());
        Map<String, String> support = new HashMap<>(), resources = new HashMap<>();
        if (!standalone) {
            loadSupport(root, "support.csv", root.resolve("support"), support);
            loadSupport(root, "resources.csv", root, resources);
        }
        System.out.println("Selection v3: first 20 positive and negative IDs per class; first 15 development, next 5 validation.");
        System.out.println("Split=" + split + "; file-level predictions; source-bundle=" + !standalone
                + "; servlet/framework classpath is not supplied.");
        System.out.println("name,category,expected,predicted,result,analysisComplete");
        List<String> manifestLines = Files.readAllLines(manifest, StandardCharsets.UTF_8);
        for (String category : List.of("sqli", "cmdi")) {
            SecurityLens lens = category.equals("sqli") ? new RegexSqliLens() : new CommandInjectionLens();
            String cwe = category.equals("sqli") ? "CWE-89" : "CWE-78";
            int tp = 0, fp = 0, tn = 0, fn = 0;
            int incomplete = 0;
            for (String line : manifestLines.subList(1, manifestLines.size())) {
                String[] row = line.replace("\"", "").split(",");
                if (row.length != 6) throw new IllegalArgumentException("Invalid benchmark manifest row");
                if (!row[1].equals(category) || (!split.equals("all") && !row[4].equals(split))) continue;
                if (!row[0].matches("BenchmarkTest[0-9]{5}")) throw new IllegalArgumentException("Invalid benchmark name");
                Path file = root.resolve(row[0] + ".java");
                byte[] bytes = Files.readAllBytes(file);
                String digest = HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes));
                if (!digest.equals(row[5])) throw new IllegalStateException("Benchmark source changed: " + file);
                boolean expected = Boolean.parseBoolean(row[2]);
                String name = file.getFileName().toString();
                Map<String, String> sources = new HashMap<>(support);
                sources.put(name, new String(bytes, StandardCharsets.UTF_8));
                var analysis = lens.analyze(new DetectionRequest(sources, Set.of(name), List.of(), resources));
                boolean predicted = analysis.findings().stream().anyMatch(f -> f.cwe().equals(cwe));
                if (!analysis.complete()) incomplete++;
                String result;
                if (expected && predicted) { tp++; result = "TP"; }
                else if (expected) { fn++; result = "FN"; }
                else if (predicted) { fp++; result = "FP"; }
                else { tn++; result = "TN"; }
                System.out.println(row[0] + "," + category + "," + expected + "," + predicted + "," + result + "," + analysis.complete());
            }
            if (tp + fp + tn + fn == 0) throw new IllegalStateException("No benchmark cases selected");
            var score = new DetectionEvaluation.Score(tp, fp, tn, fn);
            System.out.printf("%s: TP=%d FP=%d TN=%d FN=%d FNR=%s FPR=%s precision=%s%n",
                    category, tp, fp, tn, fn, score.fnr(), score.fpr(), score.precision());
            System.out.println(category + ": incomplete analyses=" + incomplete + "; none excluded from scores");
        }
        System.out.println("Small, ID-selected public subset; do not claim full-benchmark coverage or universal accuracy.");
    }

    private static void loadSupport(Path root, String manifestName, Path directory, Map<String, String> contents) throws Exception {
        Path manifest = root.resolve(manifestName);
        if (!Files.isRegularFile(manifest)) throw new IllegalStateException("Refresh benchmark cache using scripts/fetch-benchmark.ps1");
        List<String> rows = Files.readAllLines(manifest, StandardCharsets.UTF_8);
        for (String row : rows.subList(1, rows.size())) {
            String[] values = row.replace("\"", "").split(",");
            if (values.length != 2 || !values[0].matches("[A-Za-z0-9_]+\\.(java|properties|sh|bat)")) {
                throw new IllegalArgumentException("Invalid benchmark support manifest");
            }
            byte[] bytes = Files.readAllBytes(directory.resolve(values[0]));
            String digest = HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes));
            if (!digest.equals(values[1])) throw new IllegalStateException("Benchmark support changed: " + values[0]);
            contents.put(values[0], new String(bytes, StandardCharsets.UTF_8));
        }
    }
}
