package edu.fiu.capstone.ui;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.io.InputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.Executors;
import java.util.stream.Stream;

/**
 * Local-only web UI. Run from the repository root:
 * {@code java -cp out edu.fiu.capstone.ui.UiServer [--port 8080]} then open http://localhost:8080.
 * Binds to the loopback interface and only reads files inside the repository root.
 */
public final class UiServer {
    private static final int MAX_UPLOAD_BYTES = 8 * 1024 * 1024;

    private final Path root;
    private final int port;
    private final ScanService service = new ScanService();
    private List<ScanService.LabeledCase> corpus;

    private UiServer(Path root, int port) {
        this.root = root;
        this.port = port;
    }

    public static void main(String[] args) throws IOException {
        int port = 8080;
        for (int i = 0; i < args.length; i++) {
            if (args[i].equals("--port") && i + 1 < args.length) port = Integer.parseInt(args[++i]);
            else throw new IllegalArgumentException("usage: UiServer [--port <port>]");
        }
        new UiServer(Path.of("").toAbsolutePath().toRealPath(), port).start();
    }

    private void start() throws IOException {
        if (!Files.isRegularFile(root.resolve("ui/index.html"))) {
            throw new IllegalStateException("Run from the repository root (ui/index.html not found in " + root + ")");
        }
        HttpServer server = HttpServer.create(new InetSocketAddress(InetAddress.getLoopbackAddress(), port), 0);
        server.createContext("/", exchange -> handle(exchange, this::page));
        server.createContext("/api/targets", exchange -> handle(exchange, this::targets));
        server.createContext("/api/scan", exchange -> handle(exchange, this::scan));
        server.setExecutor(Executors.newSingleThreadExecutor());
        server.start();
        System.out.println("Security scanner UI running at http://localhost:" + port + "  (Ctrl+C to stop)");
    }

    private interface Handler { void handle(HttpExchange exchange) throws Exception; }

    private void handle(HttpExchange exchange, Handler handler) throws IOException {
        try {
            String host = exchange.getRequestHeaders().getFirst("Host");
            if (host == null || !(host.equals("localhost:" + port) || host.equals("127.0.0.1:" + port))) {
                send(exchange, 403, "application/json", error("Forbidden host"));
                return;
            }
            handler.handle(exchange);
        } catch (IllegalArgumentException e) {
            send(exchange, 400, "application/json", error(e.getMessage()));
        } catch (Exception e) {
            send(exchange, 500, "application/json", error(e.getClass().getSimpleName() + ": " + e.getMessage()));
        } finally {
            exchange.close();
        }
    }

    private void page(HttpExchange exchange) throws IOException {
        String path = exchange.getRequestURI().getPath();
        if (!path.equals("/") && !path.equals("/index.html")) {
            send(exchange, 404, "text/plain", "Not found");
            return;
        }
        send(exchange, 200, "text/html; charset=utf-8", Files.readString(root.resolve("ui/index.html")));
    }

    /** Lists scannable samples: each sample directory and each source file under samples/. */
    private void targets(HttpExchange exchange) throws IOException {
        List<String> targets = new ArrayList<>();
        Path samples = root.resolve("samples");
        if (Files.isDirectory(samples)) {
            try (Stream<Path> walk = Files.walk(samples, 2)) {
                for (Path path : walk.sorted().toList()) {
                    String name = path.getFileName().toString();
                    if (path.equals(samples)) continue;
                    if (Files.isDirectory(path) || name.endsWith(".java") || name.endsWith(".txt")) {
                        targets.add(root.relativize(path).toString().replace('\\', '/') + (Files.isDirectory(path) ? "/" : ""));
                    }
                }
            }
        }
        Json json = new Json().open('{').key("commandProfile").value(ScanService.commandProfile()).key("targets").open('[');
        targets.forEach(json::value);
        send(exchange, 200, "application/json", json.close(']').close('}').toString());
    }

    /** GET ?target=relative/path scans a repository path; POST scans uploaded files ("urlencodedName\tbase64" per line). */
    private void scan(HttpExchange exchange) throws IOException {
        Map<String, String> sources = new LinkedHashMap<>(), resources = new LinkedHashMap<>();
        if (exchange.getRequestMethod().equals("POST")) {
            readUpload(exchange.getRequestBody(), sources, resources);
        } else {
            String target = query(exchange, "target");
            if (target == null || target.isBlank()) throw new IllegalArgumentException("Missing target");
            Path path = root.resolve(target).normalize();
            if (!path.startsWith(root) || !Files.exists(path) || !path.toRealPath().startsWith(root)) {
                throw new IllegalArgumentException("Target must exist inside the repository: " + target);
            }
            ScanService.read(root, path, sources, resources);
        }
        if (sources.isEmpty()) throw new IllegalArgumentException("Upload at least one .java file");
        ScanService.Report report = service.scan(sources, resources);
        boolean labeled = !report.cases().isEmpty();
        List<ScanService.LabeledCase> cases = labeled ? report.cases() : corpus();
        send(exchange, 200, "application/json", toJson(report, cases, labeled ? "scan" : "corpus"));
    }

    private synchronized List<ScanService.LabeledCase> corpus() throws IOException {
        if (corpus == null) corpus = service.corpusCases(root);
        return corpus;
    }

    private static void readUpload(InputStream body, Map<String, String> sources, Map<String, String> resources) throws IOException {
        byte[] bytes = body.readNBytes(MAX_UPLOAD_BYTES + 1);
        if (bytes.length > MAX_UPLOAD_BYTES) throw new IllegalArgumentException("Upload larger than 8 MB");
        for (String line : new String(bytes, StandardCharsets.UTF_8).split("\n")) {
            if (line.isBlank()) continue;
            int tab = line.indexOf('\t');
            if (tab < 0) throw new IllegalArgumentException("Malformed upload");
            String name = URLDecoder.decode(line.substring(0, tab), StandardCharsets.UTF_8).replace('\\', '/');
            String text = new String(Base64.getDecoder().decode(line.substring(tab + 1).strip()), StandardCharsets.UTF_8);
            String lower = name.toLowerCase(Locale.ROOT);
            if (lower.endsWith(".java")) sources.put(name, text);
            else if (ScanService.isResource(lower)) ScanService.addResource(resources, name, text);
            else throw new IllegalArgumentException("Unsupported file type: " + name);
        }
    }

    private static String query(HttpExchange exchange, String key) {
        String raw = exchange.getRequestURI().getRawQuery();
        if (raw == null) return null;
        for (String pair : raw.split("&")) {
            int eq = pair.indexOf('=');
            if (eq > 0 && URLDecoder.decode(pair.substring(0, eq), StandardCharsets.UTF_8).equals(key)) {
                return URLDecoder.decode(pair.substring(eq + 1), StandardCharsets.UTF_8);
            }
        }
        return null;
    }

    private static String toJson(ScanService.Report report, List<ScanService.LabeledCase> cases, String scoreSource) {
        Map<String, ScanService.Score> scores = ScanService.tally(cases);
        Json json = new Json().open('{');
        json.key("complete").raw(Boolean.toString(report.complete()));
        json.key("commandProfile").value(ScanService.commandProfile());
        json.key("files").open('[');
        report.sources().forEach((name, source) -> json.open('{').key("name").value(name).key("source").value(source).close('}'));
        json.close(']').key("findings").open('[');
        for (ScanService.Item item : report.items()) {
            var finding = item.finding();
            var outcome = item.outcome();
            json.open('{').key("cwe").value(finding.cwe()).key("file").value(finding.file())
                    .key("line").raw(Integer.toString(finding.line())).key("message").value(finding.message())
                    .key("snippet").value(finding.snippet()).key("strategy").value(item.strategy())
                    .key("status").value(outcome.isPatched() ? "fixed" : "manual");
            if (outcome.isPatched()) json.key("rationale").value(outcome.patch().rationale()).key("patched").value(outcome.patch().patched());
            else json.key("reason").value(outcome.refusalReason()).key("guidance").value(item.guidance());
            json.close('}');
        }
        json.close(']').key("diagnostics").open('[');
        for (var diagnostic : report.diagnostics()) {
            json.open('{').key("severity").value(diagnostic.severity().name()).key("file").value(diagnostic.file())
                    .key("line").raw(Long.toString(diagnostic.line())).key("message").value(diagnostic.message()).close('}');
        }
        json.close(']').key("scores").open('{').key("source").value(scoreSource).key("categories").open('[');
        for (ScanService.Category category : ScanService.CATEGORIES) {
            ScanService.Score score = scores.get(category.key());
            if (score == null) continue;
            json.open('{').key("key").value(category.key()).key("label").value(category.label())
                    .key("tp").raw(Integer.toString(score.tp())).key("fp").raw(Integer.toString(score.fp()))
                    .key("tn").raw(Integer.toString(score.tn())).key("fn").raw(Integer.toString(score.fn())).close('}');
        }
        json.close(']').key("cases").open('[');
        for (ScanService.LabeledCase c : cases) {
            json.open('{').key("category").value(c.category()).key("file").value(c.file()).key("method").value(c.method())
                    .key("firstLine").raw(Long.toString(c.firstLine())).key("lastLine").raw(Long.toString(c.lastLine()))
                    .key("outcome").value(c.outcome()).close('}');
        }
        return json.close(']').close('}').close('}').toString();
    }

    private static String error(String message) {
        return new Json().open('{').key("error").value(message == null ? "Unknown error" : message).close('}').toString();
    }

    private static void send(HttpExchange exchange, int status, String type, String body) throws IOException {
        byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().set("Content-Type", type);
        exchange.getResponseHeaders().set("Cache-Control", "no-store");
        exchange.sendResponseHeaders(status, bytes.length);
        exchange.getResponseBody().write(bytes);
    }

    /** Minimal JSON writer that inserts commas between siblings. */
    private static final class Json {
        private final StringBuilder out = new StringBuilder();
        private boolean needComma;

        Json open(char bracket) { comma(); out.append(bracket); needComma = false; return this; }
        Json close(char bracket) { out.append(bracket); needComma = true; return this; }
        Json key(String key) { comma(); quote(key); out.append(':'); needComma = false; return this; }
        Json raw(String literal) { comma(); out.append(literal); needComma = true; return this; }
        Json value(String text) {
            comma();
            if (text == null) out.append("null"); else quote(text);
            needComma = true;
            return this;
        }

        private void comma() { if (needComma) out.append(','); }

        private void quote(String text) {
            out.append('"');
            for (int i = 0; i < text.length(); i++) {
                char c = text.charAt(i);
                switch (c) {
                    case '"' -> out.append("\\\"");
                    case '\\' -> out.append("\\\\");
                    case '\n' -> out.append("\\n");
                    case '\r' -> out.append("\\r");
                    case '\t' -> out.append("\\t");
                    default -> {
                        if (c < 0x20 || c == '<' || c == '>' || c == '&' || c == 0x2028 || c == 0x2029) {
                            out.append(String.format("\\u%04x", (int) c));
                        } else out.append(c);
                    }
                }
            }
            out.append('"');
        }

        @Override public String toString() { return out.toString(); }
    }
}
