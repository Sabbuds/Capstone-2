package edu.fiu.capstone.skeleton;

import java.nio.file.Files;
import java.util.List;
import java.util.Map;
import java.util.Set;

/** Detector handoff contract: source bundles, precise flow, diagnostics and compatibility. */
public final class DetectorContractTest {
    private static int passed;
    private static int failed;

    public static void main(String[] args) throws Exception {
        var sql = new RegexSqliLens();
        var command = new CommandInjectionLens();
        body(sql, "Safe map key overwrites tainted selection", "Map<String,String> m=new HashMap<>(); m.put(\"bad\",input); m.put(\"good\",\"users\"); String table=m.get(\"bad\"); table=m.get(\"good\"); stmt.executeQuery(\"SELECT * FROM \"+table);", 0);
        body(sql, "Unsafe map selection", "Map<String,String> m=new HashMap<>(); m.put(\"bad\",input); m.put(\"good\",\"users\"); stmt.executeQuery(\"SELECT * FROM \"+m.get(\"bad\"));", 1);
        body(sql, "Map alias mutation", "Map<String,String> m=new HashMap<>(); Map<String,String> alias=m; alias.put(\"x\",input); stmt.executeQuery(\"SELECT * FROM \"+m.get(\"x\"));", 1);
        body(sql, "Map copied constructor", "Map<String,String> m=Map.of(\"x\",\"users\"); Map<String,String> copy=new HashMap<>(m); stmt.executeQuery(\"SELECT * FROM \"+copy.get(\"x\"));", 0);
        body(sql, "Map default input", "Map<String,String> m=new HashMap<>(); stmt.executeQuery(\"SELECT * FROM \"+m.getOrDefault(\"missing\",input));", 1);
        body(sql, "Map values keep distinct key types", "Map<Object,String> m=new HashMap<>(); m.put(1,input); m.put(\"1\",\"users\"); stmt.executeQuery(\"SELECT * FROM \"+m.get(1));", 1);
        body(sql, "putIfAbsent replaces null", "Map<String,String> m=new HashMap<>(); m.put(\"x\",(String)null); m.putIfAbsent(\"x\",input); stmt.executeQuery(\"SELECT * FROM \"+m.get(\"x\"));", 1);
        body(sql, "Conditional map removal keeps unmatched value", "Map<String,String> m=new HashMap<>(); m.put(\"x\",input); m.remove(\"x\",\"wrong\"); stmt.executeQuery(\"SELECT * FROM \"+m.get(\"x\"));", 1);
        body(sql, "Map callback cannot silently keep safe value", "Map<String,String> m=new HashMap<>(); m.put(\"x\",\"users\"); m.compute(\"x\",(k,v)->input); stmt.executeQuery(\"SELECT * FROM \"+m.get(\"x\"));", 1);
        body(sql, "List removal selects safe value", "List<String> v=new ArrayList<>(); v.add(\"users\"); v.add(input); v.add(\"orders\"); v.remove(0); stmt.executeQuery(\"SELECT * FROM \"+v.get(1));", 0);
        body(sql, "List removal preserves unsafe value", "List<String> v=new ArrayList<>(); v.add(\"users\"); v.add(input); v.remove(0); stmt.executeQuery(\"SELECT * FROM \"+v.get(0));", 1);
        body(sql, "Literal character switch", "String table; char key=\"ABC\".charAt(1); switch(key){case 'A':table=input;break;case 'B':table=\"users\";break;default:table=input;} stmt.executeQuery(\"SELECT * FROM \"+table);", 0);
        body(sql, "Selected switch fallthrough", "String table=\"users\"; switch(1){case 1:table=input;case 2:break;default:table=\"orders\";} stmt.executeQuery(\"SELECT * FROM \"+table);", 1);
        body(sql, "Counter updates keep later iteration reachable", "for(int i=0;i<3;i++){if(i==2)stmt.executeQuery(\"SELECT * FROM \"+input);}", 1);
        body(sql, "URL decode constant", "stmt.executeQuery(java.net.URLDecoder.decode(\"SELECT%201\",\"UTF-8\"));", 0);
        body(sql, "URL decode input", "stmt.executeQuery(java.net.URLDecoder.decode(input,\"UTF-8\"));", 1);
        body(command, "remove Object does not remove index", "List<String> c=new ArrayList<>(List.of(\"sh\",\"-c\",input)); c.remove(\"0\"); new ProcessBuilder(c).start();", 1);
        body(command, "List indexed addAll", "List<String> c=new ArrayList<>(List.of(\"whoami\")); c.addAll(0,List.of(input)); new ProcessBuilder(c).start();", 1);
        body(command, "Copied arrays preserve executable", "String[] c={\"printf\",input}; Runtime.getRuntime().exec(Arrays.copyOf(c,2));", 0);
        body(command, "Copied arrays retain shell input", "String[] c={\"sh\",\"-c\",input}; Runtime.getRuntime().exec(Arrays.copyOf(c,3));", 1);
        body(command, "System arraycopy changes executable", "String[] c={\"whoami\"}; System.arraycopy(new String[]{input},0,c,0,1); Runtime.getRuntime().exec(c);", 1);
        body(command, "Allocated array keeps separate arguments", "String[] c=new String[2]; c[0]=\"printf\";c[1]=input;Runtime.getRuntime().exec(c);", 0);
        body(command, "Exact arraycopy keeps separate arguments", "String[] c=new String[2];System.arraycopy(new String[]{\"printf\",input},0,c,0,2);Runtime.getRuntime().exec(c);", 0);
        body(command, "Immutable list mutation cannot reach start", "List<String> c=List.of(\"whoami\");c.set(0,input);new ProcessBuilder(c).start();", 0);
        body(command, "Fixed-size list add cannot reach start", "List<String> c=Arrays.asList(\"whoami\");c.add(input);new ProcessBuilder(c).start();", 0);
        body(command, "Shell input stream is a command channel", "Process p=new ProcessBuilder(\"sh\").start();p.getOutputStream().write(input.getBytes());", 1);
        body(command, "Shell writer is a command channel", "Process p=Runtime.getRuntime().exec(\"sh\");new java.io.PrintWriter(p.getOutputStream()).println(input);", 1);
        body(command, "Ordinary process stdin is data", "Process p=new ProcessBuilder(\"cat\").start();p.getOutputStream().write(input.getBytes());", 0);
        body(command, "Fixed shell stdin remains safe", "Process p=new ProcessBuilder(\"sh\").start();p.getOutputStream().write(\"echo hello\".getBytes());", 0);
        body(command, "Versioned Python code flag", "new ProcessBuilder(\"python3.12\",\"-c\",input).start();", 1);
        body(command, "Dynamic Java jar", "new ProcessBuilder(\"java\",\"-jar\",input).start();", 1);
        body(command, "Fixed File command path", "Runtime.getRuntime().exec(new java.io.File(\"/bin/ls\").getAbsolutePath());", 0);
        body(command, "Untrusted File command path", "Runtime.getRuntime().exec(new java.io.File(input).getAbsolutePath());", 1);
        body(command, "Runtime untrusted environment", "Runtime.getRuntime().exec(new String[]{\"whoami\"},new String[]{input});", 1);
        body(command, "Runtime constant environment", "Runtime.getRuntime().exec(new String[]{\"whoami\"},new String[]{\"LANG=C\"});", 0);
        body(command, "Builder untrusted environment", "ProcessBuilder p=new ProcessBuilder(\"whoami\");p.environment().put(\"LD_PRELOAD\",input);p.start();", 1);
        body(command, "Builder cleared environment", "ProcessBuilder p=new ProcessBuilder(\"whoami\");p.environment().put(\"LD_PRELOAD\",input);p.environment().clear();p.start();", 0);
        body(command, "Numeric-derived environment remains input", "Runtime.getRuntime().exec(new String[]{\"whoami\"},new String[]{\"LD_PRELOAD=\"+Integer.toString(Integer.parseInt(input))});", 1);
        body(command, "Numeric executable is still selected by input", "new ProcessBuilder(Integer.toString(Integer.parseInt(input))).start();", 1);
        body(command, "Numeric whole executable string", "Runtime.getRuntime().exec(Integer.toString(Integer.parseInt(input)));", 1);
        body(command, "Numeric ordinary argument is safe", "Runtime.getRuntime().exec(\"ping -c \"+Integer.toString(Integer.parseInt(input)));", 0);
        body(command, "Numeric shell command is code", "new ProcessBuilder(\"sh\",\"-c\",Integer.toString(Integer.parseInt(input))).start();", 1);
        body(command, "Overwritten environment array", "String[] e={input};e[0]=\"LANG=C\";Runtime.getRuntime().exec(new String[]{\"whoami\"},e);", 0);
        body(sql, "JPA native query", "EntityManager em=provider(); em.createNativeQuery(\"SELECT * FROM \"+input);", 1);
        body(sql, "JPA bound value is separate", "EntityManager em=provider(); em.createNativeQuery(\"SELECT * FROM users WHERE name=:name\").setParameter(\"name\",input);", 0);
        body(sql, "Hibernate HQL query", "Session session=provider(); session.createQuery(\"from User where name='\"+input+\"'\");", 1);

        var sources = Map.of(
                "project/Helper.java", "package project; public class Helper { public static String sql(String table){return \"SELECT * FROM \"+table;} }",
                "project/App.java", "package project; public class App { void run(java.sql.Statement stmt,String input)throws Exception { stmt.executeQuery(Helper.sql(input)); } }");
        var result = sql.analyze(new DetectionRequest(sources));
        check(result.findings().size() == 1 && result.complete(), "Source bundle resolves external helper " + result.diagnostics());
        check(result.findings().get(0).file().equals("project/App.java"), "Source bundle retains caller path");
        var safeSources = new java.util.HashMap<>(sources);
        safeSources.put("project/App.java", sources.get("project/App.java").replace("Helper.sql(input)", "Helper.sql(\"users\")"));
        result = sql.analyze(new DetectionRequest(safeSources));
        check(result.findings().isEmpty() && result.complete(), "Constant cross-file helper is conclusively safe " + result.diagnostics());

        project(command, "Constructor field input", "class Wrapper { final String cmd; Wrapper(String v){this.cmd=v;} String value(){return cmd;} } class App {void run(String input)throws Exception{Runtime.getRuntime().exec(new Wrapper(input).value());}}", 1);
        project(command, "Constructor field constant", "class Wrapper { final String cmd; Wrapper(String v){this.cmd=v;} String value(){return cmd;} } class App {void run()throws Exception{Runtime.getRuntime().exec(new Wrapper(\"whoami\").value());}}", 0);
        project(sql, "Interface dispatch to constant implementation", "interface Tables {String name();} class Safe implements Tables {public String name(){return \"users\";}} class App {void run(java.sql.Statement s)throws Exception{Tables t=new Safe();s.executeQuery(\"SELECT * FROM \"+t.name());}}", 0);
        project(sql, "Interface dispatch to input implementation", "interface Tables {String name();} class UserTable implements Tables {String v;UserTable(String s){v=s;}public String name(){return v;}} class App {void run(java.sql.Statement s,String input)throws Exception{Tables t=new UserTable(input);s.executeQuery(\"SELECT * FROM \"+t.name());}}", 1);
        project(sql, "Distinct instances do not share fields", "class Table {String v;Table(String s){v=s;}String name(){return v;}} class App {void run(java.sql.Statement s,String input)throws Exception{Table a=new Table(input);Table b=new Table(\"users\");s.executeQuery(\"SELECT * FROM \"+b.name());}}", 0);
        project(sql, "Member alias mutations", "class Table {String v=\"users\";} class App {void run(java.sql.Statement s,String input)throws Exception{Table a=new Table();Table b=a;b.v=input;s.executeQuery(\"SELECT * FROM \"+a.v);}}", 1);
        result = sql.analyze(DetectionRequest.source("Virtual.java", "class Base {String value(){return \"users\";}}class Derived extends Base{String value(){return System.getenv(\"TABLE\");}}class App{void run(java.sql.Statement s,Base b)throws Exception{s.executeQuery(\"SELECT * FROM \"+b.value());}}"));
        check(result.findings().size()==1 && !result.complete(), "Unknown virtual receiver cannot be assumed to use safe base implementation");
        project(command, "Bounded reflective constructor", "class Fixed {public Fixed(){}String value(){return \"whoami\";}}class App{void run()throws Exception{Fixed x=(Fixed)Class.forName(\"Fixed\").getConstructor().newInstance();Runtime.getRuntime().exec(x.value());}}", 0);
        project(command, "Reflection retains input after construction", "class Fixed {String v;public Fixed(String s){v=s;}String value(){return v;}}class App{void run(String input)throws Exception{Fixed x=(Fixed)Class.forName(\"Fixed\").getConstructor(String.class).newInstance(input);Runtime.getRuntime().exec(x.value());}}", 1);
        project(sql, "Bounded polymorphic pure helpers", "interface T{String value(String s);}class A implements T{public String value(String s){return s;}}class B implements T{public String value(String s){return new StringBuilder(s).toString();}}class App{void run(java.sql.Statement s,boolean flag)throws Exception{T t=flag?new A():new B();s.executeQuery(\"SELECT * FROM \"+t.value(\"users\"));}}", 0);
        project(sql, "Polymorphic helpers keep untrusted values", "interface T{String value(String s);}class A implements T{public String value(String s){return s;}}class B implements T{public String value(String s){return new StringBuilder(s).toString();}}class App{void run(java.sql.Statement s,String input,boolean flag)throws Exception{T t=flag?new A():new B();s.executeQuery(\"SELECT * FROM \"+t.value(input));}}", 1);

        String configurable = "class App {void run()throws Exception{java.util.Properties p=new java.util.Properties();try(var r=App.class.getClassLoader().getResourceAsStream(\"test.properties\")){p.load(r);}Runtime.getRuntime().exec(p.getProperty(\"command\"));}}";
        result = command.analyze(new DetectionRequest(Map.of("App.java",configurable),Set.of("App.java"),List.of(),Map.of("test.properties","command=whoami\n")));
        check(result.findings().isEmpty() && result.complete(), "Explicit resource content is analyzed without executing I/O " + result.diagnostics());
        result = command.analyze(new DetectionRequest(Map.of("App.java", "class App {void run()throws Exception {var u=App.class.getClassLoader().getResource(\"tool.sh\");Runtime.getRuntime().exec(new java.io.File(u.toURI().getPath()).getAbsolutePath());}}"),Set.of("App.java"),List.of(),Map.of("tool.sh","echo fixed\n")));
        check(result.findings().isEmpty() && result.complete(), "Provided static resource path is not untrusted command text " + result.diagnostics());
        String relativeResource = "package p;class App {void run()throws Exception{java.util.Properties p=new java.util.Properties();p.load(App.class.getResourceAsStream(\"test.properties\"));Runtime.getRuntime().exec(p.getProperty(\"command\"));}}";
        result = command.analyze(new DetectionRequest(Map.of("p/App.java",relativeResource),Set.of("p/App.java"),List.of(),Map.of("p/test.properties","command=whoami\n")));
        check(result.findings().isEmpty() && result.complete(), "Class-relative resources use the declaring package " + result.diagnostics());
        String leadingResource = "class App {void run(String input)throws Exception{var r=App.class.getClassLoader().getResourceAsStream(\"/test.properties\");if(r==null)Runtime.getRuntime().exec(input);}}";
        result = command.analyze(new DetectionRequest(Map.of("App.java",leadingResource),Set.of("App.java"),List.of(),Map.of("test.properties","x=y\n")));
        check(result.findings().size()==1 && !result.complete(), "ClassLoader leading slash cannot falsely certify a resource");
        String unicodeProperties = "class App {void run(String input)throws Exception{java.util.Properties p=new java.util.Properties();p.load(App.class.getClassLoader().getResourceAsStream(\"test.properties\"));switch(p.getProperty(\"value\")){case \"\u00c3\u00a9\":Runtime.getRuntime().exec(input);break;default:break;}}}";
        result = command.analyze(new DetectionRequest(Map.of("App.java",unicodeProperties),Set.of("App.java"),List.of(),Map.of("test.properties","value=\u00e9\n")));
        check(result.findings().size()==1, "Properties InputStream decoding follows the Java API");

        String nested = "input" + ".concat(\"x\")".repeat(300);
        result = sql.analyze(DetectionRequest.source("Deep.java", "class Deep{void run(java.sql.Statement s,String input)throws Exception{s.executeQuery("+nested+");}}"));
        check(!result.complete() && result.diagnostics().stream().anyMatch(d -> d.message().contains("limit")), "Resource limit is explicit and never a clean result");
        result = command.analyze(DetectionRequest.source("Lines.java", "class Lines {\rvoid run(String input)throws Exception{\rRuntime.getRuntime().exec(input);\r}}"));
        check(result.findings().size()==1 && result.findings().get(0).line()==3
                && result.findings().get(0).snippet().equals("Runtime.getRuntime().exec(input);"), "CR-only source locations remain exact");

        result = command.analyze(DetectionRequest.source("Unknown.java", "class Unknown {void run()throws Exception{new Missing().start();}}"));
        check(!result.complete() && !result.diagnostics().isEmpty(), "Unresolved types cannot masquerade as complete analysis");
        result = command.analyze(DetectionRequest.source("Callback.java", "class Callback {java.util.function.Function<String,Process> callback(){return this::execute;}Process execute(String s){return null;}}"));
        check(!result.complete(), "Method reference exposes analysis limitation");
        try {
            sql.analyze(new DetectionRequest(Map.of("Broken.java", "class Broken {")));
            throw new AssertionError("Malformed source accepted");
        } catch (IllegalArgumentException expected) { passed++; }

        // A source dependency may contain a vulnerability but is not an entry point.
        var support = Map.of("Helper.java", "class Helper {static String value(){return \"whoami\";}void unused(String input)throws Exception{Runtime.getRuntime().exec(input);}}",
                "App.java", "class App {void run()throws Exception{Runtime.getRuntime().exec(Helper.value());}}");
        result = command.analyze(new DetectionRequest(support, Set.of("App.java"), List.of()));
        check(result.findings().isEmpty(), "Unused support method does not taint entry-file results");

        PathClasspathTest.run();
        passed++;
        System.out.println("Detector contract tests completed: " + passed + "/" + (passed + failed) + " passed.");
        if (failed != 0) throw new AssertionError(failed + " detector contract failures");
    }

    private static void body(SecurityLens lens, String name, String body, int expected) {
        project(lens, name, "import java.util.*; class Case {void run(java.sql.Statement stmt,String input)throws Exception{"+body+"}}", expected);
    }

    private static void project(SecurityLens lens, String name, String source, int expected) {
        var result = lens.analyze("Case.java", source);
        check(result.size() == expected, name + " expected=" + expected + " actual=" + result.size());
    }

    private static void check(boolean condition, String name) {
        if (condition) passed++; else failed++;
        System.out.println((condition ? "PASS" : "FAIL") + " | " + name);
    }

    /** Compile a harmless dependency to ensure the supplied classpath is actually used. */
    private static final class PathClasspathTest {
        static void run() throws Exception {
            var directory = Files.createTempDirectory("detector-classpath-");
            var source = directory.resolve("Helper.java");
            try {
                Files.writeString(source, "package dependency; public class Helper {public static int number(){return 1;}}");
                int status = javax.tools.ToolProvider.getSystemJavaCompiler().run(null,null,null,"-d",directory.toString(),source.toString());
                if (status != 0) throw new AssertionError("Dependency fixture did not compile");
                var request = new DetectionRequest(Map.of("Case.java", "class Case {void run(java.sql.Statement s)throws Exception{s.executeQuery(\"SELECT \"+dependency.Helper.number());}}"),Set.of("Case.java"),List.of(directory));
                var result = new RegexSqliLens().analyze(request);
                if (!result.complete() || !result.findings().isEmpty()) throw new AssertionError("Classpath dependency not resolved: " + result);
            } finally {
                Files.deleteIfExists(directory.resolve("dependency/Helper.class"));
                Files.deleteIfExists(directory.resolve("dependency"));
                Files.deleteIfExists(source);
                Files.deleteIfExists(directory);
            }
        }
    }
}
