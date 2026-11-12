package edu.fiu.capstone.skeleton;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.TreeSet;

/** These tests analyze source; they never execute the sample commands. */
public class CommandInjectionTest {
    private static int passed;
    private static int failed;

    public static void main(String[] args) throws Exception {
        SecurityLens lens = new CommandInjectionLens();
        test(lens, "Static Runtime command", "Runtime.getRuntime().exec(\"whoami\");", 0);
        test(lens, "Runtime command concatenation", "Runtime.getRuntime().exec(\"ping \" + input);", 1);
        test(lens, "Runtime whole command", "Runtime.getRuntime().exec(input);", 1);
        test(lens, "Runtime alias", "Runtime runtime = Runtime.getRuntime(); runtime.exec(input);", 1);
        test(lens, "Runtime separate data argument", "Runtime.getRuntime().exec(new String[]{\"printf\", \"%s\", input});", 0);
        test(lens, "Runtime dynamic executable", "Runtime.getRuntime().exec(new String[]{input, \"hello\"});", 1);
        test(lens, "Runtime shell array", "Runtime.getRuntime().exec(new String[]{\"sh\", \"-c\", input});", 1);
        test(lens, "Runtime constant shell", "Runtime.getRuntime().exec(new String[]{\"sh\", \"-c\", \"echo hello\"});", 0);
        test(lens, "Runtime environment overload", "Runtime.getRuntime().exec(new String[]{\"printf\", input}, new String[]{\"LANG=C\"});", 0);
        test(lens, "String variable flow", "String cmd = \"echo \" + input; Runtime.getRuntime().exec(cmd);", 1);
        test(lens, "StringBuilder command", "StringBuilder cmd = new StringBuilder(\"echo \" ); cmd.append(input); Runtime.getRuntime().exec(cmd.toString());", 1);
        test(lens, "String format command", "Runtime.getRuntime().exec(String.format(\"echo %s\", input));", 1);
        test(lens, "Safe overwrite", "String cmd = input; cmd = \"whoami\"; Runtime.getRuntime().exec(cmd);", 0);
        test(lens, "Conditional overwrite", "String cmd = input; if (flag) cmd=\"whoami\"; Runtime.getRuntime().exec(cmd);", 1);
        test(lens, "Unreachable command", "if (false) Runtime.getRuntime().exec(input);", 0);
        test(lens, "Safe ternary command", "Runtime.getRuntime().exec(flag ? \"whoami\" : \"hostname\");", 0);
        test(lens, "Numeric input", "Runtime.getRuntime().exec(\"ping -c \" + Integer.parseInt(input));", 0);
        test(lens, "Constant arithmetic command branch", "int n=86; String cmd=(7*42)-n>200 ? \"whoami\" : input; Runtime.getRuntime().exec(cmd);", 0);
        test(lens, "Escaping does not prove safety", "Runtime.getRuntime().exec(\"sh -c \" + input.replace(\";\", \"\"));", 1);
        test(lens, "ProcessBuilder not started", "new ProcessBuilder(\"sh\", \"-c\", input);", 0);
        test(lens, "ProcessBuilder separate argument", "new ProcessBuilder(\"printf\", \"%s\", input).start();", 0);
        test(lens, "Dynamic executable", "new ProcessBuilder(input, \"hello\").start();", 1);
        test(lens, "POSIX shell", "new ProcessBuilder(\"/bin/sh\", \"-c\", input).start();", 1);
        test(lens, "Bash login option", "new ProcessBuilder(\"bash\", \"-lc\", input).start();", 1);
        test(lens, "Windows cmd", "new ProcessBuilder(\"C:/Windows/System32/cmd.exe\", \"/c\", input).start();", 1);
        test(lens, "PowerShell", "new ProcessBuilder(\"powershell.exe\", \"-Command\", input).start();", 1);
        test(lens, "Encoded PowerShell", "new ProcessBuilder(\"pwsh\", \"-EncodedCommand\", input).start();", 1);
        test(lens, "Python code", "new ProcessBuilder(\"python3\", \"-c\", input).start();", 1);
        test(lens, "Node code", "new ProcessBuilder(\"node\", \"--eval\", input).start();", 1);
        test(lens, "Fixed interpreter script data", "new ProcessBuilder(\"python3\", \"report.py\", input).start();", 0);
        test(lens, "Untrusted interpreter script", "new ProcessBuilder(\"python3\", input).start();", 1);
        test(lens, "Environment wrapper shell", "new ProcessBuilder(\"env\", \"sh\", \"-c\", input).start();", 1);
        test(lens, "Windows script", "new ProcessBuilder(\"report.cmd\", input).start();", 1);
        test(lens, "Constant command with redirects", "new ProcessBuilder(\"whoami\").redirectErrorStream(true).inheritIO().start();", 0);
        test(lens, "Empty builder", "new ProcessBuilder().start();", 0);
        test(lens, "Set builder command", "ProcessBuilder pb=new ProcessBuilder(); pb.command(\"sh\", \"-c\", input); pb.start();", 1);
        test(lens, "Clear unsafe builder command", "ProcessBuilder pb=new ProcessBuilder(\"sh\",\"-c\",input); pb.command(\"whoami\"); pb.start();", 0);
        test(lens, "Builder alias", "ProcessBuilder pb=new ProcessBuilder(\"whoami\"); ProcessBuilder alias=pb; alias.command(input); pb.start();", 1);
        test(lens, "Command list view", "ProcessBuilder pb=new ProcessBuilder(\"whoami\"); pb.command().set(0,input); pb.start();", 1);
        test(lens, "Mutable backing list", "List<String> cmd=new ArrayList<>(List.of(\"whoami\")); ProcessBuilder pb=new ProcessBuilder(cmd); cmd.set(0,input); pb.start();", 1);
        test(lens, "Mutable list separate argument", "List<String> cmd=new ArrayList<>(); cmd.add(\"printf\"); cmd.add(input); new ProcessBuilder(cmd).start();", 0);
        test(lens, "Mutable list dynamic executable", "List<String> cmd=new ArrayList<>(); cmd.add(input); new ProcessBuilder(cmd).start();", 1);
        test(lens, "Immutable command list", "new ProcessBuilder(List.of(\"printf\",input)).start();", 0);
        test(lens, "Immutable shell list", "new ProcessBuilder(List.of(\"sh\",\"-c\",input)).start();", 1);
        test(lens, "Unknown list", "List<String> cmd=external(input); new ProcessBuilder(cmd).start();", 1);
        test(lens, "Runtime mutated array", "String[] cmd={\"whoami\"}; cmd[0]=input; Runtime.getRuntime().exec(cmd);", 1);
        test(lens, "Runtime array data mutation", "String[] cmd={\"printf\",\"hello\"}; cmd[1]=input; Runtime.getRuntime().exec(cmd);", 0);
        test(lens, "Builder copies varargs array", "String[] cmd={\"whoami\"}; ProcessBuilder pb=new ProcessBuilder(cmd); cmd[0]=input; pb.start();", 0);
        test(lens, "Array list view preserves mutation", "String[] cmd={\"whoami\"}; ProcessBuilder pb=new ProcessBuilder(Arrays.asList(cmd)); cmd[0]=input; pb.start();", 1);
        test(lens, "Shell alternative survives merge", "new ProcessBuilder(flag ? \"sh\" : \"printf\",\"-c\",input).start();", 1);
        test(lens, "Fixed executable allowlist", "String exe=flag ? \"printf\" : \"echo\"; new ProcessBuilder(exe,input).start();", 0);
        test(lens, "Formatted shell executable", "String exe=String.format(\"%s\",\"sh\"); new ProcessBuilder(exe,\"-c\",input).start();", 1);
        test(lens, "Joined shell executable", "String exe=String.join(\"h\",\"s\",\"\"); new ProcessBuilder(exe,\"-c\",input).start();", 1);
        test(lens, "Enforced executable guard", "if (!\"printf\".equals(input)) return; new ProcessBuilder(input,\"hello\").start();", 0);
        test(lens, "Enforced executable set", "String exe=input; if (!Set.of(\"printf\",\"echo\").contains(exe)) return; new ProcessBuilder(exe,input).start();", 0);
        test(lens, "Nonrestrictive executable guard", "Set.of(\"printf\",\"echo\").contains(input); new ProcessBuilder(input).start();", 1);
        test(lens, "Loop carries unsafe builder", "ProcessBuilder pb=new ProcessBuilder(\"whoami\"); while(flag) { pb.start(); pb.command(input); }", 1);
        test(lens, "Try catch paths", "String cmd=\"whoami\"; try { cmd=input; } catch(Exception e) { cmd=\"hostname\"; } Runtime.getRuntime().exec(cmd);", 1);
        test(lens, "Safe pipeline", "ProcessBuilder.startPipeline(List.of(new ProcessBuilder(\"printf\",input),new ProcessBuilder(\"cat\")));", 0);
        test(lens, "Unsafe pipeline", "ProcessBuilder.startPipeline(List.of(new ProcessBuilder(\"sh\",\"-c\",input),new ProcessBuilder(\"cat\")));", 1);
        test(lens, "Unrelated exec method", "class Client { void exec(String s) {} } new Client().exec(input);", 0);
        test(lens, "Unrelated start method", "class Client { void start() {} } new Client().start();", 0);
        test(lens, "Unrelated ProcessBuilder class", "class ProcessBuilder { ProcessBuilder(String s) {} void start() {} } new ProcessBuilder(input).start();", 0);
        test(lens, "Comment contains fake command", "// Runtime.getRuntime().exec(input);", 0);
        test(lens, "Literal contains fake command", "String text=\"Runtime.getRuntime().exec(input)\";", 0);
        test(lens, "Lambda command", "Runnable job=()->{try { Runtime.getRuntime().exec(input); } catch(Exception e) {}};", 1);
        testSource(lens, "Helper command flow", "class Helper { static String command(String s) { return \"echo \"+s; } } class Run { void run(String input) throws Exception { Runtime.getRuntime().exec(Helper.command(input)); } }", 1);
        testSource(lens, "Constant helper", "class Helper { static String command() { return \"whoami\"; } } class Run { void run() throws Exception { Runtime.getRuntime().exec(Helper.command()); } }", 0);
        testSource(lens, "Helper returns builder", "class Helper { static ProcessBuilder command(String s) { return new ProcessBuilder(\"sh\",\"-c\",s); } } class Run { void run(String input) throws Exception { Helper.command(input).start(); } }", 1);
        testSource(lens, "Helper conditionally changes builder", "class Helper { static void change(ProcessBuilder p,String s,boolean flag) { if(flag) p.command(s); } } class Run { void run(String input,boolean flag) throws Exception { ProcessBuilder p=new ProcessBuilder(\"whoami\"); Helper.change(p,input,flag); p.start(); } }", 1);
        testSource(lens, "Helper reassigns local parameter", "class Helper { static void change(ProcessBuilder p,String s) { p=new ProcessBuilder(s); } } class Run { void run(String input) throws Exception { ProcessBuilder p=new ProcessBuilder(\"whoami\"); Helper.change(p,input); p.start(); } }", 0);
        try {
            lens.analyze("Broken.java", "new ProcessBuilder(\"unterminated);");
            throw new AssertionError("Malformed source accepted");
        } catch (IllegalArgumentException expected) { }
        samples(lens, Path.of("samples/command"));
        System.out.println("Command tests completed: " + passed + "/" + (passed + failed) + " passed.");
        if (failed != 0) throw new AssertionError(failed + " command detection failures");
    }

    private static void test(SecurityLens lens, String name, String body, int expected) {
        testSource(lens, name, "import java.util.*; class CommandCase {\nvoid run(String input, boolean flag) throws Exception {\n"
                + body + "\n}}", expected);
    }

    private static void testSource(SecurityLens lens, String name, String source, int expected) {
        var findings = lens.analyze("CommandCase.java", source);
        boolean correct = findings.size() == expected && findings.stream().allMatch(f -> f.cwe().equals("CWE-78"));
        if (correct) passed++; else failed++;
        System.out.println((correct ? "PASS" : "FAIL") + " | " + name + " | expected=" + expected + ", actual=" + findings.size());
    }

    private static void samples(SecurityLens lens, Path directory) throws Exception {
        try (var files = Files.list(directory)) {
            for (Path file : files.filter(p -> p.toString().endsWith(".java")).sorted().toList()) {
                String source = Files.readString(file);
                String[] lines = source.split("\\R", -1);
                TreeSet<Integer> expected = new TreeSet<>(), actual = new TreeSet<>();
                for (int i = 0; i < lines.length; i++) if (lines[i].contains("// EXPECT_COMMAND")) expected.add(i + 1);
                var findings = lens.analyze(file.getFileName().toString(), source);
                boolean correct = true;
                for (Finding finding : findings) {
                    actual.add(finding.line());
                    correct &= finding.cwe().equals("CWE-78") && finding.file().equals(file.getFileName().toString())
                            && finding.line() > 0 && finding.line() <= lines.length
                            && finding.snippet().equals(lines[finding.line() - 1].strip());
                }
                correct &= actual.equals(expected) && findings.size() == expected.size();
                if (correct) passed++; else failed++;
                System.out.println((correct ? "PASS" : "FAIL") + " | " + file + " | expected=" + expected + ", actual=" + actual);
            }
        }
    }
}
