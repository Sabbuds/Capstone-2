package command;

import java.util.ArrayList;
import java.util.List;

/** Source-only security fixtures. Test code never calls these methods. */
public class CommandSamples {
    void unsafeRuntime(String input) throws Exception {
        Runtime.getRuntime().exec("ping " + input); // EXPECT_COMMAND
    }

    void unsafeShell(String input) throws Exception {
        new ProcessBuilder("/bin/sh", "-c", "ls " + input).start(); // EXPECT_COMMAND
    }

    void unsafeWindowsShell(String input) throws Exception {
        new ProcessBuilder("cmd.exe", "/c", input).start(); // EXPECT_COMMAND
    }

    void safeSeparateArgument(String input) throws Exception {
        new ProcessBuilder("printf", "%s", input).start();
    }

    void unsafeExecutable(String input) throws Exception {
        new ProcessBuilder(input, "hello").start(); // EXPECT_COMMAND
    }

    void safeRuntimeArray(String input) throws Exception {
        Runtime.getRuntime().exec(new String[] {"printf", "%s", input});
    }

    void unsafeBackingList(String input) throws Exception {
        List<String> command = new ArrayList<>(List.of("whoami"));
        ProcessBuilder builder = new ProcessBuilder(command);
        command.set(0, input);
        builder.start(); // EXPECT_COMMAND
    }

    void safeConstantShell() throws Exception {
        new ProcessBuilder("sh", "-c", "printf hello").start();
    }

    void unsafeInterpreter(String input) throws Exception {
        new ProcessBuilder("python3", "-c", input).start(); // EXPECT_COMMAND
    }

    void safeFixedScriptData(String input) throws Exception {
        new ProcessBuilder("python3", "report.py", input).start();
    }
}
