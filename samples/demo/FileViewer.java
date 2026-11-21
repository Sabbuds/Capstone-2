package demo;

/**
 * Demo: command injection. Source-only fixture; nothing in the project calls these methods.
 * One finding is repaired only when the UI runs with -CommandProfile linux-gnu-cat, one is always refused.
 */
public class FileViewer {

    // Repaired with the linux-gnu-cat profile: the shell is removed and the name becomes a separate argument.
    public void showFile(String fileName) throws Exception {
        // EXPECT_COMMAND
        new ProcessBuilder("sh", "-c", "cat " + fileName).start();
    }

    // Refused: the user controls part of a command string. Needs an allowlist decided by a human.
    public void pingHost(String host) throws Exception {
        // EXPECT_COMMAND
        Runtime.getRuntime().exec("ping " + host);
    }

    // Safe: fixed executable, user input passed as a separate argument.
    public void printText(String text) throws Exception {
        new ProcessBuilder("printf", "%s", text).start();
    }
}
