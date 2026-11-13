
package edu.fiu.capstone.skeleton;

import java.nio.file.Files;
import java.nio.file.Path;

public class CommandInjectionRuntimeTest {

    public static void main(String[] args) throws Exception {

        // Child process reads the requested file.
        if (args.length == 2 && args[0].equals("--read")) {
            System.out.print(Files.readString(Path.of(args[1])));
            return;
        }
        
        if (args.length == 2 && args[0].equals("--echo")) {
    System.out.print(args[1]);
    return;
}

        // Create temporary directory for testing.
        Path tempDir = Files.createTempDirectory(
            "command-security-"
        );

        // Test 1: Normal filename
        Path normalFile = tempDir.resolve("normal.txt");
        Files.writeString(normalFile, "Normal file content");

        // Test 2: Filename containing shell metacharacters
        Path specialFile = tempDir.resolve(
            "test & echo INJECTED.txt"
        );
        Files.writeString(
            specialFile,
            "Special filename content"
        );

        // Test 3: Filename containing spaces
        Path spaceFile = tempDir.resolve(
            "file with spaces.txt"
        );
        Files.writeString(
            spaceFile,
            "Filename with spaces content"
        );

        // Test 4: Filename containing a pipe character
        // Windows does not allow | in filenames, so we test
        // that it is passed literally as an argument.
        String pipeArgument = "test | echo INJECTED";

        testFile(normalFile, "Normal filename");
        testFile(specialFile, "Special-character filename");
        testFile(spaceFile, "Filename with spaces");
        testLiteralArgument(pipeArgument, "Pipe character");

        System.out.println();
        System.out.println("ALL RUNTIME TESTS PASSED");
    }

    private static void testFile(Path file, String label)
            throws Exception {

        Process process = new ProcessBuilder(
            javaExecutable(),
            "-cp",
            System.getProperty("java.class.path"),
            CommandInjectionRuntimeTest.class.getName(),
            "--read",
            file.toString()
        ).redirectErrorStream(true).start();

        String output = new String(
            process.getInputStream().readAllBytes()
        );

        int exitCode = process.waitFor();

        if (exitCode != 0) {
            throw new AssertionError(
                label + " failed: " + output
            );
        }

        String expected = Files.readString(file);

        if (!output.equals(expected)) {
            throw new AssertionError(
                label + " content mismatch"
            );
        }

        System.out.println("PASS: " + label);
    }

    private static void testLiteralArgument(
            String argument, String label) throws Exception {

        Process process = new ProcessBuilder(
            javaExecutable(),
            "-cp",
            System.getProperty("java.class.path"),
            CommandInjectionRuntimeTest.class.getName(),
            "--echo",
            argument
        ).redirectErrorStream(true).start();

        String output = new String(
            process.getInputStream().readAllBytes()
        );

        int exitCode = process.waitFor();

        if (exitCode != 0 || !output.equals(argument)) {
            throw new AssertionError(
                label + " was not preserved literally: " + output
            );
        }

        System.out.println("PASS: " + label);
    }

    private static String javaExecutable() {
        return Path.of(
            System.getProperty("java.home"),
            "bin",
            "java.exe"
        ).toString();
    }
}