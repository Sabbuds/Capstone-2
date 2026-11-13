
package edu.fiu.capstone.skeleton;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class CommandInjectionRepair implements RepairStrategy {

    // Matches:
    // Runtime.exec(new String[]{"sh", "-c", "cat " + filename});
    // Runtime.exec(new String[]{"bash", "-c", "cat " + filename});
    // new ProcessBuilder("sh", "-c", "cat " + filename).start();
    // new ProcessBuilder("bash", "-c", "cat " + filename).start();

    private static final Pattern RUNTIME_PATTERN = Pattern.compile(
        "^Runtime\\.getRuntime\\(\\)\\.exec\\(\\s*"
        + "new\\s+String\\s*\\[\\s*\\]\\s*\\{\\s*"
        + "\"(?:sh|bash)\"\\s*,\\s*\"-c\"\\s*,\\s*"
        + "\"cat \"\\s*\\+\\s*([A-Za-z_$][\\w$]*)"
        + "\\s*\\}\\s*\\)\\s*;$"
    );

    private static final Pattern PROCESS_BUILDER_PATTERN = Pattern.compile(
        "^new\\s+ProcessBuilder\\(\\s*"
        + "\"(?:sh|bash)\"\\s*,\\s*\"-c\"\\s*,\\s*"
        + "\"cat \"\\s*\\+\\s*([A-Za-z_$][\\w$]*)"
        + "\\s*\\)\\.start\\(\\)\\s*;$"
    );

    @Override
    public String id() {
        return "command-injection-repair";
    }

    @Override
    public RepairOutcome attempt(Finding finding, String sourceCode) {

        if (finding == null || sourceCode == null) {
            return RepairOutcome.refused(
                "Missing finding or source code"
            );
        }

        if (!"CWE-78".equals(finding.cwe())) {
            return RepairOutcome.refused(
                "This repair only supports CWE-78"
            );
        }

        // The target application must use GNU cat on Linux.
        // This property is a declared target profile, not
        // automatic verification of the target environment.
        if (!"linux-gnu-cat".equals(
                System.getProperty("capstone.target.commandProfile"))) {
            return RepairOutcome.refused(
                "Unsupported or unverified target command profile"
            );
        }

        // Support LF and CRLF, but not standalone CR.
        if (sourceCode.contains("\r")
                && !sourceCode.contains("\r\n")) {
            return RepairOutcome.refused(
                "Unsupported line endings"
            );
        }

        String newline =
            sourceCode.contains("\r\n") ? "\r\n" : "\n";

        String[] lines =
            sourceCode.split("\\r?\\n", -1);

        int lineIndex = finding.line() - 1;

        if (lineIndex < 0 || lineIndex >= lines.length) {
            return RepairOutcome.refused(
                "Invalid vulnerability line number"
            );
        }

        String originalLine = lines[lineIndex];
        String vulnerableLine = originalLine.strip();

        Matcher runtimeMatcher =
            RUNTIME_PATTERN.matcher(vulnerableLine);

        Matcher builderMatcher =
            PROCESS_BUILDER_PATTERN.matcher(vulnerableLine);

        String filenameVariable;

        if (runtimeMatcher.matches()) {
            filenameVariable = runtimeMatcher.group(1);

        } else if (builderMatcher.matches()) {
            filenameVariable = builderMatcher.group(1);

        } else {
            return RepairOutcome.refused(
                "Unsupported command injection structure"
            );
        }

        // Prototype check for a String declaration.
        // A future AST-based repair should verify actual
        // symbol resolution and scope.
        Pattern stringDeclaration = Pattern.compile(
            "\\bString\\s+"
            + Pattern.quote(filenameVariable)
            + "\\b"
        );

        if (!stringDeclaration.matcher(sourceCode).find()) {
            return RepairOutcome.refused(
                "Could not verify String filename declaration"
            );
        }

        String indentation = originalLine.substring(
            0,
            originalLine.length()
                - originalLine.stripLeading().length()
        );

        String repairedLine =
            "new ProcessBuilder(\"cat\", \"--\", "
            + filenameVariable + ").start();";

        lines[lineIndex] = indentation + repairedLine;

        String patchedSource =
            String.join(newline, lines);

        return RepairOutcome.patched(
            new Patch(
                finding.file(),
                sourceCode,
                patchedSource,
                "Replaced shell-based cat execution with direct ProcessBuilder arguments."
            )
        );
    }
}