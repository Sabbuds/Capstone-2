package edu.fiu.capstone.skeleton;
import java.util.regex.Pattern;
import java.util.regex.Matcher;

public class CommandInjectionRepair implements RepairStrategy {

    @Override
    public String id() {
        return "command-injection-repair";
    }

    @Override
    public RepairOutcome attempt(Finding finding, String sourceCode) {

        if (!"CWE-78".equals(finding.cwe())) {
            return RepairOutcome.refused(
                "This repair only handles command injection (CWE-78)"
            );
        }
      String[] lines = sourceCode.split("\\r?\\n", -1);

int lineIndex = finding.line() - 1;

if (lineIndex < 0 || lineIndex >= lines.length) {
    return RepairOutcome.refused(
        "The reported vulnerability line is outside the source file"
    );
}

String vulnerableLine = lines[lineIndex].strip();

if (!vulnerableLine.contains("Runtime.getRuntime().exec(")) {
    return RepairOutcome.refused(
        "Only direct Runtime.getRuntime().exec() calls are supported"
    );
}
if (!vulnerableLine.contains("\"sh\"")
        || !vulnerableLine.contains("\"-c\"")) {

    return RepairOutcome.refused(
        "Only sh -c command execution is supported"
    );
}

if (!vulnerableLine.contains("\"cat \"")) {
    return RepairOutcome.refused(
        "Only simple cat commands are supported"
    );
}
Pattern commandPattern = Pattern.compile(
    "^Runtime\\.getRuntime\\(\\)\\.exec\\(new String\\[\\]\\s*\\{\\s*"
    + "\"sh\"\\s*,\\s*\"-c\"\\s*,\\s*\"cat \"\\s*\\+\\s*"
    + "([A-Za-z_$][\\w$]*)\\s*\\}\\s*\\);$"
);

Matcher matcher = commandPattern.matcher(vulnerableLine);

if (!matcher.matches()) {
    return RepairOutcome.refused(
        "Unsupported command structure"
    );
}

String filenameVariable = matcher.group(1);
String repairedLine =
    "new ProcessBuilder(\"cat\", \"--\", "
    + filenameVariable + ").start();";
    String originalLine = lines[lineIndex];

String indentation = originalLine.substring(
    0,
    originalLine.length() - originalLine.stripLeading().length()
);

lines[lineIndex] = indentation + repairedLine;

String lineSeparator = sourceCode.contains("\r\n") ? "\r\n" : "\n";

String patchedSource = String.join(lineSeparator, lines);


    return createPatch(
    finding,
    sourceCode,
    patchedSource
);


    }
    
    

    private RepairOutcome createPatch(
            Finding finding,
            String originalSource,
            String repairedSource) {

        return RepairOutcome.patched(new Patch(
            finding.file(),
            originalSource,
            repairedSource,
            "Replaced vulnerable command execution with a safer implementation."
        ));
    }

}