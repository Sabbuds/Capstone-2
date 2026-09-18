package edu.fiu.capstone.skeleton;

public record RepairOutcome(Patch patch, String refusalReason) {
    public static RepairOutcome patched(Patch p)  { return new RepairOutcome(p, null); }
    public static RepairOutcome refused(String w) { return new RepairOutcome(null, w); }
    public boolean isPatched() { return patch != null; }
}