package edu.fiu.capstone.skeleton;

public interface RepairStrategy {
    String id();
    RepairOutcome attempt(Finding finding, String sourceCode);
}