package edu.fiu.capstone.skeleton;

import java.util.List;

public interface SecurityLens {
    String id();
    List<Finding> analyze(String fileName, String sourceCode);
}