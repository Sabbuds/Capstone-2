package edu.fiu.capstone.skeleton;

public record Finding(String cwe, String file, int line, String message, String snippet) {}