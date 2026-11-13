package edu.fiu.capstone.skeleton;

import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.Set;

/** All available source files, selected entry files, and optional dependency jars/directories. */
public record DetectionRequest(Map<String, String> sources, Set<String> entryFiles, List<Path> classpath,
                               Map<String, String> resources) {
    public DetectionRequest {
        sources = Map.copyOf(sources);
        entryFiles = Set.copyOf(entryFiles);
        classpath = List.copyOf(classpath);
        resources = Map.copyOf(resources);
        if (sources.isEmpty() || entryFiles.isEmpty() || !sources.keySet().containsAll(entryFiles)) {
            throw new IllegalArgumentException("Supply source and at least one matching entry file");
        }
        if (sources.keySet().stream().anyMatch(String::isBlank)) throw new IllegalArgumentException("Blank source name");
    }

    public DetectionRequest(Map<String, String> sources) {
        this(sources, sources.keySet(), List.of(), Map.of());
    }

    public DetectionRequest(Map<String, String> sources, Set<String> entryFiles, List<Path> classpath) {
        this(sources, entryFiles, classpath, Map.of());
    }

    public static DetectionRequest source(String name, String source) {
        return new DetectionRequest(Map.of(name, source));
    }
}
