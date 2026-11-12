package edu.fiu.capstone.skeleton;

import com.sun.source.tree.MethodInvocationTree;
import com.sun.source.tree.Tree;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.lang.model.element.Element;
import javax.lang.model.element.ExecutableElement;
import javax.lang.model.type.TypeKind;
import static edu.fiu.capstone.skeleton.FlowValue.*;

/** JDK string, collection and process contracts; never executes application code. */
final class LibraryModels {
    interface Context {
        String typeName(Tree tree);
        Element symbol(Tree tree);
        void mutate(FlowValue receiver, FlowValue replacement);
        void note(Tree tree, String message);
        FlowValue vector(List<FlowValue> elements, String type);
        void report(MethodInvocationTree call, String name);
        boolean checksCommands();
        void stopAfterException();
        int newIdentity();
    }

    private final Context c;
    LibraryModels(Context context) { c = context; }
    private static final Set<String> SHELLS = Set.of("sh", "bash", "dash", "zsh", "ksh", "ash", "fish",
            "cmd", "powershell", "pwsh", "env", "sudo", "busybox", "npx");
    private static final Set<String> CODE_FLAGS = Set.of("-c", "-e", "-p", "-r", "--eval", "--print", "-jar");
    private static final Pattern FORMAT = Pattern.compile(
            "%(?:(\\d+)\\$)?([-#+ 0,(<]*)(?:\\d+)?(?:\\.\\d+)?([tT])?([a-zA-Z%])");

    FlowValue stringCall(MethodInvocationTree call, String name, String owner, String apiOwner,
                         FlowValue receiver, List<FlowValue> args, boolean stringApi, boolean staticStringApi) {
        if (name.equals("getChars") && args.size() == 4 && (builder(receiver) || stringApi)) {
            c.mutate(args.get(2), join(args.get(2), receiver));
            return unknown("void");
        }
        if (builder(receiver)) {
            if (NUMERIC_TYPES.contains(c.typeName(call))) return unknown(c.typeName(call));
            if (name.equals("appendCodePoint") && args.size() == 1) {
                FlowValue arg = args.get(0);
                FlowValue appended = combine(receiver, arg.text == null ? unknown("char") : arg);
                appended.text = null;
                c.mutate(receiver, appended);
                return receiver;
            }
            if (name.equals("append") || name.equals("insert") || name.equals("add")
                    || name.equals("merge") || name.equals("setEmptyValue")) {
                int start = name.equals("insert") ? 1 : 0;
                if (args.size() > start) {
                    FlowValue appended = combine(receiver, args.get(start));
                    if (!name.equals("append")) appended.text = null;
                    c.mutate(receiver, appended);
                }
                return receiver;
            }
            if ((name.equals("replace") || name.equals("setCharAt")) && !args.isEmpty()) {
                FlowValue replaced = combine(receiver, args.get(args.size() - 1));
                replaced.text = null;
                c.mutate(receiver, replaced);
                return receiver;
            }
            if (name.equals("toString") || name.equals("substring") || name.equals("subSequence")) {
                FlowValue result = new FlowValue(name.equals("toString") ? receiver.text : null,
                        receiver.unsafe, receiver.sql, "String");
                result.inputDependent = receiver.inputDependent;
                result.prefix = name.equals("toString") ? receiver.prefix : "";
                return result;
            }
            if (name.equals("charAt")) return new FlowValue(null, receiver.unsafe, false, "char");
            if (name.equals("setLength") && args.size() == 1) {
                FlowValue resized = "0".equals(args.get(0).text) ? literal("") : receiver.copy();
                if (!"0".equals(args.get(0).text)) resized.text = null;
                c.mutate(receiver, resized);
            } else if (name.equals("reverse")) {
                FlowValue reversed = receiver.copy();
                reversed.text = receiver.text == null ? null : new StringBuilder(receiver.text).reverse().toString();
                reversed.sql |= reversed.text != null && SQL.matcher(reversed.text).find();
                c.mutate(receiver, reversed);
            } else if (name.equals("delete") || name.equals("deleteCharAt")) {
                FlowValue shortened = receiver.copy();
                shortened.text = null;
                c.mutate(receiver, shortened);
            }
            return receiver;
        }
        if (staticStringApi && name.equals("join")) {
            FlowValue joined = literal("");
            for (FlowValue arg : args) joined = combine(joined, arg);
            joined.text = null;
            joined.choices = Set.of();
            joined.prefix = "";
            return joined;
        }
        if (stringApi && (name.equals("toCharArray") || name.equals("getBytes"))) {
            FlowValue array = new FlowValue(null, receiver.unsafe, receiver.sql,
                    name.equals("toCharArray") ? "char[]" : "byte[]");
            array.origins = Set.of(c.newIdentity());
            array.inputDependent = receiver.inputDependent;
            return array;
        }
        if (stringApi && name.equals("charAt")) {
            Integer at = args.isEmpty() ? null : index(args.get(0));
            if (receiver.text != null && at != null && at >= 0 && at < receiver.text.length()) return literal(receiver.text.charAt(at));
            return new FlowValue(null, receiver.unsafe, false, "char");
        }
        if (stringApi && name.equals("split")) {
            FlowValue split = new FlowValue(null, receiver.unsafe, receiver.sql, "String[]");
            split.origins = Set.of(c.newIdentity());
            return split;
        }
        if (stringApi && Set.of("replace", "replaceAll", "replaceFirst", "substring", "subSequence",
                "trim", "strip", "stripLeading", "stripTrailing", "toLowerCase", "toUpperCase",
                "repeat", "indent", "stripIndent", "translateEscapes").contains(name)) {
            FlowValue transformed = receiver.copy();
            if (!name.equals("toLowerCase") && !name.equals("toUpperCase")) {
                for (FlowValue arg : args) transformed = combine(transformed, arg);
            }
            transformed.text = null;
            transformed.choices = Set.of();
            transformed.prefix = "";
            return transformed;
        }
        if (name.equals("concat") && args.size() == 1) return combine(receiver, args.get(0));
        if ((name.equals("format") && staticStringApi)
                || name.equals("formatted")) {
            int index = !args.isEmpty() && (args.get(0).type.equals("Locale")
                    || c.typeName(call.getArguments().get(0)).equals("Locale")) ? 1 : 0;
            if (name.equals("formatted")) return format(receiver, args);
            if (index < args.size()) return format(args.get(index), args.subList(index + 1, args.size()));
        }
        String ownerType = simpleType(apiOwner);
        if ((apiOwner.startsWith("java.lang.") || apiOwner.startsWith("java.math.")) && NUMERIC_TYPES.contains(ownerType)
                && (name.startsWith("parse") || name.equals("valueOf"))) return unknown(ownerType);
        if (name.equals("toString") || (name.equals("valueOf")
                && staticStringApi)) {
            FlowValue original = args.isEmpty() ? receiver : args.get(0);
            FlowValue result = new FlowValue(original.text, original.unsafe, original.sql, "String");
            result.inputDependent = original.inputDependent;
            result.prefix = original.prefix;
            return result;
        }
        return null;
    }

    FlowValue commandArguments(List<FlowValue> args) {
        if (args.size() == 1) {
            FlowValue first = args.get(0);
            if (first.type.endsWith("[]")) {
                FlowValue copy = first.elements == null ? unknown("List") : c.vector(first.elements, "List");
                return copy;
            }
            if (first.elements != null || Set.of("List", "ArrayList", "LinkedList", "Collection").contains(first.type)) return first;
        }
        return c.vector(args, "List");
    }

    FlowValue pathCall(String name, String owner, FlowValue receiver, List<FlowValue> args) {
        if ((owner.equals("java.nio.file.Paths") && name.equals("get"))
                || (owner.equals("java.nio.file.Path") && name.equals("of"))) {
            FlowValue path = new FlowValue(null, args.stream().anyMatch(v -> v.unsafe), false, "Path");
            path.inputDependent = args.stream().anyMatch(v -> v.inputDependent);
            return path;
        }
        if (Set.of("File", "Path", "URI", "URL").contains(receiver.type)) {
            if (Set.of("getPath", "getAbsolutePath", "getCanonicalPath", "toString").contains(name)) {
                return pathValue(receiver, "String");
            }
            if (Set.of("toURI", "toUri").contains(name)) return pathValue(receiver, "URI");
            if (Set.of("toPath", "toAbsolutePath", "normalize", "toRealPath", "getFileName").contains(name)) {
                return pathValue(receiver, "Path");
            }
            if (Set.of("toFile", "getAbsoluteFile", "getCanonicalFile").contains(name)) return pathValue(receiver, "File");
            if (name.equals("resolve") && receiver.type.equals("Path")) {
                FlowValue path = new FlowValue(null, receiver.unsafe || args.stream().anyMatch(v -> v.unsafe), false, "Path");
                path.inputDependent = receiver.inputDependent || args.stream().anyMatch(v -> v.inputDependent);
                return path;
            }
        }
        return null;
    }

    FlowValue pathValue(FlowValue receiver, String type) {
        FlowValue result = new FlowValue(null, receiver.unsafe, false, type);
        result.inputDependent = receiver.inputDependent;
        return result;
    }

    FlowValue processCall(MethodInvocationTree call, String name, String owner, FlowValue receiver, List<FlowValue> args) {
        FlowValue collection = collectionCall(call, name, owner, receiver, args);
        if (collection != null) return collection;
        if (owner.equals("java.lang.Runtime") && name.equals("getRuntime")) return unknown("Runtime");
        if (owner.equals("java.lang.Runtime") && name.equals("exec") && !args.isEmpty()) {
            FlowValue command = args.get(0);
            if (c.checksCommands() && ((command.elements == null ? commandStringRisk(command) : commandRisk(command))
                    || args.size() > 1 && environmentRisk(args.get(1)))) c.report(call, name);
            FlowValue process = unknown("Process");
            process.command = command;
            if (command.elements == null && command.text != null) {
                process.command = c.vector(Arrays.stream(command.text.strip().split("\\s+")).map(FlowValue::literal).toList(), "List");
            }
            return process;
        }
        if (owner.equals("java.lang.ProcessBuilder") || receiver.type.equals("ProcessBuilder")) {
            if (name.equals("command")) {
                if (args.isEmpty()) {
                    if (receiver.command == null) receiver.command = unknown("List");
                    return receiver.command;
                }
                FlowValue changed = receiver.copy();
                changed.command = commandArguments(args);
                c.mutate(receiver, changed);
                return receiver;
            }
            if (name.equals("environment")) {
                if (receiver.environment == null) {
                    receiver.environment = new FlowValue(null, false, false, "Map");
                    receiver.environment.entries = new HashMap<>();
                    receiver.environment.origins = Set.of(c.newIdentity());
                }
                return receiver.environment;
            }
            if (name.equals("start")) {
                if (c.checksCommands() && processRisk(receiver)) c.report(call, name);
                FlowValue process = unknown("Process");
                process.command = receiver.command;
                return process;
            }
            if (name.equals("startPipeline") && args.size() == 1) {
                FlowValue pipeline = args.get(0);
                if (c.checksCommands() && (pipeline.elements == null || pipeline.elements.stream().anyMatch(this::processRisk))) c.report(call, name);
                return unknown("List");
            }
            if (Set.of("directory", "redirectErrorStream", "redirectInput", "redirectOutput",
                    "redirectError", "inheritIO").contains(name)) {
                if (name.equals("directory") && !args.isEmpty() && args.get(0).unsafe) {
                    c.note(call, "Untrusted working directory can affect executable lookup; directory policy requires review");
                }
                return receiver;
            }
        }
        if ((owner.equals("java.lang.Process") || receiver.type.equals("Process")) && name.equals("getOutputStream")) {
            FlowValue stream = unknown("OutputStream");
            stream.command = receiver.command == null ? unknown("List") : receiver.command;
            return stream;
        }
        if (receiver.command != null && Set.of("write", "print", "println", "printf", "format", "append").contains(name)) {
            boolean unsafe = args.stream().anyMatch(v -> v.unsafe || NUMERIC_TYPES.contains(v.type) && v.text == null
                    || v.elements != null && v.elements.stream().anyMatch(item -> item.text == null && !item.definitelyNull));
            if (c.checksCommands() && unsafe && codeProcess(receiver.command)) c.report(call, name);
            return c.typeName(call).equals("void") ? unknown("void") : receiver;
        }
        if (owner.equals("java.util.Arrays") && name.equals("asList")) {
            FlowValue list = args.size() == 1 && args.get(0).type.endsWith("[]")
                    ? typed(args.get(0), "List") : c.vector(args, "List");
            list.fixedSize = true;
            return list;
        }
        if (Set.of("List", "ArrayList", "LinkedList").contains(receiver.type)) {
            if (name.equals("get") && args.size() == 1) {
                Integer at = index(args.get(0));
                if (receiver.elements != null && at != null && at >= 0 && at < receiver.elements.size()) {
                    return receiver.elements.get(at);
                }
            }
            if (Set.of("add", "set", "clear", "remove", "addAll").contains(name)) {
                if (receiver.immutable || receiver.fixedSize && !name.equals("set")) {
                    c.stopAfterException();
                    return unknown(c.typeName(call));
                }
                List<FlowValue> items = receiver.elements == null ? null : new ArrayList<>(receiver.elements);
                FlowValue previous = unknown(c.typeName(call));
                if (name.equals("clear")) items = new ArrayList<>();
                else if (items != null) {
                    Integer at = args.isEmpty() ? null : index(args.get(0));
                    if (name.equals("add") && args.size() == 1) items.add(args.get(0));
                    else if (name.equals("add") && args.size() == 2 && at != null && at >= 0 && at <= items.size()) items.add(at, args.get(1));
                    else if (name.equals("set") && args.size() == 2 && at != null && at >= 0 && at < items.size()) previous = items.set(at, args.get(1));
                    else if (name.equals("remove") && args.size() == 1) {
                        Element declaration = c.symbol(call.getMethodSelect());
                        boolean byIndex = declaration instanceof ExecutableElement method
                                ? method.getParameters().get(0).asType().getKind() == TypeKind.INT
                                : args.get(0).type.equals("int");
                        if (byIndex && at != null && at >= 0 && at < items.size()) previous = items.remove((int) at);
                        else if (!byIndex && args.get(0).text != null) {
                            for (int i = 0; i < items.size(); i++) {
                                FlowValue item = items.get(i);
                                if (item.text == null) { items = null; break; }
                                if (item.type.equals(args.get(0).type) && item.text.equals(args.get(0).text)) {
                                    items.remove(i); break;
                                }
                            }
                        } else items = null;
                    }
                    else if (name.equals("addAll") && args.size() == 1 && args.get(0).elements != null) items.addAll(args.get(0).elements);
                    else if (name.equals("addAll") && args.size() == 2 && at != null && at >= 0 && at <= items.size()
                            && args.get(1).elements != null) items.addAll(at, args.get(1).elements);
                    else items = null;
                }
                FlowValue changed = items == null ? unknown(receiver.type) : c.vector(items, receiver.type);
                c.mutate(receiver, changed);
                return previous;
            }
        }
        return null;
    }


    FlowValue collectionCall(MethodInvocationTree call, String name, String owner, FlowValue receiver, List<FlowValue> args) {
        if (owner.equals("java.util.Map") && name.equals("of")) {
            FlowValue map = new FlowValue(null, false, false, "Map");
            map.entries = new HashMap<>();
            map.immutable = true;
            map.origins = Set.of(c.newIdentity());
            for (int i = 0; i + 1 < args.size(); i += 2) {
                String key = mapKey(args.get(i));
                if (key == null) { map.entries = null; map.unsafe = true; break; }
                map.entries.put(key, args.get(i + 1));
                map.unsafe |= args.get(i + 1).unsafe;
            }
            return map;
        }
        if (Set.of("Map", "HashMap", "LinkedHashMap", "TreeMap").contains(receiver.type)) {
            String key = args.isEmpty() ? null : mapKey(args.get(0));
            if (name.equals("get") || name.equals("getOrDefault")) {
                FlowValue fallback = name.equals("getOrDefault") && args.size() > 1 ? args.get(1) : literal(null);
                if (receiver.entries == null) return unknown("?");
                if (key != null) return receiver.entries.getOrDefault(key, fallback);
                FlowValue result = fallback;
                for (FlowValue item : receiver.entries.values()) result = join(result, item);
                return result;
            }
            if (Set.of("put", "putIfAbsent", "remove", "clear", "putAll").contains(name)) {
                if (receiver.immutable) {
                    c.stopAfterException();
                    return unknown(c.typeName(call));
                }
                FlowValue changed = receiver.copy();
                FlowValue previous = key == null || receiver.entries == null ? unknown("?")
                        : receiver.entries.getOrDefault(key, literal(null));
                if (name.equals("clear")) changed.entries = new HashMap<>();
                else if (changed.entries != null && name.equals("putAll") && args.size() == 1 && args.get(0).entries != null) {
                    changed.entries.putAll(args.get(0).entries);
                } else if (changed.entries != null && key != null && args.size() == 2
                        && (name.equals("put") || name.equals("putIfAbsent"))) {
                    if (name.equals("put")) changed.entries.put(key, args.get(1));
                    else if (!changed.entries.containsKey(key) || changed.entries.get(key).definitelyNull) changed.entries.put(key, args.get(1));
                } else if (changed.entries != null && key != null && name.equals("remove")) {
                    if (args.size() == 1) changed.entries.remove(key);
                    else if (args.size() == 2 && previous.text != null && previous.text.equals(args.get(1).text)
                            && previous.type.equals(args.get(1).type)) changed.entries.remove(key);
                }
                else changed.entries = null;
                changed.unsafe = changed.entries == null || changed.entries.values().stream().anyMatch(v -> v.unsafe);
                changed.sql = changed.entries != null && changed.entries.values().stream().anyMatch(v -> v.sql);
                changed.inputDependent = changed.entries == null || changed.entries.values().stream().anyMatch(v -> v.inputDependent);
                c.mutate(receiver, changed);
                return name.equals("remove") && args.size() == 2 ? unknown("boolean") : previous;
            }
            if (Set.of("compute", "computeIfAbsent", "computeIfPresent", "merge", "replaceAll", "replace").contains(name)) {
                c.mutate(receiver, unknown(receiver.type));
                c.note(call, "Map callback/conditional mutation widened to unknown values");
                return unknown(c.typeName(call));
            }
        }
        if (owner.equals("java.lang.System") && name.equals("arraycopy") && args.size() == 5) {
            FlowValue changed = join(args.get(2), args.get(0));
            changed.elements = null;
            Integer from = index(args.get(1)), to = index(args.get(3)), count = index(args.get(4));
            if (args.get(0).elements != null && args.get(2).elements != null && from != null && to != null && count != null
                    && from >= 0 && to >= 0 && count >= 0 && count <= args.get(0).elements.size() - from
                    && count <= args.get(2).elements.size() - to) {
                changed.elements = new ArrayList<>(args.get(2).elements);
                for (int i = 0; i < count; i++) changed.elements.set(to + i, args.get(0).elements.get(from + i));
                changed.unsafe = changed.elements.stream().anyMatch(v -> v.unsafe);
                changed.sql = changed.elements.stream().anyMatch(v -> v.sql);
            }
            c.mutate(args.get(2), changed);
            return unknown("void");
        }
        if (owner.equals("java.util.Arrays") && (name.equals("copyOf") || name.equals("copyOfRange")) && !args.isEmpty()) {
            FlowValue result = args.get(0).copy();
            result.origins = Set.of(c.newIdentity());
            result.elements = null;
            Integer start = name.equals("copyOf") ? 0 : args.size() > 1 ? index(args.get(1)) : null;
            Integer end = args.size() > (name.equals("copyOf") ? 1 : 2)
                    ? index(args.get(name.equals("copyOf") ? 1 : 2)) : null;
            if (args.get(0).elements != null && start != null && end != null && start >= 0 && end >= start
                    && end <= args.get(0).elements.size()) result.elements = new ArrayList<>(args.get(0).elements.subList(start, end));
            return result;
        }
        if (owner.equals("java.util.Collections") && name.equals("singletonList") && args.size() == 1) {
            FlowValue singleton = c.vector(args, "List"); singleton.immutable = true; return singleton;
        }
        if (Set.of("List", "ArrayList", "LinkedList", "Vector").contains(receiver.type)) {
            if (name.equals("get") && args.size() == 1 && receiver.elements != null) {
                Integer at = index(args.get(0));
                if (at != null && at >= 0 && at < receiver.elements.size()) return receiver.elements.get(at);
                FlowValue result = literal(null);
                for (FlowValue item : receiver.elements) result = join(result, item);
                return result;
            }
            if (Set.of("removeIf", "replaceAll", "sort", "retainAll", "removeAll").contains(name)) {
                c.mutate(receiver, unknown(receiver.type));
                c.note(call, "Collection callback/bulk mutation widened to unknown elements");
                return unknown(c.typeName(call));
            }
        }
        return null;
    }

    boolean commandRisk(FlowValue command) {
        if (command.elements == null) return command.unsafe;
        List<FlowValue> args = command.elements;
        if (args.isEmpty()) return false; // start() fails without executing anything.
        FlowValue executable = args.get(0);
        if (executable.unsafe || executable.inputDependent) return true;
        Set<String> programs = programs(executable);
        boolean shell = programs.isEmpty() || programs.stream().anyMatch(this::shell);
        if (shell) return args.subList(1, args.size()).stream().anyMatch(v -> v.unsafe || v.inputDependent);
        boolean interpreter = programs.stream().anyMatch(this::interpreter);
        if (interpreter && args.size() > 1) {
            if (args.get(1).unsafe || args.get(1).inputDependent) return true;
            boolean codeFlag = args.get(1).choices.stream().anyMatch(CODE_FLAGS::contains);
            if (codeFlag) return args.subList(2, args.size()).stream().anyMatch(v -> v.unsafe || v.inputDependent);
        }
        return false;
    }

    boolean environmentRisk(FlowValue environment) {
        if (environment.definitelyNull) return false;
        if (environment.elements != null) return environment.elements.stream().anyMatch(v -> v.inputDependent);
        if (environment.entries != null) return environment.entries.values().stream().anyMatch(v -> v.inputDependent);
        return environment.inputDependent;
    }

    boolean commandStringRisk(FlowValue command) {
        if (command.unsafe) return true;
        if (!command.inputDependent) return false;
        String delimiters = " \t\n\r\f";
        int start = 0;
        while (start < command.prefix.length() && delimiters.indexOf(command.prefix.charAt(start)) >= 0) start++;
        int end = start;
        while (end < command.prefix.length() && delimiters.indexOf(command.prefix.charAt(end)) < 0) end++;
        if (end == command.prefix.length() || end == start) return true;
        FlowValue executable = literal(command.prefix.substring(start, end));
        return programs(executable).stream().anyMatch(p -> shell(p) || interpreter(p));
    }

    boolean processRisk(FlowValue process) {
        return process.command == null || commandRisk(process.command)
                || process.environment != null && environmentRisk(process.environment);
    }

    Set<String> programs(FlowValue executable) {
        Set<String> result = new HashSet<>();
        for (String choice : executable.choices) {
            String normalized = choice.replace('\\', '/');
            String name = normalized.substring(normalized.lastIndexOf('/') + 1).toLowerCase(Locale.ROOT);
            result.add(name.endsWith(".exe") ? name.substring(0, name.length() - 4) : name);
        }
        return result;
    }

    boolean shell(String name) { return SHELLS.contains(name) || name.endsWith(".bat") || name.endsWith(".cmd"); }

    boolean interpreter(String name) {
        return name.matches("python[23]?(\\.[0-9]+)*|pypy[23]?")
                || Set.of("node", "nodejs", "ruby", "perl", "php", "java", "wscript", "cscript").contains(name);
    }

    boolean codeProcess(FlowValue command) {
        if (command.elements == null) return command.unsafe;
        if (command.elements.isEmpty()) return false;
        FlowValue executable = command.elements.get(0);
        Set<String> programs = programs(executable);
        return executable.unsafe || programs.isEmpty() || programs.stream().anyMatch(p -> shell(p) || interpreter(p));
    }

    FlowValue format(FlowValue template, List<FlowValue> args) {
        if (template.unsafe) return new FlowValue(null, true, template.sql, "String");
        if (template.text == null) {
            return new FlowValue(null, args.stream().anyMatch(v -> v.unsafe), template.sql, "String");
        }
        FlowValue result = template.copy();
        Matcher conversions = FORMAT.matcher(template.text);
        int ordinary = 0, previous = -1;
        while (conversions.find()) {
            char conversion = Character.toLowerCase(conversions.group(4).charAt(0));
            if (conversion == '%' || conversion == 'n') continue;
            int index;
            try {
                index = conversions.group(2).contains("<") ? previous
                        : conversions.group(1) == null ? ordinary++ : Integer.parseInt(conversions.group(1)) - 1;
            } catch (NumberFormatException e) {
                return unknown("String");
            }
            previous = index;
            boolean packed = !args.isEmpty() && args.get(args.size() - 1).type.endsWith("[]");
            if (index < 0 || (index >= args.size() && !packed)) return unknown("String");
            FlowValue arg = args.get(Math.min(index, args.size() - 1));
            result.inputDependent |= arg.inputDependent;
            if (conversions.group(3) == null && conversion == 's') result = combine(result, arg);
            if (conversions.group(3) == null && conversion == 'c' && arg.text == null) result.unsafe = true;
        }
        result.text = null;
        result.choices = Set.of();
        int first = template.text.indexOf('%');
        result.prefix = first < 0 ? template.text : template.text.substring(0, first);
        return result;
    }


}
