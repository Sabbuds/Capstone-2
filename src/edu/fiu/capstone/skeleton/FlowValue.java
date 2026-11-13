package edu.fiu.capstone.skeleton;

import java.util.*;
import java.util.regex.Pattern;

/** Abstract values: syntax safety and input dependence differ for numeric data, executables and environments. */
final class FlowValue {
    static Integer index(FlowValue value) {
        try { return value.text == null ? null : Integer.valueOf(value.text); }
        catch (NumberFormatException e) { return null; }
    }

    static String mapKey(FlowValue value) {
        return value.text == null ? null : value.type + ":" + value.text;
    }
    static final Set<String> NUMERIC_TYPES = Set.of(
            "byte", "short", "int", "long", "float", "double", "boolean",
            "Byte", "Short", "Integer", "Long", "Float", "Double", "Boolean",
            "BigInteger", "BigDecimal");
    static final Pattern SQL = Pattern.compile(
            "(?is)^\\s*(?:(?:/\\*.*?\\*/|--[^\\r\\n]*(?:\\r?\\n|$))\\s*)*"
                    + "(?:SELECT|INSERT|UPDATE|DELETE|REPLACE|MERGE|WITH|CREATE|"
                    + "ALTER|DROP|TRUNCATE|CALL|EXEC|GRANT|REVOKE|SHOW|EXPLAIN|VALUES)\\b"
                    + "|(?is)^\\s*\\{\\s*(?:\\?\\s*=\\s*)?call\\b");
    static String simpleType(String type) {
        return type.substring(type.lastIndexOf('.') + 1);
    }

    static boolean builder(FlowValue value) {
        return value.type.equals("StringBuilder") || value.type.equals("StringBuffer")
                || value.type.equals("StringJoiner");
    }

    static FlowValue unknown(String type) {
        FlowValue result = new FlowValue(null, !NUMERIC_TYPES.contains(type), false, type);
        result.inputDependent = true;
        return result;
    }

    static FlowValue literal(Object value) {
        if (value == null) return new FlowValue(null, false, false, "null");
        String text = String.valueOf(value);
        return new FlowValue(text, false, SQL.matcher(text).find(),
                value instanceof String ? "String" : value instanceof Character ? "char"
                        : value instanceof Boolean ? "boolean" : value instanceof Float ? "float"
                        : value instanceof Double ? "double" : value instanceof Long ? "long" : "int");
    }

    static FlowValue combine(FlowValue left, FlowValue right) {
        String text = left.text != null && right.text != null ? left.text + right.text : null;
        FlowValue result = new FlowValue(text, left.unsafe || right.unsafe,
                left.sql || right.sql || (text != null && SQL.matcher(text).find()), "String");
        result.inputDependent = left.inputDependent || right.inputDependent;
        result.prefix = left.text == null ? left.prefix : left.text + right.prefix;
        return result;
    }

    static FlowValue join(FlowValue left, FlowValue right) {
        return join(left, right, new HashMap<>());
    }

    private static FlowValue join(FlowValue left, FlowValue right, Map<List<FlowValue>, FlowValue> visited) {
        List<FlowValue> key = List.of(left, right);
        if (visited.containsKey(key)) return visited.get(key);
        FlowValue result = new FlowValue(Objects.equals(left.text, right.text) ? left.text : null,
                left.unsafe || right.unsafe, left.sql || right.sql,
                left.type.equals(right.type) ? left.type : "?");
        visited.put(key, result);
        Set<Integer> origins = new HashSet<>(left.origins);
        origins.addAll(right.origins);
        result.origins = origins;
        Set<String> choices = new HashSet<>(left.choices);
        choices.addAll(right.choices);
        result.choices = choices;
        if (left.elements != null && right.elements != null && left.elements.size() == right.elements.size()) {
            result.elements = new ArrayList<>();
            for (int i = 0; i < left.elements.size(); i++) result.elements.add(join(left.elements.get(i), right.elements.get(i), visited));
        }
        if (left.command != null && right.command != null) result.command = join(left.command, right.command, visited);
        if (left.environment != null && right.environment != null) result.environment = join(left.environment, right.environment, visited);
        result.entries = joinFields(left.entries, right.entries, visited);
        result.members = joinFields(left.members, right.members, visited);
        Set<String> runtimeTypes = new HashSet<>(left.runtimeTypes);
        runtimeTypes.addAll(right.runtimeTypes);
        result.runtimeTypes = runtimeTypes;
        result.definitelyNull = left.definitelyNull && right.definitelyNull;
        result.immutable = left.immutable && right.immutable;
        result.fixedSize = left.fixedSize && right.fixedSize;
        result.knownNonNull = left.knownNonNull && right.knownNonNull;
        result.inputDependent = left.inputDependent || right.inputDependent;
        int common = 0;
        while (common < left.prefix.length() && common < right.prefix.length()
                && left.prefix.charAt(common) == right.prefix.charAt(common)) common++;
        result.prefix = left.prefix.substring(0, common);
        return result;
    }

    private static Map<String, FlowValue> joinFields(Map<String, FlowValue> left, Map<String, FlowValue> right,
                                                    Map<List<FlowValue>, FlowValue> visited) {
        if (left == null || right == null) return null;
        Map<String, FlowValue> result = new HashMap<>();
        Set<String> keys = new HashSet<>(left.keySet());
        keys.addAll(right.keySet());
        for (String key : keys) result.put(key, join(left.getOrDefault(key, literal(null)),
                right.getOrDefault(key, literal(null)), visited));
        return result;
    }

    static FlowValue typed(FlowValue value, String type) {
        if (NUMERIC_TYPES.contains(type)) {
            FlowValue result = new FlowValue(NUMERIC_TYPES.contains(value.type) ? value.text : null, false, false, type);
            result.inputDependent = value.inputDependent;
            return result;
        }
        if (type.equals("var") || type.equals("?") || type.equals(value.type)) return value;
        FlowValue result = new FlowValue(value.text, value.unsafe, value.sql, type);
        result.copyState(value);
        return result;
    }


    String text;
    boolean unsafe;
    boolean sql;
    final String type;
    Set<Integer> origins = Set.of();
    Set<String> choices = Set.of();
    List<FlowValue> elements;
    FlowValue command;
    FlowValue environment;
    Map<String, FlowValue> entries;
    Map<String, FlowValue> members;
    Set<String> runtimeTypes = Set.of();
    boolean definitelyNull;
    boolean immutable;
    boolean fixedSize;
    boolean knownNonNull;
    boolean inputDependent;
    String prefix = "";

    FlowValue(String text, boolean unsafe, boolean sql, String type) {
        this.text = text;
        this.unsafe = unsafe;
        inputDependent = unsafe;
        this.sql = sql;
        this.type = type;
        definitelyNull = type.equals("null");
        knownNonNull = text != null && !definitelyNull;
        if (type.startsWith("source:")) runtimeTypes = Set.of(type);
        if (text != null) choices = Set.of(text);
        if (text != null) prefix = text;
    }

    FlowValue copy() {
        FlowValue result = new FlowValue(text, unsafe, sql, type);
        result.copyState(this);
        result.elements = elements == null ? null : new ArrayList<>(elements);
        result.entries = entries == null ? null : new HashMap<>(entries);
        result.members = members == null ? null : new HashMap<>(members);
        return result;
    }

    void set(FlowValue other) {
        Set<Integer> identity = origins;
        boolean oldImmutable = immutable, oldFixedSize = fixedSize;
        text = other.text;
        unsafe = other.unsafe;
        sql = other.sql;
        copyState(other);
        origins = identity;
        immutable = oldImmutable;
        fixedSize = oldFixedSize;
    }

    private void copyState(FlowValue other) {
        origins = other.origins;
        choices = other.choices;
        elements = other.elements;
        command = other.command;
        environment = other.environment;
        entries = other.entries;
        members = other.members;
        runtimeTypes = other.runtimeTypes;
        definitelyNull = other.definitelyNull;
        immutable = other.immutable;
        fixedSize = other.fixedSize;
        knownNonNull = other.knownNonNull;
        inputDependent = other.inputDependent;
        prefix = other.prefix;
    }

}
