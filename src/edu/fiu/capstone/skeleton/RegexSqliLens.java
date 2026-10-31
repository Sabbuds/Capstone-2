package edu.fiu.capstone.skeleton;

import com.sun.source.tree.*;
import com.sun.source.util.JavacTask;
import com.sun.source.util.SourcePositions;
import com.sun.source.util.TreeScanner;
import com.sun.source.util.TreePath;
import com.sun.source.util.TreePathScanner;
import com.sun.source.util.Trees;
import java.io.IOException;
import java.net.URI;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.tools.*;
import javax.lang.model.element.Element;
import javax.lang.model.element.ExecutableElement;
import javax.lang.model.element.TypeElement;
import javax.lang.model.element.VariableElement;
import javax.lang.model.type.TypeKind;
import javax.lang.model.type.TypeMirror;
import javax.lang.model.util.Types;

/**
 * JDBC SQL-injection analysis using the JDK parser (JDK 17+).
 * The historical class name and lens ID are retained for existing callers.
 * Unknown strings are untrusted; constants, finite literal choices and numeric
 * values are safe. Passing a value as a bound parameter is not a SQL sink.
 * This is conservative static analysis, not proof of exploitability: external
 * helper contracts without available source, cross-object state and arbitrary
 * framework APIs are outside its model. Input is parsed and type-checked;
 * no application bytecode is generated or executed.
 */
public class RegexSqliLens implements SecurityLens {
    private static final Set<String> SINKS = Set.of(
            "executeQuery", "executeUpdate", "executeLargeUpdate", "execute",
            "addBatch", "prepareStatement", "prepareCall");
    private static final Set<String> JDBC_TYPES = Set.of(
            "Statement", "PreparedStatement", "CallableStatement", "Connection");
    private static final Set<String> NUMERIC_TYPES = Set.of(
            "byte", "short", "int", "long", "float", "double", "boolean",
            "Byte", "Short", "Integer", "Long", "Float", "Double", "Boolean",
            "BigInteger", "BigDecimal");
    private static final Pattern SQL = Pattern.compile(
            "(?is)^\\s*(?:(?:/\\*.*?\\*/|--[^\\r\\n]*(?:\\r?\\n|$))\\s*)*"
                    + "(?:SELECT|INSERT|UPDATE|DELETE|REPLACE|MERGE|WITH|CREATE|"
                    + "ALTER|DROP|TRUNCATE|CALL|EXEC|GRANT|REVOKE|SHOW|EXPLAIN|VALUES)\\b"
                    + "|(?is)^\\s*\\{\\s*(?:\\?\\s*=\\s*)?call\\b");
    private static final Pattern FORMAT = Pattern.compile(
            "%(?:(\\d+)\\$)?([-#+ 0,(<]*)(?:\\d+)?(?:\\.\\d+)?([tT])?([a-zA-Z%])");

    @Override
    public String id() {
        return "regex-sqli";
    }

    @Override
    public List<Finding> analyze(String fileName, String sourceCode) {
        Objects.requireNonNull(fileName, "fileName");
        Objects.requireNonNull(sourceCode, "sourceCode");
        JavaCompiler compiler = ToolProvider.getSystemJavaCompiler();
        if (compiler == null) {
            throw new IllegalStateException("SQL detection requires a JDK, not a standalone JRE.");
        }
        // Also accept method and statement fragments used by the existing API/tests.
        String[] prefixes = {"", "class __SqlInput {\n", "class __SqlInput { void __scan() {\n"};
        String[] suffixes = {"", "\n}", "\n} }"};
        for (int i = 0; i < prefixes.length; i++) {
            String input = prefixes[i] + sourceCode + suffixes[i];
            JavaFileObject file = new SimpleJavaFileObject(
                    URI.create("string:///__SqlInput.java"), JavaFileObject.Kind.SOURCE) {
                @Override
                public CharSequence getCharContent(boolean ignoreEncodingErrors) {
                    return input;
                }
            };
            DiagnosticCollector<JavaFileObject> diagnostics = new DiagnosticCollector<>();
            try (StandardJavaFileManager manager = compiler.getStandardFileManager(null, null, null)) {
                JavacTask task = (JavacTask) compiler.getTask(null, manager, diagnostics,
                        List.of("-proc:none"), null, List.of(file));
                CompilationUnitTree unit = task.parse().iterator().next();
                if (diagnostics.getDiagnostics().stream().anyMatch(
                        d -> d.getKind() == Diagnostic.Kind.ERROR)) {
                    continue;
                }
                // Resolve available symbols; unresolved dependencies in fragments remain unknown.
                task.analyze();
                Analyzer analyzer = new Analyzer(fileName, sourceCode, prefixes[i].length(), unit, task);
                analyzer.scan(unit, null);
                return new ArrayList<>(analyzer.findings.values());
            } catch (IOException e) {
                throw new IllegalStateException("Could not parse Java source", e);
            }
        }
        throw new IllegalArgumentException("Cannot analyze malformed Java source: " + fileName);
    }

    private static String simpleType(String type) {
        return type.substring(type.lastIndexOf('.') + 1);
    }

    private static boolean builder(Value value) {
        return value.type.equals("StringBuilder") || value.type.equals("StringBuffer")
                || value.type.equals("StringJoiner");
    }

    private static Value unknown(String type) {
        return new Value(null, !NUMERIC_TYPES.contains(type), false, type);
    }

    private static Value literal(Object value) {
        if (value == null) return new Value(null, false, false, "null");
        String text = String.valueOf(value);
        return new Value(text, false, SQL.matcher(text).find(),
                value instanceof String ? "String" : value instanceof Character ? "char"
                        : value instanceof Boolean ? "boolean" : value instanceof Float ? "float"
                        : value instanceof Double ? "double" : value instanceof Long ? "long" : "int");
    }

    private static Value combine(Value left, Value right) {
        String text = left.text != null && right.text != null ? left.text + right.text : null;
        return new Value(text, left.unsafe || right.unsafe,
                left.sql || right.sql || (text != null && SQL.matcher(text).find()), "String");
    }

    private static Value join(Value left, Value right) {
        Value result = new Value(Objects.equals(left.text, right.text) ? left.text : null,
                left.unsafe || right.unsafe, left.sql || right.sql,
                left.type.equals(right.type) ? left.type : "?");
        Set<Integer> origins = new HashSet<>(left.origins);
        origins.addAll(right.origins);
        result.origins = origins;
        return result;
    }

    private static Value typed(Value value, String type) {
        if (NUMERIC_TYPES.contains(type)) {
            return new Value(NUMERIC_TYPES.contains(value.type) ? value.text : null, false, false, type);
        }
        if (type.equals("var") || type.equals("?") || type.equals(value.type)) return value;
        Value result = new Value(value.text, value.unsafe, value.sql, type);
        result.origins = value.origins;
        return result;
    }

    private static final class Value {
        String text;
        boolean unsafe;
        boolean sql;
        final String type;
        Set<Integer> origins = Set.of();

        Value(String text, boolean unsafe, boolean sql, String type) {
            this.text = text;
            this.unsafe = unsafe;
            this.sql = sql;
            this.type = type;
        }

        Value copy() {
            Value result = new Value(text, unsafe, sql, type);
            result.origins = origins;
            return result;
        }

        void set(Value other) {
            text = other.text;
            unsafe = other.unsafe;
            sql = other.sql;
        }
    }

    private static final class Analyzer extends TreeScanner<Void, Void> {
        final String fileName;
        final String source;
        final int offset;
        final CompilationUnitTree unit;
        final SourcePositions positions;
        final Trees trees;
        final Types types;
        final Map<Element, MethodTree> methodDeclarations = new HashMap<>();
        final Map<MethodTree, ClassTree> methodClasses = new IdentityHashMap<>();
        final Map<Element, ClassTree> classDeclarations = new HashMap<>();
        final Map<ClassTree, Map<String, Value>> classFields = new IdentityHashMap<>();
        final List<TypeMirror> jdbcTypes = new ArrayList<>();
        ClassTree currentClass;
        final SortedMap<Integer, Finding> findings = new TreeMap<>();
        List<Map<String, Value>> scopes = new ArrayList<>();
        List<List<Map<String, Value>>> exceptionPaths = new ArrayList<>();
        Map<String, List<MethodTree>> methods = new HashMap<>();
        final Set<MethodTree> activeMethods = new HashSet<>();
        Value returned;
        Value yielded;
        int nextObjectId;
        String className = "";
        boolean abrupt;
        List<Exits> exits = new ArrayList<>();
        String pendingLabel;

        private static final class Exits {
            final boolean loop;
            final int depth;
            final String label;
            final List<List<Map<String, Value>>> breaks = new ArrayList<>();
            final List<List<Map<String, Value>>> continues = new ArrayList<>();

            Exits(boolean loop, int depth, String label) {
                this.loop = loop;
                this.depth = depth;
                this.label = label;
            }
        }

        Analyzer(String fileName, String source, int offset,
                 CompilationUnitTree unit, JavacTask task) {
            this.fileName = fileName;
            this.source = source;
            this.offset = offset;
            this.unit = unit;
            this.trees = Trees.instance(task);
            this.positions = trees.getSourcePositions();
            this.types = task.getTypes();
            for (String name : JDBC_TYPES) {
                TypeElement type = task.getElements().getTypeElement("java.sql." + name);
                if (type != null) jdbcTypes.add(types.erasure(type.asType()));
            }
            new TreePathScanner<Void, Void>() {
                @Override
                public Void visitClass(ClassTree node, Void unused) {
                    Element symbol = trees.getElement(getCurrentPath());
                    if (symbol != null) classDeclarations.put(symbol, node);
                    return super.visitClass(node, unused);
                }

                @Override
                public Void visitMethod(MethodTree node, Void unused) {
                    Element symbol = trees.getElement(getCurrentPath());
                    if (symbol != null) methodDeclarations.put(symbol, node);
                    for (TreePath parent = getCurrentPath().getParentPath(); parent != null;
                         parent = parent.getParentPath()) {
                        if (parent.getLeaf() instanceof ClassTree owner) {
                            methodClasses.put(node, owner);
                            break;
                        }
                    }
                    return super.visitMethod(node, unused);
                }
            }.scan(unit, null);
            scopes.add(new HashMap<>());
        }

        Element symbol(Tree node) {
            TreePath path = TreePath.getPath(unit, node);
            return path == null ? null : trees.getElement(path);
        }

        String typeName(Tree node) {
            TreePath path = TreePath.getPath(unit, node);
            TypeMirror type = path == null ? null : trees.getTypeMirror(path);
            if (type == null || type.getKind() == TypeKind.ERROR || type.getKind() == TypeKind.NONE) {
                return node == null ? "?" : simpleType(node.toString());
            }
            Element declaration = types.asElement(type);
            if (classDeclarations.containsKey(declaration)) return "source:" + type;
            if (declaration instanceof TypeElement declared) return simpleType(declared.getQualifiedName().toString());
            return simpleType(type.toString());
        }

        Boolean truth(Value value) {
            if (value.type.equals("boolean") || value.type.equals("Boolean")) {
                if ("true".equals(value.text)) return true;
                if ("false".equals(value.text)) return false;
            }
            return null;
        }

        Value comparison(BinaryTree expression, Value left, Value right) {
            if ((expression.getKind() == Tree.Kind.EQUAL_TO || expression.getKind() == Tree.Kind.NOT_EQUAL_TO)
                    && !Set.of("byte", "short", "int", "long", "float", "double", "boolean").contains(left.type)
                    && !Set.of("byte", "short", "int", "long", "float", "double", "boolean").contains(right.type)) {
                return unknown("boolean");
            }
            Boolean a = truth(left), b = truth(right);
            if (a != null && b != null) {
                return switch (expression.getKind()) {
                    case EQUAL_TO -> literal(a.equals(b));
                    case NOT_EQUAL_TO -> literal(!a.equals(b));
                    default -> unknown("boolean");
                };
            }
            if (left.text == null || right.text == null
                    || !NUMERIC_TYPES.contains(left.type) || !NUMERIC_TYPES.contains(right.type)) {
                return unknown("boolean");
            }
            try {
                int order;
                Set<String> floating = Set.of("float", "Float", "double", "Double");
                if (floating.contains(left.type) || floating.contains(right.type)) {
                    double x = Double.parseDouble(left.text), y = Double.parseDouble(right.text);
                    if (!left.type.equals("double") && !left.type.equals("Double")
                            && !right.type.equals("double") && !right.type.equals("Double")) {
                        x = (float) x;
                        y = (float) y;
                    }
                    if (Double.isNaN(x) || Double.isNaN(y)) {
                        return literal(expression.getKind() == Tree.Kind.NOT_EQUAL_TO);
                    }
                    order = x == y ? 0 : x < y ? -1 : 1;
                } else {
                    order = new java.math.BigDecimal(left.text).compareTo(new java.math.BigDecimal(right.text));
                }
                return switch (expression.getKind()) {
                    case EQUAL_TO -> literal(order == 0);
                    case NOT_EQUAL_TO -> literal(order != 0);
                    case LESS_THAN -> literal(order < 0);
                    case LESS_THAN_EQUAL -> literal(order <= 0);
                    case GREATER_THAN -> literal(order > 0);
                    case GREATER_THAN_EQUAL -> literal(order >= 0);
                    default -> unknown("boolean");
                };
            } catch (NumberFormatException e) {
                return unknown("boolean");
            }
        }

        Value known(ExpressionTree expression) {
            if (expression instanceof ParenthesizedTree parens) return known(parens.getExpression());
            if (expression instanceof LiteralTree constant) return literal(constant.getValue());
            if (expression instanceof IdentifierTree identifier) return get(identifier.getName().toString());
            Element element = symbol(expression);
            if (element instanceof VariableElement variable && variable.getConstantValue() != null) {
                return literal(variable.getConstantValue());
            }
            if (expression instanceof MethodInvocationTree call && immutableFactory(call)) {
                return new Value(null, call.getArguments().stream().map(this::known).anyMatch(v -> v.unsafe),
                        false, typeName(call));
            }
            return unknown("?");
        }

        boolean immutableFactory(MethodInvocationTree call) {
            Element resolved = symbol(call.getMethodSelect());
            if (!(resolved instanceof ExecutableElement method)) return false;
            String owner = method.getEnclosingElement().toString();
            return (owner.equals("java.util.Set") || owner.equals("java.util.List"))
                    && (method.getSimpleName().contentEquals("of") || method.getSimpleName().contentEquals("copyOf"));
        }

        void assume(ExpressionTree condition, boolean holds) {
            if (condition instanceof ParenthesizedTree parens) {
                assume(parens.getExpression(), holds);
            } else if (condition instanceof UnaryTree unary && unary.getKind() == Tree.Kind.LOGICAL_COMPLEMENT) {
                assume(unary.getExpression(), !holds);
            } else if (condition instanceof BinaryTree binary) {
                boolean and = binary.getKind() == Tree.Kind.CONDITIONAL_AND;
                boolean or = binary.getKind() == Tree.Kind.CONDITIONAL_OR;
                if ((and && holds) || (or && !holds)) {
                    assume(binary.getLeftOperand(), holds);
                    assume(binary.getRightOperand(), holds);
                } else if (and || or) {
                    List<Map<String, Value>> before = snapshot();
                    assume(binary.getLeftOperand(), holds);
                    List<Map<String, Value>> first = snapshot();
                    scopes = before;
                    assume(binary.getLeftOperand(), !holds);
                    assume(binary.getRightOperand(), holds);
                    merge(first);
                } else if ((binary.getKind() == Tree.Kind.EQUAL_TO && holds)
                        || (binary.getKind() == Tree.Kind.NOT_EQUAL_TO && !holds)) {
                    restrict(binary.getLeftOperand(), binary.getRightOperand(), false);
                    restrict(binary.getRightOperand(), binary.getLeftOperand(), false);
                }
            } else if (holds && condition instanceof MethodInvocationTree call
                    && call.getMethodSelect() instanceof MemberSelectTree member
                    && call.getArguments().size() == 1) {
                String name = member.getIdentifier().toString();
                Value receiver = known(member.getExpression());
                Value argument = known(call.getArguments().get(0));
                if (name.equals("equals") || name.equals("equalsIgnoreCase")) {
                    if (receiver.type.equals("String")) {
                        restrict(call.getArguments().get(0), member.getExpression(), name.equals("equalsIgnoreCase"));
                        if (argument.type.equals("String")) {
                            restrict(member.getExpression(), call.getArguments().get(0), name.equals("equalsIgnoreCase"));
                        }
                    }
                } else if (name.equals("contains") && !receiver.unsafe
                        && (receiver.type.equals("Set") || receiver.type.equals("List"))
                        && argument.type.equals("String")) {
                    assign(call.getArguments().get(0), new Value(null, false, false, "String"));
                }
            }
        }

        void restrict(ExpressionTree target, ExpressionTree constant, boolean ignoreCase) {
            Value allowed = known(constant);
            if (!allowed.type.equals("String") || allowed.text == null || allowed.unsafe) return;
            if (target instanceof IdentifierTree || target instanceof MemberSelectTree) {
                assign(target, new Value(ignoreCase ? null : allowed.text, false, allowed.sql, "String"));
            }
        }

        boolean jdbcMethod(ExecutableElement method) {
            TypeMirror owner = method.getEnclosingElement().asType();
            return jdbcTypes.stream().anyMatch(type -> types.isSubtype(types.erasure(owner), type));
        }

        Map<String, List<MethodTree>> methodsOf(ClassTree owner) {
            Map<String, List<MethodTree>> result = new HashMap<>();
            if (owner != null) {
                for (Tree member : owner.getMembers()) {
                    if (member instanceof MethodTree method) {
                        result.computeIfAbsent(method.getName().toString(), key -> new ArrayList<>()).add(method);
                    }
                }
            }
            return result;
        }

        Value get(String name) {
            for (int i = scopes.size() - 1; i >= 0; i--) {
                Value value = scopes.get(i).get(name);
                if (value != null) return value;
            }
            return unknown("?");
        }

        void assign(ExpressionTree target, Value value) {
            if (target instanceof IdentifierTree identifier) {
                String name = identifier.getName().toString();
                for (int i = scopes.size() - 1; i >= 0; i--) {
                    if (scopes.get(i).containsKey(name)) {
                        scopes.get(i).put(name, typed(value, scopes.get(i).get(name).type));
                        return;
                    }
                }
                scopes.get(scopes.size() - 1).put(name, value);
            } else if (target instanceof MemberSelectTree member
                    && member.getExpression().toString().equals("this")) {
                String name = member.getIdentifier().toString();
                scopes.get(0).put(name, typed(value, scopes.get(0).getOrDefault(name, value).type));
            } else if (target instanceof ArrayAccessTree array) {
                Value container = value(array.getExpression());
                mutate(container, join(container, value));
            }
        }

        void mutate(Value receiver, Value replacement) {
            receiver.set(replacement);
            for (Map<String, Value> scope : scopes) {
                for (Value alias : scope.values()) {
                    if (alias == receiver || Collections.disjoint(alias.origins, receiver.origins)) continue;
                    alias.set(alias.origins.equals(receiver.origins) && alias.origins.size() == 1
                            ? replacement : join(alias, replacement));
                }
            }
        }

        List<Map<String, Value>> snapshot() {
            return copyState(scopes);
        }

        List<Map<String, Value>> copyState(List<Map<String, Value>> state) {
            IdentityHashMap<Value, Value> copies = new IdentityHashMap<>();
            List<Map<String, Value>> result = new ArrayList<>();
            for (Map<String, Value> scope : state) {
                Map<String, Value> copy = new HashMap<>();
                scope.forEach((name, value) -> copy.put(name,
                        copies.computeIfAbsent(value, v -> v.copy())));
                result.add(copy);
            }
            return result;
        }

        void merge(List<Map<String, Value>> other) {
            mergeInto(scopes, other);
        }

        void mergeInto(List<Map<String, Value>> state, List<Map<String, Value>> other) {
            // Keep definite aliases identical; object origins also retain possible aliases.
            Map<List<Value>, Value> joined = new HashMap<>();
            for (int i = 0; i < Math.min(state.size(), other.size()); i++) {
                Map<String, Value> alternate = other.get(i);
                state.get(i).replaceAll((name, value) -> {
                    Value right = alternate.getOrDefault(name, unknown(value.type));
                    return joined.computeIfAbsent(List.of(value, right),
                            pair -> join(value, right));
                });
            }
        }

        @Override
        public Void visitClass(ClassTree node, Void unused) {
            List<Map<String, Value>> saved = scopes;
            List<List<Map<String, Value>>> savedExceptions = exceptionPaths;
            List<Exits> savedExits = exits;
            boolean savedAbrupt = abrupt;
            Value savedReturn = returned, savedYield = yielded;
            String savedLabel = pendingLabel;
            exceptionPaths = new ArrayList<>();
            exits = new ArrayList<>();
            abrupt = false;
            returned = null;
            yielded = null;
            pendingLabel = null;
            ClassTree savedClassTree = currentClass;
            currentClass = node;
            String savedClass = className;
            className = node.getSimpleName().toString();
            Map<String, List<MethodTree>> savedMethods = methods;
            methods = methodsOf(node);
            scopes = new ArrayList<>();
            boolean initialize = !classFields.containsKey(node);
            scopes.add(classFields.computeIfAbsent(node, key -> new HashMap<>()));
            if (initialize) {
                for (Tree member : node.getMembers()) if (member instanceof VariableTree) scan(member, null);
                for (Tree member : node.getMembers()) if (member instanceof BlockTree) scan(member, null);
            }
            List<Map<String, Value>> before;
            do {
                before = snapshot();
                for (Tree member : node.getMembers()) if (member instanceof MethodTree) scan(member, null);
            } while (!sameState(before));
            for (Tree member : node.getMembers()) if (member instanceof ClassTree) scan(member, null);
            scopes = saved;
            methods = savedMethods;
            className = savedClass;
            currentClass = savedClassTree;
            exceptionPaths = savedExceptions;
            exits = savedExits;
            abrupt = savedAbrupt;
            returned = savedReturn;
            yielded = savedYield;
            pendingLabel = savedLabel;
            return null;
        }

        @Override
        public Void visitMethod(MethodTree node, Void unused) {
            List<Map<String, Value>> saved = scopes;
            boolean savedAbrupt = abrupt;
            abrupt = false;
            Value savedReturn = returned;
            returned = null;
            activeMethods.add(node);
            scopes = snapshot();
            scopes.add(new HashMap<>());
            for (VariableTree parameter : node.getParameters()) scan(parameter, null);
            scan(node.getBody(), null);
            mergeInto(saved, scopes.subList(0, 1));
            scopes = saved;
            returned = savedReturn;
            activeMethods.remove(node);
            abrupt = savedAbrupt;
            return null;
        }

        @Override
        public Void visitBlock(BlockTree node, Void unused) {
            scopes.add(new HashMap<>());
            captureException();
            for (StatementTree statement : node.getStatements()) {
                scan(statement, null);
                captureException();
                if (abrupt) break;
            }
            scopes.remove(scopes.size() - 1);
            return null;
        }

        @Override
        public Void visitVariable(VariableTree node, Void unused) {
            String type = node.getType() == null ? "?" : typeName(node.getType());
            Value initial = node.getInitializer() == null
                    ? (scopes.size() == 1 ? literal(null) : unknown(type)) : value(node.getInitializer());
            initial = typed(initial, type);
            if ((builder(initial) || initial.type.endsWith("[]")) && initial.origins.isEmpty()) {
                initial.origins = Set.of(++nextObjectId);
            }
            scopes.get(scopes.size() - 1).put(node.getName().toString(), initial);
            return null;
        }

        @Override
        public Void visitExpressionStatement(ExpressionStatementTree node, Void unused) {
            value(node.getExpression());
            return null;
        }

        @Override
        public Void visitMethodInvocation(MethodInvocationTree node, Void unused) {
            value(node);
            return null;
        }

        @Override
        public Void visitReturn(ReturnTree node, Void unused) {
            Value result = value(node.getExpression());
            returned = returned == null ? result.copy() : join(returned, result);
            abrupt = true;
            return null;
        }

        @Override
        public Void visitThrow(ThrowTree node, Void unused) {
            value(node.getExpression());
            captureException();
            abrupt = true;
            return null;
        }

        @Override
        public Void visitBreak(BreakTree node, Void unused) {
            for (int i = exits.size() - 1; i >= 0; i--) {
                Exits target = exits.get(i);
                if (node.getLabel() == null || node.getLabel().toString().equals(target.label)) {
                    target.breaks.add(copyState(scopes.subList(0, target.depth)));
                    break;
                }
            }
            abrupt = true;
            return null;
        }

        @Override
        public Void visitContinue(ContinueTree node, Void unused) {
            for (int i = exits.size() - 1; i >= 0; i--) {
                Exits target = exits.get(i);
                if (target.loop && (node.getLabel() == null || node.getLabel().toString().equals(target.label))) {
                    target.continues.add(copyState(scopes.subList(0, target.depth)));
                    break;
                }
            }
            abrupt = true;
            return null;
        }

        @Override
        public Void visitLabeledStatement(LabeledStatementTree node, Void unused) {
            String savedLabel = pendingLabel;
            pendingLabel = node.getLabel().toString();
            StatementTree body = node.getStatement();
            if (body instanceof WhileLoopTree || body instanceof DoWhileLoopTree
                    || body instanceof ForLoopTree || body instanceof EnhancedForLoopTree
                    || body instanceof SwitchTree) {
                scan(body, null);
            } else {
                Exits jumps = new Exits(false, scopes.size(), pendingLabel);
                pendingLabel = null;
                exits.add(jumps);
                scan(body, null);
                for (List<Map<String, Value>> path : jumps.breaks) merge(path);
                if (!jumps.breaks.isEmpty()) abrupt = false;
                exits.remove(exits.size() - 1);
            }
            pendingLabel = savedLabel;
            return null;
        }

        void captureException() {
            if (!exceptionPaths.isEmpty()) {
                List<Map<String, Value>> current = snapshot();
                for (List<Map<String, Value>> path : exceptionPaths) mergeInto(path, current);
            }
        }

        @Override
        public Void visitTry(TryTree node, Void unused) {
            scopes.add(new HashMap<>());
            List<Map<String, Value>> exceptional = snapshot();
            exceptionPaths.add(exceptional);
            scan(node.getResources(), null);
            scan(node.getBlock(), null);
            captureException();
            exceptionPaths.remove(exceptionPaths.size() - 1);
            List<Map<String, Value>> exits = snapshot();
            boolean allAbrupt = abrupt;
            for (CatchTree handler : node.getCatches()) {
                abrupt = false;
                scopes = copyState(exceptional);
                scopes.add(new HashMap<>());
                scan(handler.getParameter(), null);
                scan(handler.getBlock(), null);
                allAbrupt &= abrupt;
                scopes.remove(scopes.size() - 1);
                merge(exits);
                exits = snapshot();
            }
            scopes = exits;
            abrupt = false;
            scan(node.getFinallyBlock(), null);
            abrupt |= allAbrupt;
            scopes.remove(scopes.size() - 1);
            return null;
        }

        @Override
        public Void visitSwitch(SwitchTree node, Void unused) {
            switchValue(node.getExpression(), node.getCases());
            return null;
        }

        @Override
        public Void visitYield(YieldTree node, Void unused) {
            Value result = value(node.getValue());
            yielded = yielded == null ? result.copy() : join(yielded, result);
            return null;
        }

        Value switchValue(ExpressionTree selector, List<? extends CaseTree> cases) {
            value(selector);
            Value savedYield = yielded;
            yielded = null;
            scopes.add(new HashMap<>());
            Exits jumps = new Exits(false, scopes.size(), pendingLabel);
            pendingLabel = null;
            exits.add(jumps);
            List<Map<String, Value>> before = snapshot(), exits = null, fallthrough = null;
            boolean hasDefault = false;
            for (CaseTree branch : cases) {
                hasDefault |= branch.getExpressions().isEmpty();
                abrupt = false;
                scopes = copyState(before);
                if (fallthrough != null) merge(fallthrough);
                if (branch.getBody() instanceof ExpressionTree expression) {
                    Value result = value(expression);
                    yielded = yielded == null ? result.copy() : join(yielded, result);
                } else {
                    if (branch.getStatements() != null) {
                        for (StatementTree statement : branch.getStatements()) {
                            scan(statement, null);
                            if (abrupt) break;
                        }
                    }
                    scan(branch.getBody(), null);
                }
                fallthrough = !abrupt && branch.getCaseKind() == CaseTree.CaseKind.STATEMENT ? snapshot() : null;
                if (exits != null) merge(exits);
                exits = snapshot();
            }
            if (exits != null) scopes = exits;
            if (!hasDefault) merge(before);
            for (List<Map<String, Value>> path : jumps.breaks) merge(path);
            this.exits.remove(this.exits.size() - 1);
            abrupt = false;
            scopes.remove(scopes.size() - 1);
            Value result = yielded == null ? unknown("?") : yielded;
            yielded = savedYield;
            return result;
        }

        @Override
        public Void visitIf(IfTree node, Void unused) {
            Boolean condition = truth(value(node.getCondition()));
            if (condition != null) {
                assume(node.getCondition(), condition);
                scan(condition ? node.getThenStatement() : node.getElseStatement(), null);
                return null;
            }
            List<Map<String, Value>> before = snapshot();
            assume(node.getCondition(), true);
            scan(node.getThenStatement(), null);
            boolean thenAbrupt = abrupt;
            List<Map<String, Value>> thenState = snapshot();
            scopes = before;
            abrupt = false;
            assume(node.getCondition(), false);
            scan(node.getElseStatement(), null);
            boolean elseAbrupt = abrupt;
            if (elseAbrupt && !thenAbrupt) scopes = thenState;
            else if (!thenAbrupt) merge(thenState);
            abrupt = thenAbrupt && elseAbrupt;
            return null;
        }

        void loop(ExpressionTree condition, StatementTree body,
                  List<? extends StatementTree> updates, boolean doWhile) {
            Exits jumps = new Exits(true, scopes.size(), pendingLabel);
            pendingLabel = null;
            exits.add(jumps);
            // Iterate to a fixed point: a sink can consume a value set in a prior iteration.
            for (int pass = 0; ; pass++) {
                List<Map<String, Value>> before = snapshot();
                if (!doWhile && Boolean.FALSE.equals(truth(value(condition)))) break;
                if (!doWhile && condition != null) assume(condition, true);
                scan(body, null);
                boolean backEdge = !abrupt || !jumps.continues.isEmpty();
                if (abrupt) scopes = copyState(before);
                for (List<Map<String, Value>> path : jumps.continues) merge(path);
                abrupt = false;
                if (backEdge) {
                    scan(updates, null);
                    if (doWhile && Boolean.FALSE.equals(truth(value(condition)))) break;
                }
                if (!doWhile || pass > 0) merge(before);
                if (sameState(before)) break;
                // Widen changing constants; the safety/type lattice then converges.
                if (pass > 0) {
                    for (Map<String, Value> scope : scopes) {
                        scope.values().forEach(v -> v.text = null);
                    }
                }
            }
            for (List<Map<String, Value>> path : jumps.breaks) merge(path);
            exits.remove(exits.size() - 1);
            abrupt = false;
        }

        boolean sameState(List<Map<String, Value>> other) {
            for (int i = 0; i < scopes.size(); i++) {
                if (!scopes.get(i).keySet().equals(other.get(i).keySet())) return false;
                for (String name : scopes.get(i).keySet()) {
                    Value a = scopes.get(i).get(name), b = other.get(i).get(name);
                    if (a.unsafe != b.unsafe || a.sql != b.sql || !a.type.equals(b.type)
                            || !Objects.equals(a.text, b.text)) return false;
                }
            }
            return true;
        }

        @Override
        public Void visitWhileLoop(WhileLoopTree node, Void unused) {
            loop(node.getCondition(), node.getStatement(), List.of(), false);
            return null;
        }

        @Override
        public Void visitDoWhileLoop(DoWhileLoopTree node, Void unused) {
            loop(node.getCondition(), node.getStatement(), List.of(), true);
            return null;
        }

        @Override
        public Void visitForLoop(ForLoopTree node, Void unused) {
            scopes.add(new HashMap<>());
            scan(node.getInitializer(), null);
            loop(node.getCondition(), node.getStatement(), node.getUpdate(), false);
            scopes.remove(scopes.size() - 1);
            return null;
        }

        @Override
        public Void visitEnhancedForLoop(EnhancedForLoopTree node, Void unused) {
            value(node.getExpression());
            scopes.add(new HashMap<>());
            scan(node.getVariable(), null);
            loop(null, node.getStatement(), List.of(), false);
            scopes.remove(scopes.size() - 1);
            return null;
        }

        Value value(ExpressionTree expression) {
            if (expression == null) return literal("");
            if (expression instanceof LiteralTree literal) return literal(literal.getValue());
            if (expression instanceof IdentifierTree identifier) return get(identifier.getName().toString());
            if (expression instanceof ParenthesizedTree parens) return value(parens.getExpression());
            if (expression instanceof MemberSelectTree member) {
                Element field = symbol(member);
                if (field instanceof VariableElement variable && variable.getConstantValue() != null) {
                    return literal(variable.getConstantValue());
                }
                if (member.getExpression().toString().equals("this")
                        || member.getExpression().toString().equals(className)) {
                    return scopes.get(0).getOrDefault(member.getIdentifier().toString(), unknown("?"));
                }
                return unknown("?");
            }
            if (expression instanceof AssignmentTree assignment) {
                Value assigned = value(assignment.getExpression());
                assign(assignment.getVariable(), assigned);
                return assigned;
            }
            if (expression instanceof CompoundAssignmentTree assignment) {
                Value assigned = combine(value(assignment.getVariable()), value(assignment.getExpression()));
                assign(assignment.getVariable(), assigned);
                return assigned;
            }
            if (expression instanceof BinaryTree binary) {
                Value left = value(binary.getLeftOperand());
                boolean shortCircuit = binary.getKind() == Tree.Kind.CONDITIONAL_AND
                        || binary.getKind() == Tree.Kind.CONDITIONAL_OR;
                Boolean leftTruth = truth(left);
                boolean and = binary.getKind() == Tree.Kind.CONDITIONAL_AND;
                if (shortCircuit && leftTruth != null && leftTruth != and) return literal(leftTruth);
                List<Map<String, Value>> skipped = shortCircuit ? snapshot() : null;
                Value right = value(binary.getRightOperand());
                if (shortCircuit) {
                    if (leftTruth == null) merge(skipped);
                    Boolean rightTruth = truth(right);
                    if (rightTruth != null && (leftTruth != null || rightTruth != and)) return literal(rightTruth);
                    return unknown("boolean");
                }
                switch (binary.getKind()) {
                    case EQUAL_TO, NOT_EQUAL_TO, LESS_THAN, LESS_THAN_EQUAL,
                            GREATER_THAN, GREATER_THAN_EQUAL, CONDITIONAL_AND, CONDITIONAL_OR:
                        return comparison(binary, left, right);
                    default:
                        break;
                }
                if (binary.getKind() == Tree.Kind.PLUS) {
                    if (NUMERIC_TYPES.contains(left.type) && NUMERIC_TYPES.contains(right.type)) {
                        return unknown("int");
                    }
                    return combine(left, right);
                }
                if (NUMERIC_TYPES.contains(left.type) && NUMERIC_TYPES.contains(right.type)) {
                    return unknown("int");
                }
                return unknown("?");
            }
            if (expression instanceof ConditionalExpressionTree conditional) {
                Boolean condition = truth(value(conditional.getCondition()));
                if (condition != null) {
                    assume(conditional.getCondition(), condition);
                    return value(condition ? conditional.getTrueExpression() : conditional.getFalseExpression());
                }
                List<Map<String, Value>> before = snapshot();
                assume(conditional.getCondition(), true);
                Value left = value(conditional.getTrueExpression()).copy();
                List<Map<String, Value>> leftState = snapshot();
                scopes = before;
                assume(conditional.getCondition(), false);
                Value right = value(conditional.getFalseExpression()).copy();
                merge(leftState);
                return join(left, right);
            }
            if (expression instanceof SwitchExpressionTree selection) {
                return switchValue(selection.getExpression(), selection.getCases());
            }
            if (expression instanceof TypeCastTree cast) {
                Value original = value(cast.getExpression());
                String type = typeName(cast.getType());
                if (type.equals("char") && original.text == null) return unknown("char");
                return NUMERIC_TYPES.contains(type) ? unknown(type) : typed(original, type);
            }
            if (expression instanceof UnaryTree unary) {
                Value operand = value(unary.getExpression());
                if (unary.getKind() == Tree.Kind.LOGICAL_COMPLEMENT) {
                    Boolean condition = truth(operand);
                    return condition == null ? unknown("boolean") : literal(!condition);
                }
                return NUMERIC_TYPES.contains(operand.type) ? unknown(operand.type) : unknown("?");
            }
            if (expression instanceof NewClassTree created) {
                String type = typeName(created.getIdentifier());
                List<Value> args = created.getArguments().stream().map(this::value).toList();
                Value result = unknown(type);
                if (builder(result) || type.equals("String")) {
                    Value initial = args.isEmpty() || NUMERIC_TYPES.contains(args.get(0).type)
                            ? literal("") : args.get(0);
                    if (type.equals("StringJoiner")) {
                        initial = literal("");
                        for (Value arg : args) initial = combine(initial, arg);
                        initial.text = null;
                    }
                    result = new Value(initial.text, initial.unsafe, initial.sql, type);
                }
                if (builder(result)) result.origins = Set.of(++nextObjectId);
                if (NUMERIC_TYPES.contains(type)) result = unknown(type);
                scan(created.getClassBody(), null);
                return result;
            }
            if (expression instanceof MethodInvocationTree call) return call(call);
            if (expression instanceof ArrayAccessTree array) {
                Value container = value(array.getExpression());
                value(array.getIndex());
                String type = container.type.endsWith("[]")
                        ? container.type.substring(0, container.type.length() - 2) : "?";
                return NUMERIC_TYPES.contains(type) ? unknown(type)
                        : new Value(null, container.unsafe, container.sql, type);
            } else if (expression instanceof NewArrayTree array) {
                Value result = literal("");
                if (array.getInitializers() != null) {
                    for (ExpressionTree element : array.getInitializers()) result = combine(result, value(element));
                }
                for (ExpressionTree dimension : array.getDimensions()) value(dimension);
                Value container = new Value(null, result.unsafe, result.sql,
                        array.getType() == null ? "?[]" : typeName(array.getType()) + "[]");
                container.origins = Set.of(++nextObjectId);
                return container;
            } else if (expression instanceof LambdaExpressionTree lambda) {
                List<Map<String, Value>> saved = scopes;
                boolean savedAbrupt = abrupt;
                Value savedReturn = returned;
                List<Exits> savedExits = exits;
                List<List<Map<String, Value>>> savedExceptions = exceptionPaths;
                abrupt = false;
                returned = null;
                exits = new ArrayList<>();
                exceptionPaths = new ArrayList<>();
                scopes = snapshot();
                scopes.add(new HashMap<>());
                scan(lambda.getParameters(), null);
                if (lambda.getBody() instanceof ExpressionTree body) value(body);
                else scan(lambda.getBody(), null);
                scopes = saved;
                abrupt = savedAbrupt;
                returned = savedReturn;
                exits = savedExits;
                exceptionPaths = savedExceptions;
            }
            return unknown("?");
        }

        Value call(MethodInvocationTree call) {
            ExpressionTree select = call.getMethodSelect();
            MemberSelectTree member = select instanceof MemberSelectTree m ? m : null;
            String name = member == null ? select.toString() : member.getIdentifier().toString();
            String owner = member == null ? "" : member.getExpression().toString();
            Value receiver = member == null ? unknown("?") : value(member.getExpression());
            List<Value> args = call.getArguments().stream().map(this::value).toList();
            Element resolved = symbol(select);
            ExecutableElement method = resolved instanceof ExecutableElement executable ? executable : null;
            String apiOwner = method == null ? owner : method.getEnclosingElement().toString();
            boolean stringApi = receiver.type.equals("String")
                    && (method == null || apiOwner.equals("java.lang.String"));
            boolean staticStringApi = apiOwner.equals("java.lang.String") || apiOwner.equals("String");
            MethodTree body = methodDeclarations.get(method);
            if (body != null && body.getBody() != null) return localCall(body, args);
            if (immutableFactory(call)) {
                return new Value(null, args.stream().anyMatch(v -> v.unsafe), false, typeName(call));
            }
            if (method == null && (member == null || owner.equals("this") || owner.equals(className))) {
                List<MethodTree> candidates = methods.getOrDefault(name, List.of()).stream()
                        .filter(m -> m.getParameters().size() == args.size()).toList();
                if (candidates.size() == 1) return localCall(candidates.get(0), args);
            }
            boolean jdbc = method != null && jdbcMethod(method);
            boolean inferredJdbc = method == null && !args.isEmpty() && (JDBC_TYPES.contains(receiver.type)
                    || (receiver.type.equals("?") && (!name.equals("execute") || args.get(0).sql)));
            if (SINKS.contains(name) && !args.isEmpty() && args.get(0).unsafe
                    && (jdbc || inferredJdbc)) {
                report(call, name);
            }
            if (method == null || jdbc) {
                if (name.equals("createStatement")) return unknown("Statement");
                if (name.equals("prepareStatement")) return unknown("PreparedStatement");
                if (name.equals("prepareCall")) return unknown("CallableStatement");
            }
            if (name.equals("getChars") && args.size() == 4 && (builder(receiver) || stringApi)) {
                mutate(args.get(2), join(args.get(2), receiver));
                return unknown("void");
            }
            if (builder(receiver)) {
                if (NUMERIC_TYPES.contains(typeName(call))) return unknown(typeName(call));
                if (name.equals("appendCodePoint") && args.size() == 1) {
                    Value arg = args.get(0);
                    Value appended = combine(receiver, arg.text == null ? unknown("char") : arg);
                    appended.text = null;
                    mutate(receiver, appended);
                    return receiver;
                }
                if (name.equals("append") || name.equals("insert") || name.equals("add")
                        || name.equals("merge") || name.equals("setEmptyValue")) {
                    int start = name.equals("insert") ? 1 : 0;
                    if (args.size() > start) {
                        Value appended = combine(receiver, args.get(start));
                        if (!name.equals("append")) appended.text = null;
                        mutate(receiver, appended);
                    }
                    return receiver;
                }
                if ((name.equals("replace") || name.equals("setCharAt")) && !args.isEmpty()) {
                    Value replaced = combine(receiver, args.get(args.size() - 1));
                    replaced.text = null;
                    mutate(receiver, replaced);
                    return receiver;
                }
                if (name.equals("toString") || name.equals("substring") || name.equals("subSequence")) {
                    return new Value(name.equals("toString") ? receiver.text : null,
                            receiver.unsafe, receiver.sql, "String");
                }
                if (name.equals("charAt")) return new Value(null, receiver.unsafe, false, "char");
                if (name.equals("setLength") && args.size() == 1) {
                    Value resized = "0".equals(args.get(0).text) ? literal("") : receiver.copy();
                    if (!"0".equals(args.get(0).text)) resized.text = null;
                    mutate(receiver, resized);
                } else if (name.equals("reverse")) {
                    Value reversed = receiver.copy();
                    reversed.text = receiver.text == null ? null : new StringBuilder(receiver.text).reverse().toString();
                    reversed.sql |= reversed.text != null && SQL.matcher(reversed.text).find();
                    mutate(receiver, reversed);
                } else if (name.equals("delete") || name.equals("deleteCharAt")) {
                    Value shortened = receiver.copy();
                    shortened.text = null;
                    mutate(receiver, shortened);
                }
                return receiver;
            }
            if (staticStringApi && name.equals("join")) {
                Value joined = literal("");
                for (Value arg : args) joined = combine(joined, arg);
                joined.text = null;
                return joined;
            }
            if (stringApi && (name.equals("toCharArray") || name.equals("getBytes"))) {
                Value array = new Value(null, receiver.unsafe, receiver.sql,
                        name.equals("toCharArray") ? "char[]" : "byte[]");
                array.origins = Set.of(++nextObjectId);
                return array;
            }
            if (stringApi && name.equals("charAt")) return new Value(null, receiver.unsafe, false, "char");
            if (stringApi && Set.of("replace", "replaceAll", "replaceFirst", "substring", "subSequence",
                    "trim", "strip", "stripLeading", "stripTrailing", "toLowerCase", "toUpperCase",
                    "repeat", "indent", "stripIndent", "translateEscapes").contains(name)) {
                Value transformed = receiver.copy();
                if (!name.equals("toLowerCase") && !name.equals("toUpperCase")) {
                    for (Value arg : args) transformed = combine(transformed, arg);
                }
                transformed.text = null;
                return transformed;
            }
            if (name.equals("concat") && args.size() == 1) return combine(receiver, args.get(0));
            if ((name.equals("format") && staticStringApi)
                    || name.equals("formatted")) {
                int index = !args.isEmpty() && (args.get(0).type.equals("Locale")
                        || typeName(call.getArguments().get(0)).equals("Locale")) ? 1 : 0;
                if (name.equals("formatted")) return format(receiver, args);
                if (index < args.size()) return format(args.get(index), args.subList(index + 1, args.size()));
            }
            String ownerType = simpleType(owner);
            if (NUMERIC_TYPES.contains(ownerType)
                    && (name.startsWith("parse") || name.equals("valueOf"))) return unknown(ownerType);
            if (name.equals("toString") || (name.equals("valueOf")
                    && staticStringApi)) {
                Value original = args.isEmpty() ? receiver : args.get(0);
                return new Value(original.text, original.unsafe, original.sql, "String");
            }
            // Unknown helpers may mutate a supplied buffer/array.
            for (Value arg : args) {
                if (!arg.origins.isEmpty()) mutate(arg, new Value(null, true, arg.sql, arg.type));
            }
            // Arbitrary escaping/replace helpers do not establish SQL safety.
            Value result = unknown(method == null ? "?" : typeName(call));
            result.sql = receiver.sql || args.stream().anyMatch(v -> v.sql);
            return result;
        }

        Value localCall(MethodTree method, List<Value> args) {
            String type = method.getReturnType() == null ? "?" : typeName(method.getReturnType());
            if (activeMethods.contains(method) || method.getBody() == null) return unknown(type);
            ClassTree owner = methodClasses.get(method);
            if (owner != null && !classFields.containsKey(owner)) scan(owner, null);
            List<Map<String, Value>> saved = scopes;
            ClassTree savedClassTree = currentClass;
            String savedClassName = className;
            Map<String, List<MethodTree>> savedMethods = methods;
            boolean savedAbrupt = abrupt;
            abrupt = false;
            List<Exits> savedExits = exits;
            exits = new ArrayList<>();
            List<List<Map<String, Value>>> savedExceptions = exceptionPaths;
            exceptionPaths = new ArrayList<>();
            Value savedReturn = returned;
            scopes = new ArrayList<>();
            scopes.add(new HashMap<>(owner == null || owner == currentClass
                    ? saved.get(0) : classFields.get(owner)));
            scopes.add(new HashMap<>());
            currentClass = owner;
            className = owner == null ? "" : owner.getSimpleName().toString();
            methods = methodsOf(owner);
            Element declaration = symbol(method);
            boolean varargs = declaration instanceof ExecutableElement executable && executable.isVarArgs();
            for (int i = 0; i < method.getParameters().size(); i++) {
                VariableTree parameter = method.getParameters().get(i);
                String parameterType = typeName(parameter.getType());
                Value argument = i < args.size() ? args.get(i) : unknown(parameterType);
                if (varargs && i == method.getParameters().size() - 1
                        && (args.size() != method.getParameters().size() || !argument.type.endsWith("[]"))) {
                    argument = new Value(null, false, false, parameterType);
                    argument.origins = Set.of(++nextObjectId);
                    for (int j = i; j < args.size(); j++) {
                        argument.unsafe |= args.get(j).unsafe;
                        argument.sql |= args.get(j).sql;
                    }
                }
                scopes.get(1).put(parameter.getName().toString(),
                        typed(argument, parameterType));
            }
            returned = null;
            activeMethods.add(method);
            scan(method.getBody(), null);
            Value result = returned == null ? unknown(type) : typed(returned, type);
            activeMethods.remove(method);
            scopes = saved;
            exceptionPaths = savedExceptions;
            returned = savedReturn;
            abrupt = savedAbrupt;
            exits = savedExits;
            currentClass = savedClassTree;
            className = savedClassName;
            methods = savedMethods;
            return result;
        }

        Value format(Value template, List<Value> args) {
            if (template.unsafe) return new Value(null, true, template.sql, "String");
            if (template.text == null) {
                return new Value(null, args.stream().anyMatch(v -> v.unsafe), template.sql, "String");
            }
            Value result = template.copy();
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
                Value arg = args.get(Math.min(index, args.size() - 1));
                if (conversions.group(3) == null && conversion == 's') result = combine(result, arg);
                if (conversions.group(3) == null && conversion == 'c' && arg.text == null) result.unsafe = true;
            }
            result.text = null;
            return result;
        }

        void report(MethodInvocationTree call, String name) {
            int position = (int) positions.getEndPosition(unit, call.getMethodSelect()) - name.length() - offset;
            if (position < 0 || position >= source.length()) return;
            int line = 1;
            for (int i = 0; i < position; i++) if (source.charAt(i) == '\n') line++;
            int start = source.lastIndexOf('\n', position) + 1;
            int end = source.indexOf('\n', position);
            if (end < 0) end = source.length();
            findings.put(position, new Finding("CWE-89", fileName, line,
                    "SQL execution may use dynamically constructed query data. "
                            + "Verify the data flow and use parameterized queries.",
                    source.substring(start, end).strip()));
        }
    }
}
