package edu.fiu.capstone.skeleton;

import com.sun.source.tree.*;
import static edu.fiu.capstone.skeleton.FlowValue.*;
import com.sun.source.util.SourcePositions;
import com.sun.source.util.TreeScanner;
import com.sun.source.util.TreePath;
import com.sun.source.util.TreePathScanner;
import com.sun.source.util.Trees;
import java.io.IOException;
import java.util.*;
import javax.lang.model.element.Element;
import javax.lang.model.element.ExecutableElement;
import javax.lang.model.element.TypeElement;
import javax.lang.model.element.VariableElement;
import javax.lang.model.type.TypeKind;
import javax.lang.model.type.TypeMirror;
import javax.lang.model.util.Types;

/**
 * Shared SQL and command-injection data-flow analysis using the JDK parser (JDK 17+).
 * Unknown strings are untrusted; constants, finite literal choices and numeric
 * values are safe. Passing a value as a bound parameter is not a SQL sink.
 * This is conservative static analysis, not proof of exploitability: external
 * helper contracts without available source, cross-object state and arbitrary
 * framework APIs are outside its model. Input is parsed and type-checked;
 * no application bytecode is generated or executed.
 */
final class JavaSecurityAnalyzer {
    enum Check { SQL_INJECTION, COMMAND_INJECTION }
    private static final Set<String> SINKS = Set.of(
            "executeQuery", "executeUpdate", "executeLargeUpdate", "execute",
            "addBatch", "prepareStatement", "prepareCall");
    private static final Set<String> JDBC_TYPES = Set.of(
            "Statement", "PreparedStatement", "CallableStatement", "Connection");
    private static final Set<String> SPRING_SQL = Set.of(
            "query", "queryForObject", "queryForList", "queryForMap", "queryForRowSet", "update", "batchUpdate", "execute");
    private static final Set<String> ORM_SQL = Set.of("createQuery", "createNativeQuery", "createSQLQuery");


    static List<Finding> analyze(String fileName, String sourceCode, Check check) {
        return analyze(DetectionRequest.source(fileName, sourceCode), Set.of(check)).findings();
    }

    static DetectionResult analyze(DetectionRequest request, Set<Check> checks) {
        try (JavaSources program = JavaSources.parse(request)) {
            List<Finding> findings = new ArrayList<>();
            Set<DetectionDiagnostic> diagnostics = new LinkedHashSet<>(program.diagnostics);
            for (Check check : checks.stream().sorted().toList()) {
                Analyzer analyzer = new Analyzer(program, check);
                for (var unit : program.units) {
                    var source = program.sources.get(unit);
                    if (request.entryFiles().contains(source.name())) {
                        analyzer.useSource(unit);
                        try { analyzer.scan(unit, null); }
                        catch (AnalysisLimit limit) {
                            analyzer.diagnostics.add(new DetectionDiagnostic(source.name(), 0,
                                    DetectionDiagnostic.Severity.ERROR, limit.getMessage()));
                            break;
                        }
                    }
                }
                findings.addAll(analyzer.findings.values());
                diagnostics.addAll(analyzer.diagnostics);
            }
            var ordered = findings.stream().sorted(Comparator.comparing(Finding::file)
                    .thenComparingInt(Finding::line).thenComparing(Finding::cwe)).toList();
            return new DetectionResult(ordered, new ArrayList<>(diagnostics));
        } catch (IOException e) {
            throw new IllegalStateException("Could not read Java source", e);
        }
    }

    private static final class AnalysisLimit extends RuntimeException {
        private static final long serialVersionUID = 1L;
        AnalysisLimit(String message) { super(message); }
    }

    private static final class Analyzer extends TreeScanner<Void, Void> implements LibraryModels.Context {
        final LibraryModels libraries = new LibraryModels(this);
        String fileName;
        String source;
        int offset;
        CompilationUnitTree unit;
        final JavaSources program;
        final Map<Tree, TreePath> paths = new IdentityHashMap<>();
        final Set<DetectionDiagnostic> diagnostics = new LinkedHashSet<>();
        final SourcePositions positions;
        final Trees trees;
        final Types types;
        final Check check;
        final Map<Element, MethodTree> methodDeclarations = new HashMap<>();
        final Map<MethodTree, ClassTree> methodClasses = new IdentityHashMap<>();
        final Map<Element, ClassTree> classDeclarations = new HashMap<>();
        final Map<ClassTree, Map<String, FlowValue>> classFields = new IdentityHashMap<>();
        final Map<ClassTree, Map<String, FlowValue>> initialFields = new IdentityHashMap<>();
        final List<TypeMirror> jdbcTypes = new ArrayList<>();
        ClassTree currentClass;
        final SortedMap<String, Finding> findings = new TreeMap<>();
        List<Map<String, FlowValue>> scopes = new ArrayList<>();
        List<List<Map<String, FlowValue>>> exceptionPaths = new ArrayList<>();
        Map<String, List<MethodTree>> methods = new HashMap<>();
        final Set<MethodTree> activeMethods = new HashSet<>();
        FlowValue returned;
        FlowValue yielded;
        int nextObjectId;
        String className = "";
        boolean abrupt;
        List<Exits> exits = new ArrayList<>();
        String pendingLabel;
        FlowValue thisValue;
        int steps;
        int expressionDepth;

        @Override public Void scan(Tree tree, Void unused) {
            if (tree == null) return null;
            if (++steps > 200_000) throw new AnalysisLimit("Analysis work limit reached; results are incomplete");
            return super.scan(tree, unused);
        }

        /** Saves interpreter state when entering a class, method or callback. */
        private final class Frame implements AutoCloseable {
            final CompilationUnitTree savedUnit = unit;
            final List<Map<String, FlowValue>> savedScopes = scopes;
            final List<List<Map<String, FlowValue>>> savedExceptions = exceptionPaths;
            final List<Exits> savedExits = exits;
            final boolean savedAbrupt = abrupt;
            final FlowValue savedReturn = returned, savedYield = yielded, savedThis = thisValue;
            final ClassTree savedClass = currentClass;
            final String savedName = className, savedLabel = pendingLabel;
            final Map<String, List<MethodTree>> savedMethods = methods;

            @Override public void close() {
                useSource(savedUnit);
                scopes = savedScopes;
                exceptionPaths = savedExceptions;
                exits = savedExits;
                abrupt = savedAbrupt;
                returned = savedReturn;
                yielded = savedYield;
                thisValue = savedThis;
                currentClass = savedClass;
                className = savedName;
                pendingLabel = savedLabel;
                methods = savedMethods;
            }
        }

        void enterClass(ClassTree owner, Map<String, FlowValue> fields) {
            if (owner != null) useSource(owner);
            currentClass = owner;
            className = owner == null ? "" : owner.getSimpleName().toString();
            methods = methodsOf(owner);
            scopes = new ArrayList<>();
            scopes.add(fields);
            exceptionPaths = new ArrayList<>();
            exits = new ArrayList<>();
            abrupt = false;
            returned = null;
            yielded = null;
            thisValue = null;
            pendingLabel = null;
        }

        void initializeClass(ClassTree owner) {
            if (owner == null || classFields.containsKey(owner)) return;
            Frame frame = new Frame();
            try {
                Map<String, FlowValue> fields = new HashMap<>();
                classFields.put(owner, fields);
                enterClass(owner, fields);
                for (Tree member : owner.getMembers()) if (member instanceof VariableTree) scan(member, null);
                for (Tree member : owner.getMembers()) if (member instanceof BlockTree) scan(member, null);
                initialFields.put(owner, snapshot().get(0));
            } finally { frame.close(); }
        }

        private static final class Exits {
            final boolean loop;
            final int depth;
            final String label;
            final List<List<Map<String, FlowValue>>> breaks = new ArrayList<>();
            final List<List<Map<String, FlowValue>>> continues = new ArrayList<>();

            Exits(boolean loop, int depth, String label) {
                this.loop = loop;
                this.depth = depth;
                this.label = label;
            }
        }

        Analyzer(JavaSources program, Check check) {
            this.program = program;
            this.trees = program.trees;
            this.positions = trees.getSourcePositions();
            this.types = program.task.getTypes();
            this.check = check;
            useSource(program.units.get(0));
            for (String name : JDBC_TYPES) {
                TypeElement type = program.task.getElements().getTypeElement("java.sql." + name);
                if (type != null) jdbcTypes.add(types.erasure(type.asType()));
            }
            var index = new TreePathScanner<Void, Void>() {
                @Override public Void scan(Tree tree, Void unused) {
                    if (tree == null) return null;
                    TreePath path = tree instanceof CompilationUnitTree compilation ? new TreePath(compilation)
                            : new TreePath(getCurrentPath(), tree);
                    paths.put(tree, path);
                    return super.scan(tree, unused);
                }

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
            };
            for (var parsed : program.units) index.scan(parsed, null);
            scopes.add(new HashMap<>());
        }

        void useSource(CompilationUnitTree sourceUnit) {
            var input = program.sources.get(sourceUnit);
            unit = sourceUnit;
            fileName = input.name();
            source = input.text();
            offset = input.offset();
        }

        void useSource(Tree tree) {
            TreePath path = paths.get(tree);
            if (path != null) useSource(path.getCompilationUnit());
        }

        public void note(Tree tree, String message) {
            TreePath path = paths.get(tree);
            if (path == null) return;
            var input = program.sources.get(path.getCompilationUnit());
            long position = positions.getStartPosition(input.unit(), tree);
            long line = position < 0 ? 0 : input.unit().getLineMap().getLineNumber(position);
            if (input.offset() > 0 && position >= 0) {
                line -= input.unit().getLineMap().getLineNumber(input.offset()) - 1;
            }
            diagnostics.add(new DetectionDiagnostic(input.name(), line, DetectionDiagnostic.Severity.WARNING, message));
        }

        public Element symbol(Tree node) {
            TreePath path = paths.get(node);
            return path == null ? null : trees.getElement(path);
        }

        public String typeName(Tree node) {
            TreePath path = paths.get(node);
            TypeMirror type = path == null ? null : trees.getTypeMirror(path);
            if (type == null || type.getKind() == TypeKind.ERROR || type.getKind() == TypeKind.NONE) {
                return node == null ? "?" : simpleType(node.toString());
            }
            Element declaration = types.asElement(type);
            if (classDeclarations.containsKey(declaration)) return "source:" + type;
            if (declaration instanceof TypeElement declared) return simpleType(declared.getQualifiedName().toString());
            return simpleType(type.toString());
        }

        Boolean truth(FlowValue value) {
            if (value.type.equals("boolean") || value.type.equals("Boolean")) {
                if ("true".equals(value.text)) return true;
                if ("false".equals(value.text)) return false;
            }
            return null;
        }

        FlowValue comparison(BinaryTree expression, FlowValue left, FlowValue right) {
            if (expression.getKind() == Tree.Kind.EQUAL_TO || expression.getKind() == Tree.Kind.NOT_EQUAL_TO) {
                boolean known = left.definitelyNull && right.definitelyNull
                        || left.definitelyNull && nonNull(right) || right.definitelyNull && nonNull(left);
                if (known) return literal(expression.getKind() == Tree.Kind.EQUAL_TO
                        ? left.definitelyNull && right.definitelyNull : !(left.definitelyNull && right.definitelyNull));
            }
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

        boolean nonNull(FlowValue value) {
            return value.knownNonNull || value.text != null || value.members != null || value.entries != null || value.elements != null;
        }

        FlowValue arithmetic(Tree.Kind operation, FlowValue left, FlowValue right) {
            if (left.text == null || right.text == null || !NUMERIC_TYPES.contains(left.type)
                    || !NUMERIC_TYPES.contains(right.type)) return unknown("int");
            try {
                boolean decimal = Set.of("float", "Float", "double", "Double").contains(left.type)
                        || Set.of("float", "Float", "double", "Double").contains(right.type);
                if (decimal) {
                    boolean doublePrecision = left.type.equals("double") || left.type.equals("Double")
                            || right.type.equals("double") || right.type.equals("Double");
                    if (!doublePrecision) {
                        float a = Float.parseFloat(left.text), b = Float.parseFloat(right.text);
                        float result = switch (operation) {
                            case PLUS -> a + b; case MINUS -> a - b; case MULTIPLY -> a * b;
                            case DIVIDE -> a / b; case REMAINDER -> a % b;
                            default -> throw new IllegalArgumentException();
                        };
                        return literal(result);
                    }
                    double a = Double.parseDouble(left.text), b = Double.parseDouble(right.text);
                    double result = switch (operation) {
                        case PLUS -> a + b;
                        case MINUS -> a - b;
                        case MULTIPLY -> a * b;
                        case DIVIDE -> a / b;
                        case REMAINDER -> a % b;
                        default -> throw new IllegalArgumentException();
                    };
                    return literal(result);
                }
                long a = Long.parseLong(left.text), b = Long.parseLong(right.text);
                boolean wide = operation == Tree.Kind.LEFT_SHIFT || operation == Tree.Kind.RIGHT_SHIFT
                        || operation == Tree.Kind.UNSIGNED_RIGHT_SHIFT
                        ? left.type.equals("long") || left.type.equals("Long")
                        : left.type.equals("long") || left.type.equals("Long") || right.type.equals("long") || right.type.equals("Long");
                long result;
                if (wide) {
                    result = switch (operation) {
                        case PLUS -> a + b; case MINUS -> a - b; case MULTIPLY -> a * b;
                        case DIVIDE -> a / b; case REMAINDER -> a % b;
                        case AND -> a & b; case OR -> a | b; case XOR -> a ^ b;
                        case LEFT_SHIFT -> a << b; case RIGHT_SHIFT -> a >> b; case UNSIGNED_RIGHT_SHIFT -> a >>> b;
                        default -> throw new IllegalArgumentException();
                    };
                    return literal(result);
                }
                int x = (int) a, y = (int) b;
                int result32 = switch (operation) {
                    case PLUS -> x + y; case MINUS -> x - y; case MULTIPLY -> x * y;
                    case DIVIDE -> x / y; case REMAINDER -> x % y;
                    case AND -> x & y; case OR -> x | y; case XOR -> x ^ y;
                    case LEFT_SHIFT -> x << y; case RIGHT_SHIFT -> x >> y; case UNSIGNED_RIGHT_SHIFT -> x >>> y;
                    default -> throw new IllegalArgumentException();
                };
                return literal(result32);
            } catch (ArithmeticException | IllegalArgumentException e) {
                return unknown("int");
            }
        }

        FlowValue known(ExpressionTree expression) {
            if (expression instanceof ParenthesizedTree parens) return known(parens.getExpression());
            if (expression instanceof LiteralTree constant) return literal(constant.getValue());
            if (expression instanceof IdentifierTree identifier) return get(identifier.getName().toString());
            Element element = symbol(expression);
            if (element instanceof VariableElement variable && variable.getConstantValue() != null) {
                return literal(variable.getConstantValue());
            }
            if (expression instanceof MethodInvocationTree call && immutableFactory(call)) {
                List<FlowValue> items = call.getArguments().stream().map(this::known).toList();
                return check == Check.COMMAND_INJECTION ? vector(items, typeName(call))
                        : new FlowValue(null, items.stream().anyMatch(v -> v.unsafe), false, typeName(call));
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
                    List<Map<String, FlowValue>> before = snapshot();
                    assume(binary.getLeftOperand(), holds);
                    List<Map<String, FlowValue>> first = snapshot();
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
                FlowValue receiver = known(member.getExpression());
                FlowValue argument = known(call.getArguments().get(0));
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
                    FlowValue allowed = new FlowValue(null, false, false, "String");
                    if (receiver.elements != null) {
                        Set<String> choices = new HashSet<>();
                        receiver.elements.forEach(v -> choices.addAll(v.choices));
                        allowed.choices = choices;
                    }
                    assign(call.getArguments().get(0), allowed);
                }
            }
        }

        void restrict(ExpressionTree target, ExpressionTree constant, boolean ignoreCase) {
            FlowValue allowed = known(constant);
            if (!allowed.type.equals("String") || allowed.text == null || allowed.unsafe) return;
            if (target instanceof IdentifierTree || target instanceof MemberSelectTree) {
                assign(target, new FlowValue(ignoreCase ? null : allowed.text, false, allowed.sql, "String"));
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

        FlowValue get(String name) {
            for (int i = scopes.size() - 1; i >= 0; i--) {
                FlowValue value = scopes.get(i).get(name);
                if (value != null) return value;
            }
            return unknown("?");
        }

        void assign(ExpressionTree target, FlowValue value) {
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
            } else if (target instanceof MemberSelectTree member) {
                FlowValue object = value(member.getExpression());
                if (object.members != null) {
                    FlowValue changed = object.copy();
                    changed.members.put(member.getIdentifier().toString(), value);
                    mutate(object, changed);
                } else {
                    note(target, "Field assignment on an unresolved object; alias effects are unknown");
                }
            } else if (target instanceof ArrayAccessTree array) {
                FlowValue container = value(array.getExpression());
                FlowValue changed = join(container, value);
                Integer index = index(known(array.getIndex()));
                if (container.elements != null && index != null && index >= 0 && index < container.elements.size()) {
                    changed.elements = new ArrayList<>(container.elements);
                    changed.elements.set(index, value);
                }
                mutate(container, changed);
            }
        }

        public void mutate(FlowValue receiver, FlowValue replacement) {
            receiver.set(replacement);
            Set<FlowValue> visited = Collections.newSetFromMap(new IdentityHashMap<>());
            Deque<FlowValue> pending = new ArrayDeque<>();
            scopes.forEach(scope -> pending.addAll(scope.values()));
            while (!pending.isEmpty()) {
                FlowValue alias = pending.removeFirst();
                if (!visited.add(alias)) continue;
                if (alias != receiver && !Collections.disjoint(alias.origins, receiver.origins)) {
                    alias.set(alias.origins.equals(receiver.origins) && alias.origins.size() == 1
                            ? replacement : join(alias, replacement));
                }
                if (alias.elements != null) pending.addAll(alias.elements);
                if (alias.command != null) pending.add(alias.command);
                if (alias.environment != null) pending.add(alias.environment);
                if (alias.entries != null) pending.addAll(alias.entries.values());
                if (alias.members != null) pending.addAll(alias.members.values());
            }
        }

        List<Map<String, FlowValue>> snapshot() {
            return copyState(scopes);
        }

        List<Map<String, FlowValue>> copyState(List<Map<String, FlowValue>> state) {
            IdentityHashMap<FlowValue, FlowValue> copies = new IdentityHashMap<>();
            List<Map<String, FlowValue>> result = new ArrayList<>();
            for (Map<String, FlowValue> scope : state) {
                Map<String, FlowValue> copy = new HashMap<>();
                scope.forEach((name, value) -> copy.put(name, copyValue(value, copies)));
                result.add(copy);
            }
            return result;
        }

        FlowValue copyValue(FlowValue value, IdentityHashMap<FlowValue, FlowValue> copies) {
            FlowValue existing = copies.get(value);
            if (existing != null) return existing;
            FlowValue result = value.copy();
            copies.put(value, result);
            if (value.elements != null) {
                result.elements = new ArrayList<>();
                for (FlowValue element : value.elements) result.elements.add(copyValue(element, copies));
            }
            if (value.command != null) result.command = copyValue(value.command, copies);
            if (value.environment != null) result.environment = copyValue(value.environment, copies);
            if (value.entries != null) {
                result.entries = new HashMap<>();
                value.entries.forEach((key, item) -> result.entries.put(key, copyValue(item, copies)));
            }
            if (value.members != null) {
                result.members = new HashMap<>();
                value.members.forEach((key, item) -> result.members.put(key, copyValue(item, copies)));
            }
            return result;
        }

        void merge(List<Map<String, FlowValue>> other) {
            mergeInto(scopes, other);
        }

        void mergeInto(List<Map<String, FlowValue>> state, List<Map<String, FlowValue>> other) {
            // Keep definite aliases identical; object origins also retain possible aliases.
            Map<List<FlowValue>, FlowValue> joined = new HashMap<>();
            for (int i = 0; i < Math.min(state.size(), other.size()); i++) {
                Map<String, FlowValue> alternate = other.get(i);
                state.get(i).replaceAll((name, value) -> {
                    FlowValue right = alternate.getOrDefault(name, unknown(value.type));
                    return joined.computeIfAbsent(List.of(value, right),
                            pair -> join(value, right));
                });
            }
        }

        @Override
        public Void visitClass(ClassTree node, Void unused) {
            Frame frame = new Frame();
            try {
                initializeClass(node);
                enterClass(node, classFields.get(node));
                List<Map<String, FlowValue>> before;
                do {
                    before = snapshot();
                    for (Tree member : node.getMembers()) if (member instanceof MethodTree) scan(member, null);
                } while (!sameState(before));
                for (Tree member : node.getMembers()) if (member instanceof ClassTree) scan(member, null);
                return null;
            } finally { frame.close(); }
        }

        @Override
        public Void visitMethod(MethodTree node, Void unused) {
            Frame frame = new Frame();
            try {
                scopes = snapshot();
                abrupt = false;
                returned = null;
                if (!node.getModifiers().getFlags().contains(javax.lang.model.element.Modifier.STATIC)) {
                    thisValue = unknown("source:" + symbol(currentClass));
                    thisValue.members = scopes.get(0);
                    thisValue.origins = Set.of(++nextObjectId);
                }
                activeMethods.add(node);
                scopes.add(new HashMap<>());
                for (VariableTree parameter : node.getParameters()) scan(parameter, null);
                scan(node.getBody(), null);
                mergeInto(frame.savedScopes, scopes.subList(0, 1));
                return null;
            } finally {
                activeMethods.remove(node);
                frame.close();
            }
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
            FlowValue initial = node.getInitializer() == null
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
            FlowValue result = value(node.getExpression());
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
                for (List<Map<String, FlowValue>> path : jumps.breaks) merge(path);
                if (!jumps.breaks.isEmpty()) abrupt = false;
                exits.remove(exits.size() - 1);
            }
            pendingLabel = savedLabel;
            return null;
        }

        void captureException() {
            if (!exceptionPaths.isEmpty()) {
                List<Map<String, FlowValue>> current = snapshot();
                for (List<Map<String, FlowValue>> path : exceptionPaths) mergeInto(path, current);
            }
        }

        @Override
        public Void visitTry(TryTree node, Void unused) {
            scopes.add(new HashMap<>());
            List<Map<String, FlowValue>> exceptional = snapshot();
            exceptionPaths.add(exceptional);
            scan(node.getResources(), null);
            scan(node.getBlock(), null);
            captureException();
            exceptionPaths.remove(exceptionPaths.size() - 1);
            List<Map<String, FlowValue>> exits = snapshot();
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
            FlowValue result = value(node.getValue());
            yielded = yielded == null ? result.copy() : join(yielded, result);
            return null;
        }

        FlowValue switchValue(ExpressionTree selector, List<? extends CaseTree> cases) {
            FlowValue selected = value(selector);
            boolean exact = selected.text != null && !selected.unsafe;
            int selectedCase = -1, defaultCase = -1;
            if (exact) {
                for (int i = 0; i < cases.size(); i++) {
                    if (cases.get(i).getExpressions().isEmpty()) defaultCase = i;
                    for (ExpressionTree label : cases.get(i).getExpressions()) {
                        FlowValue constant = known(label);
                        if (selected.text.equals(constant.text)) selectedCase = i;
                    }
                }
                if (selectedCase < 0) selectedCase = defaultCase;
            }
            FlowValue savedYield = yielded;
            yielded = null;
            scopes.add(new HashMap<>());
            Exits jumps = new Exits(false, scopes.size(), pendingLabel);
            pendingLabel = null;
            exits.add(jumps);
            List<Map<String, FlowValue>> before = snapshot(), exits = null, fallthrough = null;
            boolean hasDefault = false;
            for (int caseIndex = 0; caseIndex < cases.size(); caseIndex++) {
                CaseTree branch = cases.get(caseIndex);
                hasDefault |= branch.getExpressions().isEmpty();
                if (exact && (selectedCase < 0 || caseIndex < selectedCase)) continue;
                abrupt = false;
                scopes = exact && fallthrough != null ? copyState(fallthrough) : copyState(before);
                if (!exact && fallthrough != null) merge(fallthrough);
                if (branch.getBody() instanceof ExpressionTree expression) {
                    FlowValue result = value(expression);
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
                if (exact && fallthrough == null) break;
            }
            if (exits != null) scopes = exits;
            if (!hasDefault && (!exact || selectedCase < 0)) merge(before);
            for (List<Map<String, FlowValue>> path : jumps.breaks) merge(path);
            this.exits.remove(this.exits.size() - 1);
            abrupt = false;
            scopes.remove(scopes.size() - 1);
            FlowValue result = yielded == null ? unknown("?") : yielded;
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
            List<Map<String, FlowValue>> before = snapshot();
            assume(node.getCondition(), true);
            scan(node.getThenStatement(), null);
            boolean thenAbrupt = abrupt;
            List<Map<String, FlowValue>> thenState = snapshot();
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
                List<Map<String, FlowValue>> before = snapshot();
                if (!doWhile && Boolean.FALSE.equals(truth(value(condition)))) break;
                if (!doWhile && condition != null) assume(condition, true);
                scan(body, null);
                boolean backEdge = !abrupt || !jumps.continues.isEmpty();
                if (abrupt) scopes = copyState(before);
                for (List<Map<String, FlowValue>> path : jumps.continues) merge(path);
                abrupt = false;
                if (backEdge) {
                    scan(updates, null);
                    if (doWhile && Boolean.FALSE.equals(truth(value(condition)))) break;
                }
                if (!doWhile || pass > 0) merge(before);
                if (sameState(before)) break;
                // Widen changing constants; the safety/type lattice then converges.
                if (pass > 0) {
                    for (Map<String, FlowValue> scope : scopes) {
                        scope.values().forEach(v -> v.text = null);
                    }
                }
            }
            for (List<Map<String, FlowValue>> path : jumps.breaks) merge(path);
            exits.remove(exits.size() - 1);
            abrupt = false;
        }

        boolean sameState(List<Map<String, FlowValue>> other) {
            for (int i = 0; i < scopes.size(); i++) {
                if (!scopes.get(i).keySet().equals(other.get(i).keySet())) return false;
                for (String name : scopes.get(i).keySet()) {
                    FlowValue a = scopes.get(i).get(name), b = other.get(i).get(name);
                    if (!sameValue(a, b, new HashSet<>())) return false;
                }
            }
            return true;
        }

        boolean sameValue(FlowValue a, FlowValue b, Set<List<FlowValue>> seen) {
            if (!seen.add(List.of(a, b))) return true;
            if (a.unsafe != b.unsafe || a.sql != b.sql || !a.type.equals(b.type)
                    || !Objects.equals(a.text, b.text) || !a.choices.equals(b.choices)) return false;
            if ((a.command == null) != (b.command == null) || (a.environment == null) != (b.environment == null)
                    || (a.elements == null) != (b.elements == null)) return false;
            if (a.command != null && !sameValue(a.command, b.command, seen)) return false;
            if (a.environment != null && !sameValue(a.environment, b.environment, seen)) return false;
            if (a.elements != null) {
                if (a.elements.size() != b.elements.size()) return false;
                for (int i = 0; i < a.elements.size(); i++) if (!sameValue(a.elements.get(i), b.elements.get(i), seen)) return false;
            }
            if (!a.runtimeTypes.equals(b.runtimeTypes)) return false;
            if (a.definitelyNull != b.definitelyNull || a.immutable != b.immutable || a.fixedSize != b.fixedSize) return false;
            if (a.knownNonNull != b.knownNonNull) return false;
            if (a.inputDependent != b.inputDependent) return false;
            if (!a.prefix.equals(b.prefix)) return false;
            if (!sameFields(a.entries, b.entries, seen) || !sameFields(a.members, b.members, seen)) return false;
            return true;
        }

        boolean sameFields(Map<String, FlowValue> a, Map<String, FlowValue> b, Set<List<FlowValue>> seen) {
            if (a == null || b == null) return a == b;
            if (!a.keySet().equals(b.keySet())) return false;
            return a.keySet().stream().allMatch(key -> sameValue(a.get(key), b.get(key), seen));
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

        FlowValue value(ExpressionTree expression) {
            if (++steps > 200_000) throw new AnalysisLimit("Analysis work limit reached; results are incomplete");
            if (++expressionDepth > 256) {
                expressionDepth--;
                throw new AnalysisLimit("Expression nesting limit reached; results are incomplete");
            }
            try { return evaluate(expression); }
            finally { expressionDepth--; }
        }

        FlowValue evaluate(ExpressionTree expression) {
            if (expression == null) return literal("");
            if (expression instanceof LiteralTree literal) return literal(literal.getValue());
            if (expression instanceof IdentifierTree identifier) {
                return identifier.getName().contentEquals("this") && thisValue != null ? thisValue : get(identifier.getName().toString());
            }
            if (expression instanceof ParenthesizedTree parens) return value(parens.getExpression());
            if (expression instanceof MemberSelectTree member) {
                if (member.getIdentifier().contentEquals("class") && symbol(member.getExpression()) instanceof TypeElement type) {
                    FlowValue handle = new FlowValue(null, false, false, "Class");
                    handle.runtimeTypes = Set.of("source:" + type.getQualifiedName());
                    return handle;
                }
                Element field = symbol(member);
                if (field instanceof VariableElement variable && variable.getConstantValue() != null) {
                    return literal(variable.getConstantValue());
                }
                if (member.getExpression().toString().equals("this")
                        || member.getExpression().toString().equals(className)) {
                    return scopes.get(0).getOrDefault(member.getIdentifier().toString(), unknown("?"));
                }
                FlowValue object = value(member.getExpression());
                if (object.members != null) return object.members.getOrDefault(member.getIdentifier().toString(), unknown(typeName(member)));
                return unknown("?");
            }
            if (expression instanceof AssignmentTree assignment) {
                FlowValue assigned = value(assignment.getExpression());
                assign(assignment.getVariable(), assigned);
                return assigned;
            }
            if (expression instanceof CompoundAssignmentTree assignment) {
                FlowValue assigned = combine(value(assignment.getVariable()), value(assignment.getExpression()));
                assign(assignment.getVariable(), assigned);
                return assigned;
            }
            if (expression instanceof BinaryTree binary) {
                FlowValue left = value(binary.getLeftOperand());
                boolean shortCircuit = binary.getKind() == Tree.Kind.CONDITIONAL_AND
                        || binary.getKind() == Tree.Kind.CONDITIONAL_OR;
                Boolean leftTruth = truth(left);
                boolean and = binary.getKind() == Tree.Kind.CONDITIONAL_AND;
                if (shortCircuit && leftTruth != null && leftTruth != and) return literal(leftTruth);
                List<Map<String, FlowValue>> skipped = shortCircuit ? snapshot() : null;
                FlowValue right = value(binary.getRightOperand());
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
                        return arithmetic(binary.getKind(), left, right);
                    }
                    return combine(left, right);
                }
                if (NUMERIC_TYPES.contains(left.type) && NUMERIC_TYPES.contains(right.type)) {
                    return arithmetic(binary.getKind(), left, right);
                }
                return unknown("?");
            }
            if (expression instanceof ConditionalExpressionTree conditional) {
                Boolean condition = truth(value(conditional.getCondition()));
                if (condition != null) {
                    assume(conditional.getCondition(), condition);
                    return value(condition ? conditional.getTrueExpression() : conditional.getFalseExpression());
                }
                List<Map<String, FlowValue>> before = snapshot();
                assume(conditional.getCondition(), true);
                FlowValue left = value(conditional.getTrueExpression()).copy();
                List<Map<String, FlowValue>> leftState = snapshot();
                scopes = before;
                assume(conditional.getCondition(), false);
                FlowValue right = value(conditional.getFalseExpression()).copy();
                merge(leftState);
                return join(left, right);
            }
            if (expression instanceof SwitchExpressionTree selection) {
                return switchValue(selection.getExpression(), selection.getCases());
            }
            if (expression instanceof TypeCastTree cast) {
                FlowValue original = value(cast.getExpression());
                String type = typeName(cast.getType());
                if (type.equals("char") && original.text == null) return unknown("char");
                return NUMERIC_TYPES.contains(type) ? unknown(type) : typed(original, type);
            }
            if (expression instanceof UnaryTree unary) {
                FlowValue operand = value(unary.getExpression());
                if (unary.getKind() == Tree.Kind.LOGICAL_COMPLEMENT) {
                    Boolean condition = truth(operand);
                    return condition == null ? unknown("boolean") : literal(!condition);
                }
                if (Set.of(Tree.Kind.PREFIX_INCREMENT, Tree.Kind.POSTFIX_INCREMENT,
                        Tree.Kind.PREFIX_DECREMENT, Tree.Kind.POSTFIX_DECREMENT).contains(unary.getKind())) {
                    FlowValue previous = operand.copy();
                    boolean increment = unary.getKind() == Tree.Kind.PREFIX_INCREMENT || unary.getKind() == Tree.Kind.POSTFIX_INCREMENT;
                    FlowValue updated = arithmetic(increment ? Tree.Kind.PLUS : Tree.Kind.MINUS, operand, literal(1));
                    assign(unary.getExpression(), updated);
                    return unary.getKind() == Tree.Kind.POSTFIX_INCREMENT || unary.getKind() == Tree.Kind.POSTFIX_DECREMENT ? previous : updated;
                }
                if (unary.getKind() == Tree.Kind.UNARY_MINUS) return arithmetic(Tree.Kind.MINUS, literal(0), operand);
                if (unary.getKind() == Tree.Kind.UNARY_PLUS) return operand.copy();
                return NUMERIC_TYPES.contains(operand.type) ? unknown(operand.type) : unknown("?");
            }
            if (expression instanceof NewClassTree created) {
                String type = typeName(created.getIdentifier());
                List<FlowValue> args = created.getArguments().stream().map(this::value).toList();
                FlowValue result = unknown(type);
                Element constructor = symbol(created);
                ClassTree declared = constructor == null ? null : classDeclarations.get(constructor.getEnclosingElement());
                if (declared != null) {
                    initializeClass(declared);
                    result.members = copyState(List.of(initialFields.getOrDefault(declared, Map.of()))).get(0);
                    result.origins = Set.of(++nextObjectId);
                    MethodTree body = methodDeclarations.get(constructor);
                    if (body != null) localCall(body, args, result);
                }
                if (Set.of("OutputStreamWriter", "BufferedWriter", "PrintWriter", "BufferedOutputStream", "PrintStream").contains(type)
                        && !args.isEmpty()) result.command = args.get(0).command;
                if (type.equals("File")) {
                    result.unsafe = args.stream().anyMatch(v -> v.unsafe);
                    result.inputDependent = args.stream().anyMatch(v -> v.inputDependent);
                }
                if (type.equals("ProcessBuilder")) {
                    result.command = libraries.commandArguments(args);
                    result.origins = Set.of(++nextObjectId);
                } else if (type.equals("ArrayList") || type.equals("LinkedList") || type.equals("Vector")) {
                    result = vector(args.size() == 1 && args.get(0).elements != null
                            ? args.get(0).elements : List.of(), type);
                    if (args.size() == 1 && args.get(0).unsafe && args.get(0).elements == null) result.unsafe = true;
                } else if (Set.of("HashMap", "LinkedHashMap", "TreeMap", "Properties").contains(type)) {
                    result = new FlowValue(null, false, false, type);
                    result.entries = args.size() == 1 ? args.get(0).entries == null ? null
                            : new HashMap<>(args.get(0).entries) : new HashMap<>();
                    result.unsafe = result.entries == null || result.entries.values().stream().anyMatch(v -> v.unsafe);
                    result.origins = Set.of(++nextObjectId);
                }
                if (builder(result) || type.equals("String")) {
                    FlowValue initial = args.isEmpty() || NUMERIC_TYPES.contains(args.get(0).type)
                            ? literal("") : args.get(0);
                    if (type.equals("StringJoiner")) {
                        initial = literal("");
                        for (FlowValue arg : args) initial = combine(initial, arg);
                        initial.text = null;
                    }
                    result = new FlowValue(initial.text, initial.unsafe, initial.sql, type);
                    result.inputDependent = initial.inputDependent;
                    result.prefix = initial.prefix;
                }
                if (builder(result)) result.origins = Set.of(++nextObjectId);
                if (NUMERIC_TYPES.contains(type)) result = unknown(type);
                scan(created.getClassBody(), null);
                return result;
            }
            if (expression instanceof MethodInvocationTree call) return call(call);
            if (expression instanceof ArrayAccessTree array) {
                FlowValue container = value(array.getExpression());
                value(array.getIndex());
                Integer index = index(known(array.getIndex()));
                if (container.elements != null && index != null && index >= 0 && index < container.elements.size()) {
                    return container.elements.get(index);
                }
                String type = container.type.endsWith("[]")
                        ? container.type.substring(0, container.type.length() - 2) : "?";
                return NUMERIC_TYPES.contains(type) ? unknown(type)
                        : new FlowValue(null, container.unsafe, container.sql, type);
            } else if (expression instanceof NewArrayTree array) {
                FlowValue result = literal("");
                List<FlowValue> elements = new ArrayList<>();
                if (array.getInitializers() != null) {
                    for (ExpressionTree element : array.getInitializers()) {
                        FlowValue item = value(element);
                        elements.add(item);
                        result = combine(result, item);
                    }
                }
                for (ExpressionTree dimension : array.getDimensions()) value(dimension);
                FlowValue container = new FlowValue(null, result.unsafe, result.sql,
                        array.getType() == null ? "?[]" : typeName(array.getType()) + "[]");
                container.origins = Set.of(++nextObjectId);
                container.inputDependent = result.inputDependent;
                if (array.getInitializers() != null) {
                    container.elements = elements;
                } else if (array.getDimensions().size() == 1) {
                    Integer length = index(known(array.getDimensions().get(0)));
                    if (length != null && length >= 0 && length <= 1024) {
                        container.elements = new ArrayList<>();
                        for (int i = 0; i < length; i++) container.elements.add(literal(null));
                    }
                }
                return container;
            } else if (expression instanceof LambdaExpressionTree lambda) {
                Frame frame = new Frame();
                try {
                    scopes = snapshot();
                    if (thisValue != null) {
                        thisValue = thisValue.copy();
                        thisValue.members = scopes.get(0);
                    }
                    scopes.add(new HashMap<>());
                    abrupt = false;
                    returned = null;
                    exits = new ArrayList<>();
                    exceptionPaths = new ArrayList<>();
                    scan(lambda.getParameters(), null);
                    if (lambda.getBody() instanceof ExpressionTree body) value(body);
                    else scan(lambda.getBody(), null);
                    note(lambda, "Callback body analyzed conservatively; invocation and capture effects are not resolved");
                } finally { frame.close(); }
            } else if (expression instanceof MemberReferenceTree) {
                note(expression, "Method-reference callback execution is not resolved; inspect its target manually");
            } else {
                note(expression, "Unsupported expression flow: " + expression.getKind());
                scan(expression, null);
            }
            return unknown("?");
        }

        FlowValue call(MethodInvocationTree call) {
            ExpressionTree select = call.getMethodSelect();
            MemberSelectTree member = select instanceof MemberSelectTree m ? m : null;
            String name = member == null ? select.toString() : member.getIdentifier().toString();
            String owner = member == null ? "" : member.getExpression().toString();
            FlowValue receiver = member == null ? unknown("?") : value(member.getExpression());
            List<FlowValue> args = call.getArguments().stream().map(this::value).toList();
            if (abrupt) return unknown(typeName(call));
            Element resolved = symbol(select);
            ExecutableElement method = resolved instanceof ExecutableElement executable ? executable : null;
            String apiOwner = method == null ? owner : method.getEnclosingElement().toString();
            boolean stringApi = receiver.type.equals("String")
                    && (method == null || apiOwner.equals("java.lang.String"));
            boolean staticStringApi = apiOwner.equals("java.lang.String") || apiOwner.equals("String");
            FlowValue target = member == null || owner.equals("this") ? thisValue : receiver;
            if (method != null && method.getModifiers().contains(javax.lang.model.element.Modifier.STATIC)) target = null;
            if (target != null && target.members == null && methodDeclarations.containsKey(method)
                    && !method.getModifiers().contains(javax.lang.model.element.Modifier.FINAL)
                    && !method.getModifiers().contains(javax.lang.model.element.Modifier.PRIVATE)
                    && !method.getEnclosingElement().getModifiers().contains(javax.lang.model.element.Modifier.FINAL)) {
                note(call, "Virtual receiver runtime type is unknown; result is conservatively untrusted");
                return unknown(typeName(call));
            }
            if (target != null && target.members != null && target.runtimeTypes.size() > 1) {
                FlowValue result = pureDispatch(method, target, name, args);
                if (result != null) return result;
            }
            MethodTree body = dispatchedMethod(method, target, name);
            if (body != null && body.getBody() != null) return localCall(body, args, target);
            FlowValue process = libraries.processCall(call, name, apiOwner, receiver, args);
            if (process != null) return process;
            FlowValue path = libraries.pathCall(name, apiOwner, receiver, args);
            if (path != null) return path;
            FlowValue reflection = reflectionCall(call, name, apiOwner, receiver, args);
            if (reflection != null) return reflection;
            if (immutableFactory(call)) {
                FlowValue collection = new FlowValue(null, args.stream().anyMatch(v -> v.unsafe), false, typeName(call));
                collection = name.equals("copyOf") && args.size() == 1 && args.get(0).elements != null
                            ? vector(args.get(0).elements, typeName(call)) : vector(args, typeName(call));
                collection.immutable = true;
                return collection;
            }
            if (method == null && (member == null || owner.equals("this") || owner.equals(className))) {
                List<MethodTree> candidates = methods.getOrDefault(name, List.of()).stream()
                        .filter(m -> m.getParameters().size() == args.size()).toList();
                if (candidates.size() == 1) return localCall(candidates.get(0), args, target);
            }
            boolean jdbc = method != null && jdbcMethod(method);
            boolean spring = apiOwner.startsWith("org.springframework.jdbc.")
                    || Set.of("JdbcTemplate", "JdbcOperations", "NamedParameterJdbcTemplate", "NamedParameterJdbcOperations").contains(receiver.type)
                    || (method == null && !args.isEmpty() && args.get(0).sql && receiver.type.equals("?"));
            boolean orm = apiOwner.startsWith("jakarta.persistence.") || apiOwner.startsWith("javax.persistence.")
                    || apiOwner.startsWith("org.hibernate.")
                    || Set.of("EntityManager", "Session", "StatelessSession").contains(receiver.type)
                    || (method == null && !args.isEmpty() && args.get(0).sql && receiver.type.equals("?"));
            boolean inferredJdbc = method == null && !args.isEmpty() && (JDBC_TYPES.contains(receiver.type)
                    || (receiver.type.equals("?") && (!name.equals("execute") || args.get(0).sql)));
            if (check == Check.SQL_INJECTION && SINKS.contains(name) && !args.isEmpty() && args.get(0).unsafe
                    && (jdbc || inferredJdbc)) {
                report(call, name);
            }
            if (check == Check.SQL_INJECTION && SPRING_SQL.contains(name) && spring
                    && !args.isEmpty() && args.get(0).unsafe) report(call, name);
            if (check == Check.SQL_INJECTION && ORM_SQL.contains(name) && orm
                    && !args.isEmpty() && args.get(0).unsafe) report(call, name);
            if (method == null || jdbc) {
                if (name.equals("createStatement")) return unknown("Statement");
                if (name.equals("prepareStatement")) return unknown("PreparedStatement");
                if (name.equals("prepareCall")) return unknown("CallableStatement");
            }
            if (jdbc && SINKS.contains(name) || spring && SPRING_SQL.contains(name) || orm && ORM_SQL.contains(name)) return unknown(typeName(call));
            if (apiOwner.startsWith("java.sql.") && name.startsWith("get")) return unknown(typeName(call));
            if ((apiOwner.equals("java.lang.System") && Set.of("getenv", "getProperty").contains(name))
                    || (Set.of("getParameter", "getParameterValues", "getHeader", "getHeaders", "getCookies").contains(name)
                    && (apiOwner.contains("servlet") || method == null))
                    || (Set.of("java.io.BufferedReader", "java.io.Console", "java.util.Scanner").contains(apiOwner)
                    && (name.startsWith("read") || name.startsWith("next")))) return unknown(typeName(call));
            if (apiOwner.equals("java.net.URLDecoder") && name.equals("decode")) {
                return new FlowValue(null, args.stream().anyMatch(v -> v.unsafe),
                        args.stream().anyMatch(v -> v.sql), "String");
            }
            FlowValue stringResult = libraries.stringCall(call, name, owner, apiOwner, receiver, args, stringApi, staticStringApi);
            if (stringResult != null) return stringResult;
            // Unknown helpers may mutate a supplied buffer/array.
            for (FlowValue arg : args) {
                if (!arg.origins.isEmpty()) mutate(arg, new FlowValue(null, true, arg.sql, arg.type));
            }
            // Arbitrary escaping/replace helpers do not establish SQL safety.
            FlowValue result = unknown(method == null ? "?" : typeName(call));
            result.sql = receiver.sql || args.stream().anyMatch(v -> v.sql);
            if (result.unsafe && !name.equals("<init>") && !name.equals("super")
                    && (!result.type.equals("void") || !apiOwner.startsWith("java."))) {
                note(call, "Unmodeled call " + name + "; return value is conservatively untrusted");
            }
            return result;
        }

        MethodTree dispatchedMethod(ExecutableElement method, FlowValue receiver, String name) {
            MethodTree declared = methodDeclarations.get(method);
            if (receiver == null || receiver.members == null) return declared;
            if (receiver.runtimeTypes.size() != 1) {
                note(declared == null ? currentClass : declared, "Multiple possible runtime types; dispatch is conservatively unresolved");
                return null;
            }
            String runtime = receiver.runtimeTypes.iterator().next().substring("source:".length()).split("<", 2)[0];
            for (var entry : classDeclarations.entrySet()) {
                if (!entry.getKey().toString().equals(runtime)) continue;
                for (MethodTree candidate : methodsOf(entry.getValue()).getOrDefault(name, List.of())) {
                    Element symbol = symbol(candidate);
                    if (method == null || symbol == method || symbol instanceof ExecutableElement override
                            && program.task.getElements().overrides(override, method, (TypeElement) entry.getKey())) return candidate;
                }
            }
            return declared;
        }

        FlowValue pureDispatch(ExecutableElement method, FlowValue receiver, String name, List<FlowValue> args) {
            if (args.stream().anyMatch(v -> !v.origins.isEmpty())) return null;
            List<MethodTree> targets = new ArrayList<>();
            for (String runtime : receiver.runtimeTypes) {
                FlowValue one = receiver.copy(); one.runtimeTypes = Set.of(runtime);
                MethodTree candidate = dispatchedMethod(method, one, name);
                if (candidate == null || candidate.getBody() == null || !pure(candidate)) return null;
                targets.add(candidate);
            }
            FlowValue result = null;
            int index = 0;
            for (String runtime : receiver.runtimeTypes) {
                FlowValue one = receiver.copy(); one.runtimeTypes = Set.of(runtime); one.origins = Set.of();
                FlowValue returned = localCall(targets.get(index++), args, one);
                result = result == null ? returned : join(result, returned);
            }
            return result;
        }

        boolean pure(MethodTree method) {
            boolean[] pure = {true};
            new TreeScanner<Void, Void>() {
                @Override public Void visitAssignment(AssignmentTree tree, Void unused) { pure[0] = false; return null; }
                @Override public Void visitCompoundAssignment(CompoundAssignmentTree tree, Void unused) { pure[0] = false; return null; }
                @Override public Void visitUnary(UnaryTree tree, Void unused) {
                    if (Set.of(Tree.Kind.PREFIX_INCREMENT, Tree.Kind.POSTFIX_INCREMENT,
                            Tree.Kind.PREFIX_DECREMENT, Tree.Kind.POSTFIX_DECREMENT).contains(tree.getKind())) pure[0] = false;
                    return super.visitUnary(tree, unused);
                }
                @Override public Void visitMethodInvocation(MethodInvocationTree tree, Void unused) {
                    Element element = symbol(tree.getMethodSelect());
                    if (!(element instanceof ExecutableElement call)) pure[0] = false;
                    else {
                        String owner = call.getEnclosingElement().toString();
                        if (!owner.equals("java.lang.String") && !(owner.equals("java.lang.StringBuilder")
                                && call.getSimpleName().contentEquals("toString"))) pure[0] = false;
                    }
                    return super.visitMethodInvocation(tree, unused);
                }
                @Override public Void visitNewClass(NewClassTree tree, Void unused) {
                    if (!Set.of("String", "StringBuilder", "StringBuffer").contains(typeName(tree.getIdentifier()))) pure[0] = false;
                    return super.visitNewClass(tree, unused);
                }
            }.scan(method.getBody(), null);
            return pure[0];
        }

        FlowValue reflectionCall(MethodInvocationTree call, String name, String owner, FlowValue receiver, List<FlowValue> args) {
            if (owner.equals("java.lang.Object") && name.equals("getClass")) {
                FlowValue type = new FlowValue(null, false, false, "Class");
                if (receiver.members != null) type.runtimeTypes = receiver.runtimeTypes;
                return type;
            }
            if (owner.equals("java.lang.Class") && name.equals("getClassLoader")) return new FlowValue(null, false, false, "ClassLoader");
            if ((owner.equals("java.lang.ClassLoader") || owner.equals("java.lang.Class"))
                    && name.equals("getResourceAsStream") && args.size() == 1 && args.get(0).text != null) {
                String key = resourceName(owner, receiver, args.get(0).text);
                String resource = key == null ? null : program.request.resources().get(key);
                if (resource != null && args.get(0).text.endsWith(".properties")) {
                    try {
                        var properties = new java.util.Properties();
                        properties.load(new java.io.ByteArrayInputStream(resource.getBytes(java.nio.charset.StandardCharsets.UTF_8)));
                        FlowValue stream = new FlowValue(null, false, false, "InputStream");
                        stream.entries = new HashMap<>();
                        for (String property : properties.stringPropertyNames()) stream.entries.put("String:" + property, literal(properties.getProperty(property)));
                        return stream;
                    } catch (IOException e) { throw new IllegalArgumentException("Invalid properties resource", e); }
                }
            }
            if ((owner.equals("java.lang.ClassLoader") || owner.equals("java.lang.Class")) && name.equals("getResource") && args.size() == 1
                    && args.get(0).text != null && resourceName(owner, receiver, args.get(0).text) != null
                    && program.request.resources().containsKey(resourceName(owner, receiver, args.get(0).text))) {
                FlowValue resource = new FlowValue(null, false, false, "URL");
                resource.knownNonNull = true;
                return resource;
            }
            if (receiver.type.equals("Properties") && name.equals("load") && args.size() == 1) {
                FlowValue changed = receiver.copy();
                changed.entries = receiver.entries == null || args.get(0).entries == null ? null : new HashMap<>(receiver.entries);
                if (changed.entries != null) changed.entries.putAll(args.get(0).entries);
                changed.unsafe = changed.entries == null;
                mutate(receiver, changed);
                if (changed.entries == null) note(call, "Properties content is unavailable; supply configuration resources for precise values");
                return unknown("void");
            }
            if (receiver.type.equals("Properties") && name.equals("getProperty") && !args.isEmpty()) {
                if (receiver.entries == null) return unknown("String");
                return receiver.entries.getOrDefault(mapKey(args.get(0)), args.size() > 1 ? args.get(1) : literal(null));
            }
            if (owner.equals("java.lang.Class") && name.equals("forName") && !args.isEmpty()
                    && !args.get(0).unsafe && args.get(0).text != null) {
                FlowValue handle = new FlowValue(null, false, false, "Class");
                handle.runtimeTypes = Set.of("source:" + args.get(0).text);
                return handle;
            }
            if (receiver.type.equals("Class") && Set.of("getConstructor", "getDeclaredConstructor").contains(name)) {
                FlowValue constructor = receiver.copy();
                constructor = typed(constructor, "Constructor");
                constructor.elements = args;
                return constructor;
            }
            if (Set.of("Class", "Constructor").contains(receiver.type) && name.equals("newInstance")
                    && receiver.runtimeTypes.size() == 1) {
                String runtime = receiver.runtimeTypes.iterator().next().substring("source:".length());
                for (var entry : classDeclarations.entrySet()) {
                    if (!entry.getKey().toString().equals(runtime)) continue;
                    initializeClass(entry.getValue());
                    List<FlowValue> arguments = args.size() == 1 && args.get(0).elements != null ? args.get(0).elements : args;
                    var constructors = methodsOf(entry.getValue()).getOrDefault("<init>", List.of()).stream()
                            .filter(m -> m.getParameters().size() == arguments.size()).toList();
                    if (constructors.size() != 1) break;
                    FlowValue object = unknown("source:" + runtime);
                    object.members = copyState(List.of(initialFields.getOrDefault(entry.getValue(), Map.of()))).get(0);
                    object.origins = Set.of(++nextObjectId);
                    localCall(constructors.get(0), arguments, object);
                    return object;
                }
                note(call, "Reflective constructor is not uniquely resolvable from supplied source");
            }
            return null;
        }

        String resourceName(String owner, FlowValue receiver, String name) {
            if (owner.equals("java.lang.ClassLoader")) return name.startsWith("/") ? null : name;
            if (name.startsWith("/")) return name.substring(1);
            if (receiver.runtimeTypes.size() != 1) return null;
            String type = receiver.runtimeTypes.iterator().next().replaceFirst("^source:", "");
            int end = type.lastIndexOf('.');
            return end < 0 ? name : type.substring(0, end).replace('.', '/') + "/" + name;
        }

        FlowValue localCall(MethodTree method, List<FlowValue> args) {
            return localCall(method, args, null);
        }

        FlowValue localCall(MethodTree method, List<FlowValue> args, FlowValue receiver) {
            String type = method.getReturnType() == null ? "?" : typeName(method.getReturnType());
            if (activeMethods.contains(method) || activeMethods.size() >= 64 || method.getBody() == null) {
                note(method, "Recursive or unavailable helper body; result is conservatively untrusted");
                return unknown(type);
            }
            ClassTree owner = methodClasses.get(method);
            initializeClass(owner);
            Frame frame = new Frame();
            FlowValue result;
            List<FlowValue> effects = new ArrayList<>();
            try {
                Map<String, FlowValue> fields = receiver != null && receiver.members != null ? receiver.members
                        : owner == null || owner == currentClass ? scopes.get(0) : classFields.get(owner);
                enterClass(owner, new HashMap<>(fields));
                thisValue = receiver;
                scopes.add(new HashMap<>());
                Element declaration = symbol(method);
                boolean varargs = declaration instanceof ExecutableElement executable && executable.isVarArgs();
                for (int i = 0; i < method.getParameters().size(); i++) {
                    VariableTree parameter = method.getParameters().get(i);
                    String parameterType = typeName(parameter.getType());
                    FlowValue argument = i < args.size() ? args.get(i) : unknown(parameterType);
                    if (varargs && i == method.getParameters().size() - 1
                            && (args.size() != method.getParameters().size() || !argument.type.endsWith("[]"))) {
                        argument = vector(args.subList(i, args.size()), parameterType);
                    }
                    scopes.get(1).put(parameter.getName().toString(), typed(argument, parameterType));
                }
                activeMethods.add(method);
                scan(method.getBody(), null);
                result = returned == null ? unknown(type) : typed(returned, type);
                for (int i = 0; i < Math.min(args.size(), method.getParameters().size()); i++) {
                    FlowValue effect = get(method.getParameters().get(i).getName().toString());
                    effects.add(Collections.disjoint(args.get(i).origins, effect.origins) ? null : effect.copy());
                }
                Map<String, FlowValue> updated = new HashMap<>(scopes.get(0));
                if (receiver != null && receiver.members != null) receiver.members = updated;
                if (owner == frame.savedClass && (receiver == null || receiver == frame.savedThis)) {
                    frame.savedScopes.get(0).clear();
                    frame.savedScopes.get(0).putAll(updated);
                } else if (receiver == null && owner != null) {
                    classFields.get(owner).putAll(updated);
                }
            } finally {
                activeMethods.remove(method);
                frame.close();
            }
            if (receiver != null && !receiver.origins.isEmpty()) mutate(receiver, receiver.copy());
            for (int i = 0; i < effects.size(); i++) if (effects.get(i) != null) mutate(args.get(i), effects.get(i));
            return result;
        }

        public FlowValue vector(List<FlowValue> elements, String type) {
            FlowValue result = new FlowValue(null, elements.stream().anyMatch(v -> v.unsafe),
                    elements.stream().anyMatch(v -> v.sql), type);
            result.elements = new ArrayList<>(elements);
            result.inputDependent = elements.stream().anyMatch(v -> v.inputDependent);
            result.origins = Set.of(++nextObjectId);
            return result;
        }

        public boolean checksCommands() { return check == Check.COMMAND_INJECTION; }
        public int newIdentity() { return ++nextObjectId; }

        public void stopAfterException() { captureException(); abrupt = true; }

        public void report(MethodInvocationTree call, String name) {
            int position = (int) positions.getEndPosition(unit, call.getMethodSelect()) - name.length() - offset;
            if (position < 0 || position >= source.length()) return;
            int line = (int) (unit.getLineMap().getLineNumber(position + offset)
                    - unit.getLineMap().getLineNumber(offset) + 1);
            int start = Math.max(source.lastIndexOf('\n', position), source.lastIndexOf('\r', position)) + 1;
            int end = source.length();
            for (int i = position; i < source.length(); i++) {
                if (source.charAt(i) == '\n' || source.charAt(i) == '\r') { end = i; break; }
            }
            boolean command = check == Check.COMMAND_INJECTION;
            findings.put(fileName + "\u0000" + String.format(Locale.ROOT, "%010d", position), new Finding(command ? "CWE-78" : "CWE-89", fileName, line,
                    command ? "Untrusted input may control an executable, command text, shell input, or process environment. "
                            + "An attacker could run unintended commands. Use an allowlisted executable and separate "
                            + "data arguments; avoid passing input to a shell or interpreter."
                            : "SQL execution may use dynamically constructed query data. "
                            + "Verify the data flow and use parameterized queries.",
                    source.substring(start, end).strip()));
        }
    }
}
