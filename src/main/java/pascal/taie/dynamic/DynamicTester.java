package pascal.taie.dynamic;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.yaml.YAMLFactory;
import pascal.taie.analysis.dataflow.analysis.methodsummary.plugin.PrioriKnowConfig;
import pascal.taie.config.Options;
import sun.misc.Unsafe;

import javax.management.BadAttributeValueExpException;
import java.io.*;
import java.lang.reflect.*;
import java.math.BigInteger;
import java.net.URL;
import java.net.URLClassLoader;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.ThreadLocalRandom;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Dynamic tester for validating gadget chains discovered by static analysis.
 * Incorporates techniques from both Crystaliser and GCMiner for robust object instantiation and chain validation.
 */
public class DynamicTester {

    // ========== Configuration ==========
    private static Options options;
    private static String identifier;
    private static int MAX_DEPTH = 5;

    // ========== Knowledge Base ==========
    private static Map<String, Map<String, HierarchyNode>> classHierarchy;
    private static List<String> SINKS;
    private static Map<String, Object> prioriKnowledge;

    // ========== Instantiation Cache ==========
    // LinkedHashMap preserves insertion order - important for chain construction
    private static Map<Class<?>, Object> localCache = new LinkedHashMap<>();

    // ========== Statistics ==========
    private static int totalChains = 0;
    private static int successfulChains = 0;
    private static int partialChains = 0;

    /**
     * Represents a node in the class hierarchy JSON
     */
    public static class HierarchyNode {
        public String module;
        public Map<String, HierarchyNode> children;
    }

    /**
     * Represents one step in a gadget chain
     */
    public static class ChainStep {
        public final String fullSignature;
        public final String className;
        public final String methodName;
        public final String returnType;
        public final List<String> argumentTypes;
        public final List<Integer> controllabilityMap;  // Maps taint from previous to current

        public ChainStep(String fullSignature, String className, String methodName, String returnType,
                         List<String> argumentTypes, List<Integer> controllabilityMap) {
            this.fullSignature = fullSignature;
            this.className = className;
            this.methodName = methodName;
            this.returnType = returnType;
            this.argumentTypes = argumentTypes;
            this.controllabilityMap = controllabilityMap;
        }

        @Override
        public String toString() {
            return "ChainStep{class='" + className + "', method='" + methodName +
                   "', args=" + argumentTypes + ", map=" + controllabilityMap + '}';
        }
    }

    /**
     * Custom exception for skippable instantiation errors
     */
    private static class SkippableInstantiationException extends Exception {
        public SkippableInstantiationException(String message, Throwable cause) {
            super(message, cause);
        }
        public SkippableInstantiationException(String message) {
            super(message);
        }
    }

    // ========== INITIALIZATION ==========

    public static void main(String[] args) {
        try {
            setup(args);
            redirectLogging();

            String chainsFile = options.getOutputDir() + File.separator + options.getGC_OUT();
            String configFile = args.length > 1 ? args[1] : null;
            runDynamicValidation(chainsFile,configFile);

            printSummary();
        } catch (Exception e) {
            System.err.println("Fatal error: " + e.getMessage());
            e.printStackTrace();
        }
    }

    private static void setup(String[] args) {
        try {
            options = Options.parse(args);
            if (options.isPrintHelp() || args.length == 0) {
                options.printHelp();
                System.exit(0);
            }

            identifier = PrioriKnowConfig.getIndentiferOfJar(options);

            // Load class hierarchy
            ObjectMapper mapper = new ObjectMapper();
            String hierarchyFile = options.getOutputDir() + File.separator + "class-hierarchy-" + identifier + ".json";
            classHierarchy = mapper.readValue(new File(hierarchyFile),
                    new com.fasterxml.jackson.core.type.TypeReference<Map<String, Map<String, HierarchyNode>>>() {});
            System.out.println("[INFO] Loaded class hierarchy with " + countClasses() + " classes");

            // Load priori knowledge (sinks, transfers, imitates)
            loadPrioriKnowledge(options.getAnalyses().getOrDefault("method-summary", "").split(":")[1]);
            System.out.println("[INFO] Loaded " + SINKS.size() + " sinks from priori knowledge");

        } catch (IOException e) {
            System.err.println("[ERROR] Failed to load configuration: " + e.getMessage());
            e.printStackTrace();
            System.exit(1);
        }
    }

    private static void loadPrioriKnowledge(String yamlFilePath) throws IOException {
        ObjectMapper mapper = new ObjectMapper(new YAMLFactory());
        prioriKnowledge = mapper.readValue(new File(yamlFilePath),
                new com.fasterxml.jackson.core.type.TypeReference<Map<String, Object>>() {});

        // Extract sinks
        @SuppressWarnings("unchecked")
        List<Map<String, Object>> sinksData = (List<Map<String, Object>>) prioriKnowledge.get("sinks");
        SINKS = new ArrayList<>();
        if (sinksData != null) {
            for (Map<String, Object> sink : sinksData) {
                SINKS.add((String) sink.get("method"));
            }
        }
    }

    private static void redirectLogging() {
        try {
            File logDir = new File(options.getOutputDir() + File.separator + "log");
            if (!logDir.exists()) {
                logDir.mkdirs();
            }

            File logFile = new File(logDir, String.format("dynamic-tester-%s.log", identifier));
            FileOutputStream fos = new FileOutputStream(logFile);
            PrintStream ps = new PrintStream(fos);
            System.setOut(ps);
            System.setErr(ps);
        } catch (FileNotFoundException e) {
            System.err.println("[WARN] Failed to set up file logger: " + e.getMessage());
        }
    }

    private static int countClasses() {
        int count = 0;
        for (Map<String, HierarchyNode> module : classHierarchy.values()) {
            count += countClassesRecursive(module);
        }
        return count;
    }

    private static int countClassesRecursive(Map<String, HierarchyNode> nodes) {
        int count = nodes.size();
        for (HierarchyNode node : nodes.values()) {
            if (node.children != null) {
                count += countClassesRecursive(node.children);
            }
        }
        return count;
    }

    // ========== CHAIN PARSING ==========

    public static List<List<ChainStep>> parseChains(String filePath) throws IOException {
        List<List<ChainStep>> chains = new ArrayList<>();
        Pattern linePattern = Pattern.compile("(<.*?>)(?:->(\\[.*\\]))?");
        Pattern methodPattern = Pattern.compile("<(.*): (.*) (.*)\\((.*)\\)>");

        try (BufferedReader reader = new BufferedReader(new FileReader(filePath, StandardCharsets.UTF_8))) {
            String line;
            List<String> chainLines = new ArrayList<>();

            while ((line = reader.readLine()) != null) {
                line = line.trim();
                if (line.isEmpty()) {
                    if (!chainLines.isEmpty()) {
                        chains.add(parseChain(chainLines, linePattern, methodPattern));
                        chainLines.clear();
                    }
                } else {
                    chainLines.add(line);
                }
            }

            // Don't forget the last chain if file doesn't end with blank line
            if (!chainLines.isEmpty()) {
                chains.add(parseChain(chainLines, linePattern, methodPattern));
            }
        }

        return chains;
    }

    private static List<ChainStep> parseChain(List<String> chainLines, Pattern linePattern, Pattern methodPattern) {
        List<ChainStep> chain = new ArrayList<>();

        for (int i = 0; i < chainLines.size(); i++) {
            String line = chainLines.get(i);
            Matcher lineMatcher = linePattern.matcher(line);

            if (lineMatcher.find()) {
                String signature = lineMatcher.group(1);

                // Parse controllability map from previous line
                List<Integer> map = null;
                if (i > 0) {
                    String prevLine = chainLines.get(i - 1);
                    Matcher prevLineMatcher = linePattern.matcher(prevLine);
                    if (prevLineMatcher.find()) {
                        String mapStr = prevLineMatcher.group(2);
                        if (mapStr != null) {
                            map = parseControllabilityMap(mapStr);
                        }
                    }
                }

                // Parse method signature
                Matcher methodMatcher = methodPattern.matcher(signature);
                if (methodMatcher.find()) {
                    String className = methodMatcher.group(1);
                    String returnType = methodMatcher.group(2);
                    String methodName = methodMatcher.group(3);
                    String argsStr = methodMatcher.group(4);

                    List<String> argumentTypes = new ArrayList<>();
                    if (argsStr != null && !argsStr.trim().isEmpty()) {
                        for (String arg : argsStr.split(",")) {
                            argumentTypes.add(arg.trim());
                        }
                    }

                    chain.add(new ChainStep(signature, className, methodName, returnType, argumentTypes, map));
                }
            }
        }

        return chain;
    }

    private static List<Integer> parseControllabilityMap(String mapStr) {
        List<Integer> map = new ArrayList<>();
        String[] values = mapStr.replace("[", "").replace("]", "").split(",");

        for (String val : values) {
            if (!val.trim().isEmpty()) {
                map.add(Integer.parseInt(val.trim()));
            }
        }

        return map;
    }

    // ========== OBJECT INSTANTIATION ==========

    /**
     * Instantiate an object using multiple strategies
     * 1. Try constructors (scored by parameter matching)
     * 2. Try declared constructors with setAccessible
     * 3. Use Unsafe.allocateInstance as fallback
     */
    @SuppressWarnings("unchecked")
    public static <T> T instantiateObject(String className, URLClassLoader classLoader) throws Exception {
        return (T) instantiateObject(className, null, classLoader, 0);
    }

    @SuppressWarnings("unchecked")
    public static <T> T instantiateObject(String className, List<String> preferredArgTypes,
                                          URLClassLoader classLoader) throws Exception {
        return (T) instantiateObject(className, preferredArgTypes, classLoader, 0);
    }

    private static Object instantiateObject(String className, List<String> preferredArgTypes,
                                            URLClassLoader classLoader, int depth) throws Exception {
        if (depth > MAX_DEPTH) {
            throw new SkippableInstantiationException("Max recursion depth reached for: " + className);
        }

        // Check cache first
        Class<?> targetClass = null;
        try {
            targetClass = Class.forName(className, true, classLoader);
        } catch (ClassNotFoundException | NoClassDefFoundError e) {
            throw new SkippableInstantiationException("Class not found: " + className, e);
        } catch (ExceptionInInitializerError e) {
            throw new SkippableInstantiationException("Class initialization failed: " + className, e);
        } catch (LinkageError e) {
            throw new SkippableInstantiationException("Class linkage error: " + className, e);
        }

        // Check if we've already instantiated this type
        Object cached = localCache.get(targetClass);
        if (cached != null) {
            System.out.println("  [Cache] Reusing cached instance of " + className);
            return cached;
        }

        // Handle special cases
        if (targetClass == String.class) {
            return getStrategicString();
        }

        if (targetClass == Class.class) {
            return Object.class;  // Safe default
        }

        // Handle array types
        if (targetClass.isArray()) {
            return instantiateArray(targetClass, classLoader, depth);
        }

        // Handle interfaces and abstract classes
        if (targetClass.isInterface() || Modifier.isAbstract(targetClass.getModifiers())) {
            return instantiateConcreteSubclass(className, classLoader, depth);
        }

        // Try instantiation strategies
        Object instance = null;

        // Strategy 1: Try public constructors (with scoring if we have preferred types)
        instance = tryConstructors(targetClass, targetClass.getConstructors(), preferredArgTypes, classLoader, depth);
        if (instance != null) {
            localCache.put(targetClass, instance);
            return instance;
        }

        // Strategy 2: Try all declared constructors (including private)
        instance = tryConstructors(targetClass, targetClass.getDeclaredConstructors(), preferredArgTypes, classLoader, depth);
        if (instance != null) {
            localCache.put(targetClass, instance);
            return instance;
        }

        // Strategy 3: Use Unsafe
        instance = tryUnsafeAllocation(targetClass);
        if (instance != null) {
            localCache.put(targetClass, instance);
            initializeFields(instance, classLoader, depth);
            return instance;
        }

        throw new Exception("Failed to instantiate " + className + " after trying all strategies");
    }

    /**
     * Get a strategic string value that might be useful in gadget chains
     */
    private static String getStrategicString() {
        String[] strategicStrings = {
            "outputProperties",  // For TemplatesImpl chains
            "newTransformer",    // For TemplatesImpl chains
            "toString",          // Common trigger
            "hashCode",          // Common trigger
            "execute",           // For Groovy chains
            "entrySet",          // For Groovy chains
            "key",               // Generic
            "value"              // Generic
        };
        return strategicStrings[ThreadLocalRandom.current().nextInt(strategicStrings.length)];
    }

    /**
     * Instantiate an array type
     * Handles JVM array descriptors like [S (short[]), [Ljava.lang.String; (String[]), etc.
     */
    private static Object instantiateArray(Class<?> arrayClass, URLClassLoader classLoader, int depth) throws Exception {
        Class<?> componentType = arrayClass.getComponentType();
        System.out.println("  [Array] Creating array of type: " + arrayClass.getName() + " (component: " + componentType.getName() + ")");

        // Create array with 1-3 elements for better coverage
        int arraySize = ThreadLocalRandom.current().nextInt(1, 4);
        Object array = Array.newInstance(componentType, arraySize);

        // Try to populate the array with instances
        for (int i = 0; i < arraySize; i++) {
            try {
                Object element;
                if (componentType.isPrimitive()) {
                    // Primitives get default values (already set by Array.newInstance)
                    continue;
                } else if (componentType == String.class) {
                    element = getStrategicString();
                } else if (componentType == Class.class) {
                    element = Object.class;
                } else {
                    // Try to instantiate component type
                    element = instantiateObject(componentType.getName(), null, classLoader, depth + 1);
                }
                Array.set(array, i, element);
            } catch (Exception e) {
                // If we can't instantiate an element, leave it as null
                System.out.println("  [Array] Could not populate element " + i + ": " + e.getMessage());
            }
        }

        return array;
    }

    /**
     * Find and instantiate a concrete subclass for an interface or abstract class
     */
    private static Object instantiateConcreteSubclass(String abstractClassName, URLClassLoader classLoader, int depth)
            throws Exception {
        System.out.println("  [Hierarchy] Finding concrete subclass for " + abstractClassName);

        List<String> candidates = findConcreteSubclasses(abstractClassName);

        if (candidates.isEmpty()) {
            throw new SkippableInstantiationException("No concrete subclasses found for: " + abstractClassName);
        }

        // Try each candidate
        for (String candidateName : candidates) {
            try {
                // Quick viability check
                Class.forName(candidateName, false, classLoader).getMethods();
                System.out.println("  [Hierarchy] Trying concrete subclass: " + candidateName);
                return instantiateObject(candidateName, null, classLoader, depth + 1);
            } catch (Throwable e) {
                System.out.println("  [Hierarchy] Candidate " + candidateName + " failed: " + e.getMessage());
            }
        }

        throw new SkippableInstantiationException("All concrete subclasses failed for: " + abstractClassName);
    }

    /**
     * Try to instantiate using constructors, with optional scoring for preferred parameter types
     */
    private static Object tryConstructors(Class<?> targetClass, Constructor<?>[] constructors,
                                          List<String> preferredArgTypes, URLClassLoader classLoader, int depth) {
        if (constructors.length == 0) {
            return null;
        }

        // Score and sort constructors if we have preferred types
        List<Constructor<?>> sortedConstructors = new ArrayList<>(Arrays.asList(constructors));
        if (preferredArgTypes != null && !preferredArgTypes.isEmpty()) {
            sortedConstructors.sort((c1, c2) -> {
                int score1 = scoreConstructor(c1, preferredArgTypes);
                int score2 = scoreConstructor(c2, preferredArgTypes);
                if (score1 != score2) {
                    return score2 - score1;  // Higher score first
                }
                return c1.getParameterCount() - c2.getParameterCount();  // Prefer fewer params
            });
        } else {
            // No preference - just sort by parameter count
            sortedConstructors.sort(Comparator.comparingInt(Constructor::getParameterCount));
        }

        // Try each constructor
        for (Constructor<?> constructor : sortedConstructors) {
            try {
                constructor.setAccessible(true);
                Class<?>[] paramTypes = constructor.getParameterTypes();
                Object[] params = new Object[paramTypes.length];

                // Instantiate parameters
                for (int i = 0; i < paramTypes.length; i++) {
                    params[i] = instantiateParameter(paramTypes[i], classLoader, depth);
                }

                Object instance = constructor.newInstance(params);
                System.out.println("  [Constructor] Successfully used: " + constructor);
                return instance;

            } catch (Throwable e) {
                // This constructor didn't work, try next
                System.out.println("  [Constructor] Failed: " + e.getMessage());
            }
        }

        return null;
    }

    /**
     * Score a constructor based on how well its parameters match the preferred types
     */
    private static int scoreConstructor(Constructor<?> constructor, List<String> preferredTypes) {
        Class<?>[] paramTypes = constructor.getParameterTypes();
        if (paramTypes.length != preferredTypes.size()) {
            return 0;
        }

        int score = 0;
        for (int i = 0; i < paramTypes.length; i++) {
            if (paramTypes[i].getName().equals(preferredTypes.get(i))) {
                score++;
            }
        }
        return score;
    }

    /**
     * Instantiate a parameter value
     */
    private static Object instantiateParameter(Class<?> type, URLClassLoader classLoader, int depth) {
        // Primitives
        if (type.isPrimitive()) {
            if (type == boolean.class) return true;
            if (type == char.class) return 'A';
            if (type == byte.class) return (byte) 1;
            if (type == short.class) return (short) 1;
            if (type == int.class) return 1;
            if (type == long.class) return 1L;
            if (type == float.class) return 1.0f;
            if (type == double.class) return 1.0d;
        }

        // Try recursive instantiation
        try {
            return instantiateObject(type.getName(), null, classLoader, depth + 1);
        } catch (Exception e) {
            System.out.println("  [Param] Recursive instantiation failed for " + type.getName() + ", using null");
            return null;
        }
    }

    /**
     * Use Unsafe to allocate instance without calling constructor
     */
    private static Object tryUnsafeAllocation(Class<?> targetClass) {
        try {
            Field unsafeField = Unsafe.class.getDeclaredField("theUnsafe");
            unsafeField.setAccessible(true);
            Unsafe unsafe = (Unsafe) unsafeField.get(null);
            System.out.println("  [Unsafe] Allocating instance for " + targetClass.getName());
            return unsafe.allocateInstance(targetClass);
        } catch (Exception | NoClassDefFoundError e) {
            return null;
        }
    }

    /**
     * Initialize fields of an Unsafe-allocated object
     */
    private static void initializeFields(Object obj, URLClassLoader classLoader, int depth) {
        if (obj == null) return;

        for (Field field : getAllFields(obj.getClass())) {
            if (Modifier.isStatic(field.getModifiers()) || field.isSynthetic()) {
                continue;
            }

            try {
                field.setAccessible(true);
                if (field.get(obj) != null) {
                    continue;  // Already initialized
                }

                Class<?> fieldType = field.getType();
                Object value = instantiateParameter(fieldType, classLoader, depth + 1);
                if (value != null) {
                    field.set(obj, value);
                }
            } catch (Throwable e) {
                // Ignore field initialization failures
            }
        }
    }

    /**
     * Find concrete subclasses using the class hierarchy
     */
    private static List<String> findConcreteSubclasses(String abstractClassName) {
        List<String> candidates = new ArrayList<>();
        HierarchyNode abstractNode = findNodeInHierarchy(abstractClassName);

        if (abstractNode != null) {
            findConcreteSubclassesRecursive(abstractNode, candidates);
        }

        return candidates;
    }

    private static HierarchyNode findNodeInHierarchy(String className) {
        for (Map<String, HierarchyNode> module : classHierarchy.values()) {
            for (Map.Entry<String, HierarchyNode> entry : module.entrySet()) {
                HierarchyNode result = findNodeRecursive(entry.getValue(), className, entry.getKey());
                if (result != null) {
                    return result;
                }
            }
        }
        return null;
    }

    private static HierarchyNode findNodeRecursive(HierarchyNode currentNode, String targetName, String currentName) {
        if (currentName.equals(targetName)) {
            return currentNode;
        }

        if (currentNode.children != null) {
            for (Map.Entry<String, HierarchyNode> entry : currentNode.children.entrySet()) {
                HierarchyNode result = findNodeRecursive(entry.getValue(), targetName, entry.getKey());
                if (result != null) {
                    return result;
                }
            }
        }

        return null;
    }

    private static void findConcreteSubclassesRecursive(HierarchyNode node, List<String> candidates) {
        if (node.children != null) {
            for (String subclassName : node.children.keySet()) {
                try {
                    Class<?> clazz = Class.forName(subclassName, false, Thread.currentThread().getContextClassLoader());
                    if (!Modifier.isAbstract(clazz.getModifiers()) && !clazz.isInterface()) {
                        candidates.add(subclassName);
                    }
                    // Always recurse to find all descendants
                    findConcreteSubclassesRecursive(node.children.get(subclassName), candidates);
                } catch (ClassNotFoundException | NoClassDefFoundError e) {
                    // Skip unavailable classes
                } catch ( LinkageError e) {
                    // Skip classes with initialization or linkage errors
                }
            }
        }
    }

    /**
     * Get all fields including inherited ones
     */
    private static List<Field> getAllFields(Class<?> clazz) {
        List<Field> fields = new ArrayList<>();
        while (clazz != null) {
            fields.addAll(Arrays.asList(clazz.getDeclaredFields()));
            clazz = clazz.getSuperclass();
        }
        return fields;
    }

    // ========== CHAIN CONSTRUCTION ==========

    /**
     * Build a complete payload from a parsed chain
     */
    public static Object buildPayload(List<ChainStep> chain, URLClassLoader classLoader) {
        if (chain == null || chain.isEmpty()) {
            return null;
        }

        localCache.clear();  // Fresh cache for each chain

        // Build chain from last to first (bottom-up)
        int gadgetsToBuild = Math.max(1, chain.size() - 2);  // Exclude sink from construction

        // Start with the last gadget (closest to sink)
        ChainStep lastStep = chain.get(Math.min(gadgetsToBuild, chain.size() - 2));
        Object lastObject;
        for (int i = gadgetsToBuild ; i >= 1; i--) {
            ChainStep currentStep = chain.get(i);

            // Skip if same class as next (internal method call)
            if (i + 1 < chain.size() && currentStep.className.equals(chain.get(i + 1).className)) {
                System.out.println("  [Skip] Same class as next: " + currentStep.className);
                continue;
            }
            else{
                lastStep=currentStep;
                gadgetsToBuild=i-1;
                break;
            }
        }

        try {
            lastObject = instantiateObject(lastStep.className, lastStep.argumentTypes, classLoader);
            System.out.println("  [Build] Instantiated last gadget: " + lastStep.className);
        } catch (SkippableInstantiationException e) {
            System.out.println("  [Skip] " + e.getMessage());
            return null;
        } catch (Exception e) {
            System.err.println("  [Fail] Could not instantiate last gadget " + lastStep.className);
            e.printStackTrace();
            return null;
        }

        Object payload = lastObject;

        // Build chain backwards
        for (int i = gadgetsToBuild ; i >= 1; i--) {
            ChainStep currentStep = chain.get(i);

            // Skip if same class as next (internal method call)
            if (i + 1 < chain.size() && currentStep.className.equals(chain.get(i + 1).className)) {
                System.out.println("  [Skip] Same class as next: " + currentStep.className);
                continue;
            }

            // Skip if same as entry point
            if (currentStep.className.equals(chain.get(0).className)) {
                break;
            }

            Object currentObject;
            try {
                currentObject = instantiateObject(currentStep.className, currentStep.argumentTypes, classLoader);
                System.out.println("  [Build] Instantiated: " + currentStep.className);
            } catch (SkippableInstantiationException e) {
                System.out.println("  [Skip] " + e.getMessage());
                return null;
            } catch (Exception e) {
                System.err.println("  [Fail] Could not instantiate " + currentStep.className);
                e.printStackTrace();
                return null;
            }

            // Link current object to payload using controllability map
            ChainStep nextStep = chain.get(i + 1);
            if (!linkObjects(currentObject, payload, nextStep.controllabilityMap)) {
                System.out.println("  [Warn] Failed to link " + currentStep.className + " -> " + payload.getClass().getName());
            } else {
                System.out.println("  [Link] Linked " + currentStep.className + " -> " + payload.getClass().getName());
            }

            payload = currentObject;
        }

        return payload;
    }

    /**
     * Link two objects based on controllability map
     * Map tells us which fields of current object should point to payload
     */
    private static boolean linkObjects(Object current, Object payload, List<Integer> controllabilityMap) {
        if (controllabilityMap == null || controllabilityMap.isEmpty()) {
            return false;
        }

        // controllabilityMap[0] = -1 means current's 'this' is tainted by previous 'this'
        // This means we need to set a field in 'current' to 'payload'

        // Try multiple linking strategies

        // Strategy 1: Find field by type match
        if (tryFieldAssignment(current, payload)) {
            return true;
        }

        // Strategy 2: Try setter methods
        if (trySetterMethod(current, payload)) {
            return true;
        }

        // Strategy 3: Try array wrapping
        if (tryArrayAssignment(current, payload)) {
            return true;
        }

        // Strategy 4: Try map insertion
        if (tryMapAssignment(current, payload)) {
            return true;
        }

        return false;
    }

    private static boolean tryFieldAssignment(Object owner, Object value) {
        for (Field field : getAllFields(owner.getClass())) {
            if (Modifier.isStatic(field.getModifiers())) continue;

            try {
                field.setAccessible(true);
                if (field.getType().isAssignableFrom(value.getClass())) {
                    field.set(owner, value);
                    return true;
                }
            } catch (Throwable e) {
                // Try next field
            }
        }
        return false;
    }

    private static boolean trySetterMethod(Object owner, Object value) {
        for (Method method : owner.getClass().getMethods()) {
            if (Modifier.isStatic(method.getModifiers())) continue;

            if (method.getName().startsWith("set") && method.getParameterCount() == 1) {
                try {
                    if (method.getParameterTypes()[0].isAssignableFrom(value.getClass())) {
                        method.invoke(owner, value);
                        return true;
                    }
                } catch (Exception e) {
                    // Try next method
                }
            }
        }
        return false;
    }

    private static boolean tryArrayAssignment(Object owner, Object value) {
        for (Field field : getAllFields(owner.getClass())) {
            if (Modifier.isStatic(field.getModifiers())) continue;

            try {
                field.setAccessible(true);
                if (field.getType().isArray() &&
                    field.getType().getComponentType().isAssignableFrom(value.getClass())) {
                    Object array = Array.newInstance(field.getType().getComponentType(), 1);
                    Array.set(array, 0, value);
                    field.set(owner, array);
                    return true;
                }
            } catch (Exception e) {
                // Try next field
            }
        }
        return false;
    }

    @SuppressWarnings("unchecked")
    private static boolean tryMapAssignment(Object owner, Object value) {
        for (Field field : getAllFields(owner.getClass())) {
            if (Modifier.isStatic(field.getModifiers())) continue;

            try {
                field.setAccessible(true);
                if (Map.class.isAssignableFrom(field.getType())) {
                    Map<Object, Object> map = (Map<Object, Object>) field.get(owner);
                    if (map == null) {
                        map = new HashMap<>();
                        field.set(owner, map);
                    }
                    map.put("key", value);
                    return true;
                }
            } catch (Exception e) {
                // Try next field
            }
        }
        return false;
    }

    /**
     * Wrap payload in a trigger gadget for entry points
     */
    public static Object wrapInTrigger(Object payload, ChainStep entryStep) {
        String entryMethod = entryStep.methodName;

        try {
            // toString() trigger
            if (entryMethod.contains("toString")) {
                BadAttributeValueExpException trigger = new BadAttributeValueExpException(payload);
                System.out.println("  [Trigger] Wrapped in BadAttributeValueExpException for toString()");
                return trigger;
            }

            // hashCode() trigger - use HashMap
            if (entryMethod.contains("hashCode")) {
                HashMap<Object, Object> trigger = new HashMap<>();
                Field tableField = HashMap.class.getDeclaredField("table");
                tableField.setAccessible(true);

                // Put dummy value to create table
                trigger.put("dummy", "value");

                Object[] table = (Object[]) tableField.get(trigger);
                if (table != null) {
                    for (Object node : table) {
                        if (node != null) {
                            Field keyField = node.getClass().getDeclaredField("key");
                            keyField.setAccessible(true);
                            keyField.set(node, payload);
                            System.out.println("  [Trigger] Wrapped in HashMap for hashCode()");
                            return trigger;
                        }
                    }
                }
//                HashMap<Object, Object> trigger = new HashMap<>();
//                trigger.put(payload, payload);
//                System.out.println("  [Trigger] Wrapped in HashMap for hashCode()");
                return trigger;
            }

            // compare() trigger - use PriorityQueue
            if (entryMethod.contains("compare")) {
                PriorityQueue<Object> trigger = new PriorityQueue<>(2, (Comparator) payload);
                trigger.add(new BigInteger("1"));
                trigger.add(new BigInteger("1"));
                System.out.println("  [Trigger] Wrapped in PriorityQueue for compare()");
                return trigger;
            }

        } catch (Exception e) {
            System.out.println("  [Trigger] Failed to wrap in trigger: " + e.getMessage());
        }

        // No trigger needed or trigger failed
        return payload;
    }

    // ========== TESTING ==========

    /**
     * Serialize, deserialize, and check if sinks were triggered
     */
    public static boolean testPayload(Object payload) {
        if (payload == null) {
            return false;
        }

        try {
            // Serialize
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            ObjectOutputStream oos = new ObjectOutputStream(baos);
            oos.writeObject(payload);
            oos.close();

            byte[] serialized = baos.toByteArray();
            System.out.println("  [Test] Serialized payload (" + serialized.length + " bytes)");

            // Deserialize with sink tracking
            SinkTrackingInputStream ois = new SinkTrackingInputStream(
                new ByteArrayInputStream(serialized), SINKS);
            ois.readObject();
            ois.close();

            List<String> triggeredSinks = ois.getTriggeredSinks();
            if (!triggeredSinks.isEmpty()) {
                System.out.println("  [Success] Triggered sinks: " + triggeredSinks);
                return true;
            } else {
                System.out.println("  [Fail] No sinks triggered");
                return false;
            }

        } catch (NotSerializableException | InvalidClassException e) {
            System.out.println("  [Fail] Serialization error: " + e.getMessage());
            return false;
        } catch (NoClassDefFoundError | ClassNotFoundException e) {
            // Missing class during deserialization - treat as failure
            System.out.println("  [Fail] Class loading error during deserialization: " + e.getMessage());
            return false;
        } catch (ExceptionInInitializerError e) {
            // Static initializer failure - treat as failure
            System.out.println("  [Fail] Class initialization error: " + e.getMessage());
            return false;
        } catch (LinkageError e) {
            // Other class linkage errors - treat as failure
            System.out.println("  [Fail] Class linkage error: " + e.getMessage());
            return false;
        } catch (Exception e) {
            // Exception during deserialization might indicate chain triggered
            System.out.println("  [Success] Exception during deserialization: " + e.getClass().getSimpleName());
            return true;
        } catch (Error e) {
            // Catch any other errors (e.g., OutOfMemoryError) and treat as failure
            System.out.println("  [Fail] Error during testing: " + e.getClass().getSimpleName() + " - " + e.getMessage());
            return false;
        }
    }

    /**
     * ObjectInputStream that tracks which sink methods are called during deserialization
     */
    public static class SinkTrackingInputStream extends ObjectInputStream {
        private final List<String> sinks;
        private final List<String> triggeredSinks = new ArrayList<>();

        public SinkTrackingInputStream(InputStream in, List<String> sinks) throws IOException {
            super(in);
            this.sinks = sinks;
            enableResolveObject(true);
        }

        @Override
        protected Object resolveObject(Object obj) throws IOException {
            // Wrap non-JDK objects in proxy to track method calls
            if (obj != null) {
                String className = obj.getClass().getName();
                if (!className.startsWith("java.") && !className.startsWith("javax.") &&
                    obj.getClass().getInterfaces().length > 0) {
                    return wrapInProxy(obj);
                }
            }
            return obj;
        }

        private Object wrapInProxy(Object obj) {
            try {
                return Proxy.newProxyInstance(
                    obj.getClass().getClassLoader(),
                    obj.getClass().getInterfaces(),
                    new SinkCheckingHandler(obj, sinks, triggeredSinks)
                );
            } catch (IllegalArgumentException e) {
                return obj;  // Can't proxy this object
            }
        }

        public List<String> getTriggeredSinks() {
            return triggeredSinks;
        }
    }

    /**
     * InvocationHandler that checks if invoked methods are sinks
     */
    public static class SinkCheckingHandler implements InvocationHandler {
        private final Object target;
        private final List<String> sinks;
        private final List<String> triggeredSinks;

        public SinkCheckingHandler(Object target, List<String> sinks, List<String> triggeredSinks) {
            this.target = target;
            this.sinks = sinks;
            this.triggeredSinks = triggeredSinks;
        }

        @Override
        public Object invoke(Object proxy, Method method, Object[] args) throws Throwable {
            // Build method signature
            StringBuilder sig = new StringBuilder("<");
            sig.append(target.getClass().getName()).append(": ");
            sig.append(method.getReturnType().getName()).append(" ");
            sig.append(method.getName()).append("(");

            Class<?>[] paramTypes = method.getParameterTypes();
            for (int i = 0; i < paramTypes.length; i++) {
                sig.append(paramTypes[i].getName());
                if (i < paramTypes.length - 1) sig.append(",");
            }
            sig.append(")>");

            String signature = sig.toString();
            if (sinks.contains(signature)) {
                System.out.println("  [Sink] Triggered: " + signature);
                triggeredSinks.add(signature);
            }

            return method.invoke(target, args);
        }
    }

    // ========== MAIN VALIDATION LOGIC ==========

    public static void runDynamicValidation(String chainsFile,String configFile) {
        try {
            // Load classpath from configuration

            List<URL> classpath = configFile != null ? loadClasspathFromYaml(configFile) : new ArrayList<URL>();
            URLClassLoader classLoader = new URLClassLoader(
                classpath.toArray(new URL[0]),
                DynamicTester.class.getClassLoader()
            );
            Thread.currentThread().setContextClassLoader(classLoader);

            // Parse chains
            List<List<ChainStep>> chains = parseChains(chainsFile);
            totalChains = chains.size();
            System.out.println("[INFO] Found " + totalChains + " chains to test\n");

            if (chains.isEmpty()) {
                System.out.println("[WARN] No chains found in " + chainsFile);
                return;
            }

            // Test each chain
            for (int i = 0; i < chains.size(); i++) {
                System.out.println("======================================================================");
                System.out.println("Testing Chain " + (i + 1) + "/" + chains.size());
                System.out.println("======================================================================");

                List<ChainStep> chain = chains.get(i);

                // Print chain
                for (ChainStep step : chain) {
                    System.out.println("  -> " + step);
                }
                System.out.println();

                try {
                    // Build payload
                    Object payload = buildPayload(chain, classLoader);

                    if (payload != null) {
                        // Wrap in trigger if this is an entry gadget
                        if (!chain.isEmpty()) {
                            ChainStep entryStep = chain.get(0);
                            payload = wrapInTrigger(payload, entryStep);
                        }

                        // Test payload
                        if (testPayload(payload)) {
                            successfulChains++;
                        } else {
                            partialChains++;
                        }
                    } else {
                        System.out.println("  [Fail] Could not build payload");
                    }

                } catch (NoClassDefFoundError  e) {
                    System.err.println("  [Error] Class loading error: " + e.getMessage());
                    System.err.println("  [Info] Skipping chain and continuing with next...");
                } catch (ExceptionInInitializerError e) {
                    System.err.println("  [Error] Class initialization error: " + e.getMessage());
                    System.err.println("  [Info] Skipping chain and continuing with next...");
                } catch (LinkageError e) {
                    System.err.println("  [Error] Class linkage error: " + e.getMessage());
                    System.err.println("  [Info] Skipping chain and continuing with next...");
                } catch (Exception e) {
                    System.err.println("  [Error] Unexpected exception: " + e.getClass().getSimpleName() + " - " + e.getMessage());
                    e.printStackTrace();
                } catch (Error e) {
                    System.err.println("  [Error] Unexpected error: " + e.getClass().getSimpleName() + " - " + e.getMessage());
                    System.err.println("  [Info] Skipping chain and continuing with next...");
                    // Don't print full stack trace for errors to keep log cleaner
                }

                System.out.println("======================================================================\n");
            }

        } catch (IOException e) {
            System.err.println("[ERROR] Failed to read chains file: " + e.getMessage());
            e.printStackTrace();
        }
    }

    private static List<URL> loadClasspathFromYaml(String yamlFilePath) throws IOException {
        ObjectMapper mapper = new ObjectMapper(new YAMLFactory());
        Map<String, Object> yamlMap = mapper.readValue(new File(yamlFilePath),
                new com.fasterxml.jackson.core.type.TypeReference<Map<String, Object>>() {});

        @SuppressWarnings("unchecked")
        List<String> appClassPath = (List<String>) yamlMap.get("appClassPath");
        List<URL> urls = new ArrayList<>();

        if (appClassPath != null) {
            for (String path : appClassPath) {
                File file = new File(path);
                if (file.isDirectory()) {
                    urls.add(file.toURI().toURL());
                    // Also add all JARs in directory
                    File[] jarFiles = file.listFiles((dir, name) -> name.toLowerCase().endsWith(".jar"));
                    if (jarFiles != null) {
                        for (File jarFile : jarFiles) {
                            urls.add(jarFile.toURI().toURL());
                        }
                    }
                } else {
                    urls.add(file.toURI().toURL());
                }
            }
        }

        return urls;
    }

    private static void printSummary() {
        System.out.println("\n======================================================================");
        System.out.println("                         VALIDATION SUMMARY");
        System.out.println("======================================================================");
        System.out.println("Total chains tested:     " + totalChains);
        System.out.println("Successful validations:  " + successfulChains +
                           " (" + (totalChains > 0 ? (successfulChains * 100 / totalChains) : 0) + "%)");
        System.out.println("Partial validations:     " + partialChains);
        System.out.println("Failed validations:      " + (totalChains - successfulChains - partialChains));
        System.out.println("======================================================================");
    }
}
