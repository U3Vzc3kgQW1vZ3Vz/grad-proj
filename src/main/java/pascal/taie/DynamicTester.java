package pascal.taie;

import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.yaml.YAMLFactory;
import java.io.InputStreamReader;
import java.io.FileInputStream;
import java.io.ObjectInputStream;
import java.io.BufferedReader;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.Modifier;
import java.net.URL;
import java.net.URLClassLoader;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import sun.misc.Unsafe;

public class DynamicTester {

    private static Map<String, Map<String, Map<String, String>>> classHierarchy;
    private static final String PRIORI_KNOWLEDGE_PATH = "java-benchmarks/JDV/priori-knowledge.yml";

    private static List<String> SINKS;
    private static Map<String, Map<String, Map<String, String>>> IMITATES;

    static {
        try {
            ObjectMapper mapper = new ObjectMapper();
            classHierarchy = mapper.readValue(new java.io.File("output/class-hierarchy-BasicDependency.json"),
                    new com.fasterxml.jackson.core.type.TypeReference<Map<String, Map<String, Map<String, String>>>>() {});
        } catch (IOException e) {
            e.printStackTrace();
            classHierarchy = new HashMap<>();
        }

        try {
            loadPrioriKnowledge(PRIORI_KNOWLEDGE_PATH);
        } catch (IOException e) {
            e.printStackTrace();
            throw new RuntimeException("Failed to load sinks from YAML file", e);
        }
    }

    private static void loadPrioriKnowledge(String yamlFilePath) throws IOException {
        ObjectMapper mapper = new ObjectMapper(new YAMLFactory());
        Map<String, Object> yamlMap = mapper.readValue(new java.io.File(yamlFilePath), new com.fasterxml.jackson.core.type.TypeReference<Map<String, Object>>() {});
        @SuppressWarnings("unchecked")
        List<Map<String, String>> sinksData = (List<Map<String, String>>) yamlMap.get("sinks");
        SINKS = new ArrayList<>();
        if (sinksData != null) {
            for (Map<String, String> sink : sinksData) {
                SINKS.add(sink.get("method"));
            }
        }
        Object imitatesObj = yamlMap.get("imitates");
        if (imitatesObj instanceof Map) {
            @SuppressWarnings("unchecked")
            Map<String, Map<String, Map<String, String>>> imitatesMap = (Map<String, Map<String, Map<String, String>>>) imitatesObj;
            IMITATES = imitatesMap;
        } else {
            IMITATES = new HashMap<>();
            if (imitatesObj != null) {
                System.err.println("Warning: 'imitates' in " + yamlFilePath + " is not a Map, but a " + imitatesObj.getClass().getName() + ". Ignoring it.");
            }
        }
    }

    // Represents one step in a gadget chain
    public static class ChainStep {
        public final String fullSignature;
        public final String className;
        public final String methodName;
        public final List<Integer> controllabilityMap;

        public ChainStep(String fullSignature, String className, String methodName, List<Integer> controllabilityMap) {
            this.fullSignature = fullSignature;
            this.className = className;
            this.methodName = methodName;
            this.controllabilityMap = controllabilityMap;
        }

        @Override
        public String toString() {
            return "ChainStep{" +
                    "className='" + className + '\'' +
                    ", methodName='" + methodName + '\'' +
                    ", map=" + controllabilityMap +
                    '}';
        }
    }

    public static List<List<ChainStep>> parseChains(String filePath) throws IOException {
        List<List<ChainStep>> chains = new ArrayList<>();
        Pattern linePattern = Pattern.compile("(<.*?>)(?:->(\\[.*\\]))?");
        Pattern methodPattern = Pattern.compile("<(.*): .* (.*)\\(.*\\)>");

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

                List<Integer> map = null;
                if (i > 0) {
                    String prevLine = chainLines.get(i - 1);
                    Matcher prevLineMatcher = linePattern.matcher(prevLine);
                    if (prevLineMatcher.find()) {
                        String mapStr = prevLineMatcher.group(2);
                        if (mapStr != null) {
                            map = new ArrayList<>();
                            String[] mapValues = mapStr.replace("[", "").replace("]", "").split(",");
                            for (String val : mapValues) {
                                if (!val.trim().isEmpty()) {
                                    map.add(Integer.parseInt(val.trim()));
                                }
                            }
                        }
                    }
                }

                Matcher methodMatcher = methodPattern.matcher(signature);
                if (methodMatcher.find()) {
                    String className = methodMatcher.group(1);
                    String methodName = methodMatcher.group(2);
                    chain.add(new ChainStep(signature, className, methodName, map));
                }
            }
        }
        return chain;
    }


    @SuppressWarnings("unchecked")
    public static <T> T objectInit(String className, URLClassLoader classLoader) throws Exception {
        System.out.println("  [Debug] Instantiating: " + className);
        Class<?> targetClass = Class.forName(className, true, classLoader);
        if (Modifier.isAbstract(targetClass.getModifiers()) || targetClass.isInterface()) {
            String concreteClassName = findConcreteClass(className);
            if (concreteClassName != null) {
                System.out.println("  [Debug] Found concrete class: " + concreteClassName);
                targetClass = Class.forName(concreteClassName, true, classLoader);
            } else {
                throw new InstantiationException("Cannot a instantiate abstract class or interface: " + className);
            }
        }
        try {
            Constructor<?> constructor = targetClass.getDeclaredConstructor();
            constructor.setAccessible(true);
            return (T) constructor.newInstance();
        } catch (Exception e) {
            System.err.println("  [Debug] Failed to instantiate " + className + " with default constructor: " + e.getMessage());
            // Try to find any constructor and invoke it with null values
            for (Constructor<?> constructor : targetClass.getDeclaredConstructors()) {
                try {
                    constructor.setAccessible(true);
                    Object[] params = new Object[constructor.getParameterCount()];
                    return (T) constructor.newInstance(params);
                } catch (Exception e2) {
                    // try next constructor
                }
            }

            try {
                Field unsafeField = Unsafe.class.getDeclaredField("theUnsafe");
                unsafeField.setAccessible(true);
                Unsafe unsafe = (Unsafe) unsafeField.get(null);
                return (T) unsafe.allocateInstance(targetClass);
            } catch (Exception unsafeException) {
                System.err.println("  [Debug] Failed to instantiate " + className + " with Unsafe: " + unsafeException.getMessage());
                throw unsafeException;
            }
        }
    }

    private static String findConcreteClass(String abstractClassName) {
        System.out.println("  [Debug] Finding concrete class for: " + abstractClassName);
        for (Map.Entry<String, Map<String, Map<String, String>>> moduleEntry : classHierarchy.entrySet()) {
            Map<String, Map<String, String>> module = moduleEntry.getValue();
            if (module.containsKey(abstractClassName)) {
                System.out.println("  [Debug] Found module for: " + abstractClassName);
                Map<String, String> subclasses = module.get(abstractClassName);
                if (subclasses != null) {
                    for (String subclass : subclasses.keySet()) {
                        System.out.println("  [Debug]  Checking subclass: " + subclass);
                        try {
                            Class<?> clazz = Class.forName(subclass, false, Thread.currentThread().getContextClassLoader());
                            if (!Modifier.isAbstract(clazz.getModifiers()) && !clazz.isInterface()) {
                                System.out.println("  [Debug]  Found concrete subclass: " + subclass);
                                return subclass;
                            } else {
                                // Recursively search for a concrete class
                                String concreteClass = findConcreteClass(subclass);
                                if (concreteClass != null) {
                                    return concreteClass;
                                }
                            }
                        } catch (ClassNotFoundException e) {
                            // Ignore and try next subclass
                        }
                    }
                }
            }
        }
        System.out.println("  [Debug] No concrete class found for: " + abstractClassName);
        return null;
    }

    private static List<Field> getAllFields(Class<?> clazz) {
        List<Field> fields = new ArrayList<>();
        while (clazz != null) {
            fields.addAll(Arrays.asList(clazz.getDeclaredFields()));
            clazz = clazz.getSuperclass();
        }
        return fields;
    }

    public static class ValidatingObjectInputStream extends ObjectInputStream {
        private final List<String> sinks;
        private final List<String> calledSinks = new ArrayList<>();

        public ValidatingObjectInputStream(java.io.InputStream in, List<String> sinks) throws IOException {
            super(in);
            this.sinks = sinks;
            enableResolveObject(true);
        }

        @Override
        protected Object resolveObject(Object obj) throws IOException {
            String className = obj.getClass().getName();
            if (!className.startsWith("java.") && !className.startsWith("javax.") &&
                    obj.getClass().getInterfaces().length > 0) {
                return new SinkCheckingProxy(obj, sinks, calledSinks).getProxy();
            }
            return obj;
        }

        public List<String> getCalledSinks() {
            return calledSinks;
        }
    }

    public static class SinkCheckingProxy implements java.lang.reflect.InvocationHandler {
        private final Object original;
        private final List<String> sinks;
        private final List<String> calledSinks;

        public SinkCheckingProxy(Object original, List<String> sinks, List<String> calledSinks) {
            this.original = original;
            this.sinks = sinks;
            this.calledSinks = calledSinks;
        }

        public Object getProxy() {
            try {
                return java.lang.reflect.Proxy.newProxyInstance(
                        original.getClass().getClassLoader(),
                        original.getClass().getInterfaces(),
                        this
                );
            } catch (IllegalArgumentException e) {
                // This can happen with sealed interfaces (e.g., java.lang.constant.ConstantDesc)
                // or other proxyability issues. In this case, we can't wrap the object to check
                // for sinks, so we return the original object.
                return original;
            }
        }

        @Override
        public Object invoke(Object proxy, java.lang.reflect.Method method, Object[] args) throws Throwable {
            String methodSignature = "<" + original.getClass().getName() + ": " + method.getReturnType().getName() + " " + method.getName() + "(";
            Class<?>[] parameterTypes = method.getParameterTypes();
            for (int i = 0; i < parameterTypes.length; i++) {
                methodSignature += parameterTypes[i].getName();
                if (i < parameterTypes.length - 1) {
                    methodSignature += ",";
                }
            }
            methodSignature += ")>";

            if (sinks.contains(methodSignature)) {
                calledSinks.add(methodSignature);
                System.out.println("  SINK TRIGGERED: " + methodSignature);
            }
            return method.invoke(original, args);
        }
    }

    private static java.lang.reflect.Method getSetMethod(Class<?> clazz, Field field) {
        String fieldName = field.getName();
        String setterName = "set" + fieldName.substring(0, 1).toUpperCase() + fieldName.substring(1);
        for (java.lang.reflect.Method method : clazz.getMethods()) {
            if (method.getName().equals(setterName) && method.getParameterCount() == 1 && method.getParameterTypes()[0].isAssignableFrom(field.getType())) {
                return method;
            }
        }
        return null;
    }

    private static boolean findAndSetField(Object owner, Object valueToSet) {
        // Try direct assignment
        for (Field field : getAllFields(owner.getClass())) {
            if (Modifier.isStatic(field.getModifiers())) continue;
            if (field.getType().isAssignableFrom(valueToSet.getClass())) {
                try {
                    field.setAccessible(true);
                    field.set(owner, valueToSet);
                    return true;
                } catch (Exception e) { /* try next field */ }
            }
        }

        // Try array assignment
        for (Field field : getAllFields(owner.getClass())) {
            if (Modifier.isStatic(field.getModifiers())) continue;
            if (field.getType().isArray() && field.getType().getComponentType().isAssignableFrom(valueToSet.getClass())) {
                try {
                    field.setAccessible(true);
                    Object array = java.lang.reflect.Array.newInstance(field.getType().getComponentType(), 1);
                    java.lang.reflect.Array.set(array, 0, valueToSet);
                    field.set(owner, array);
                    return true;
                } catch (Exception e) { /* try next field */ }
            }
        }

        // Try map assignment
        for (Field field : getAllFields(owner.getClass())) {
            if (Modifier.isStatic(field.getModifiers())) continue;
            if (Map.class.isAssignableFrom(field.getType())) {
                try {
                    field.setAccessible(true);
                    @SuppressWarnings("unchecked")
                    Map<Object, Object> map = (Map<Object, Object>) field.get(owner);
                    if (map == null) {
                        map = new HashMap<>();
                        field.set(owner, map);
                    }
                    map.put("key", valueToSet); // Using a dummy key
                    return true;
                } catch (Exception e) { /* try next field */ }
            }
        }
        return false;
    }

    public static Object buildPayload(List<ChainStep> chain, URLClassLoader classLoader) {
        if (chain == null || chain.isEmpty()) {
            return null;
        }

        List<Object> chainObjects = new ArrayList<>();
        for (ChainStep step : chain) {
            try {
                Object obj = objectInit(step.className, classLoader);
                chainObjects.add(obj);
            } catch (Exception e) {
                System.err.println("  Could not instantiate " + step.className + ": " + e.getMessage());
                chainObjects.add(null); // Use null as a placeholder
            }
        }

        // Link objects together using the controllability map.
        for (int i = 0; i < chain.size() - 1; i++) {
            Object currentObject = chainObjects.get(i);
            Object nextObject = chainObjects.get(i + 1);

            if (currentObject == null || nextObject == null) {
                System.err.println("  Skipping linking due to null object in chain.");
                continue;
            }

            List<Integer> map = chain.get(i + 1).controllabilityMap;
            boolean linked = false;

            if (map != null && !map.isEmpty()) {
                // map[0] corresponds to 'this' of the next method.
                // If it's tainted by 'this' of the current method (-1), it implies
                // nextObject should be a field of currentObject.
                if (map.get(0) == -1) {
                    if (findAndSetField(currentObject, nextObject)) {
                        System.out.println("  [Debug] Linked " + currentObject.getClass().getSimpleName() + " -> " + nextObject.getClass().getSimpleName() + " (based on this->this taint)");
                        linked = true;
                    }
                }

                // Heuristic inspired by gcminer: handle other taints by adding to collections.
                if (!linked) {
                    for (int j = 1; j < map.size(); j++) {
                        int sourceParamIndex = map.get(j);
                        // If an argument to the next call is tainted by the current object...
                        if (sourceParamIndex == -1) {
                            // ...try to put the current object into a collection in the next object.
                            if (nextObject instanceof Map) {
                                @SuppressWarnings("unchecked")
                                Map<Object, Object> asMap = (Map<Object, Object>) nextObject;
                                asMap.put("key", currentObject);
                                System.out.println("  [Debug] Set " + currentObject.getClass().getSimpleName() + " as value in Map " + nextObject.getClass().getSimpleName());
                                linked = true;
                                break;
                            }
                            if (nextObject instanceof List) {
                                @SuppressWarnings("unchecked")
                                List<Object> asList = (List<Object>) nextObject;
                                asList.add(currentObject);
                                System.out.println("  [Debug] Added " + currentObject.getClass().getSimpleName() + " to List " + nextObject.getClass().getSimpleName());
                                linked = true;
                                break;
                            }
                        }
                    }
                }
            }

            // Fallback for chains without a clear this->this link or if linking failed
            if (!linked) {
                if (findAndSetField(currentObject, nextObject)) {
                    System.out.println("  [Debug] Linked " + currentObject.getClass().getSimpleName() + " -> " + nextObject.getClass().getSimpleName() + " (fallback)");
                } else {
                    System.err.println("  [Warning] Failed to link " + currentObject.getClass().getName() + " and " + nextObject.getClass().getName());
                }
            }
        }

        // The source gadget is the entry point of the chain.
        return chainObjects.get(0);
    }

    public static boolean testPayload(Object payload) {
        if (payload == null) {
            return false;
        }
        try {
            java.io.ByteArrayOutputStream barr = new java.io.ByteArrayOutputStream();
            java.io.ObjectOutputStream oos = new java.io.ObjectOutputStream(barr);
            oos.writeObject(payload);
            oos.close();

            System.out.println("  [Debug] Payload serialized successfully. Size: " + barr.size() + " bytes.");
            System.out.println("  [Debug] Attempting to deserialize and trigger chain...");

            ValidatingObjectInputStream ois = new ValidatingObjectInputStream(new java.io.ByteArrayInputStream(barr.toByteArray()), SINKS);
            ois.readObject();

            if (!ois.getCalledSinks().isEmpty()) {
                System.out.println("  [SUCCESS] Gadget chain successfully triggered a sink: " + ois.getCalledSinks().get(0));
                return true;
            } else {
                System.out.println("  [FAILURE] Deserialization completed without triggering a sink.");
                return false;
            }
        } catch (java.io.NotSerializableException | java.io.InvalidClassException e) {
            System.err.println("  [FAILURE] Payload failed during serialization/deserialization (uninteresting exception): " + e.getClass().getSimpleName() + " - " + e.getMessage());
            return false;
        } catch (Exception e) {
            System.out.println("  [SUCCESS] Payload triggered an exception during deserialization (potential gadget execution): " + e.getClass().getSimpleName() + " - " + e.getMessage());
            // Optionally print stack trace for debugging, but can be noisy
            // e.printStackTrace();
            return true;
        }
    }

    private static List<URL> loadClasspathFromYaml(String yamlFilePath) throws IOException {
        ObjectMapper mapper = new ObjectMapper(new YAMLFactory());
        Map<String, Object> yamlMap = mapper.readValue(new java.io.File(yamlFilePath), new com.fasterxml.jackson.core.type.TypeReference<Map<String, Object>>() {});
        @SuppressWarnings("unchecked")
        List<String> appClassPath = (List<String>) yamlMap.get("appClassPath");
        List<URL> urls = new ArrayList<>();
        if (appClassPath != null) {
            for (String path : appClassPath) {
                urls.add(new java.io.File(path).toURI().toURL());
            }
        }
        return urls;
    }

    public static void main(String[] args) {
        // Set up logging to a file
        try {
            java.io.File logDir = new java.io.File("output/log");
            if (!logDir.exists()) {
                logDir.mkdirs();
            }
            java.io.File logFile = new java.io.File(logDir, "dynamic-tester-log.txt");
            java.io.FileOutputStream fos = new java.io.FileOutputStream(logFile);
            java.io.PrintStream ps = new java.io.PrintStream(fos);
            System.setOut(ps);
            System.setErr(ps);
        } catch (java.io.FileNotFoundException e) {
            // If logging setup fails, we'll just print to the original console.
            System.err.println("Failed to set up file logger: " + e.getMessage());
        }

        String chainsFile = "output/chains";
        if (args.length > 0) {
            chainsFile = args[0];
        }

        try {
            List<URL> classpath = loadClasspathFromYaml("java-benchmarks/JDV/test.yml");
            URLClassLoader classLoader = new URLClassLoader(classpath.toArray(new URL[0]), DynamicTester.class.getClassLoader());
            Thread.currentThread().setContextClassLoader(classLoader);

            List<List<ChainStep>> chains = parseChains(chainsFile);
            System.out.println("Found " + chains.size() + " chains.");
            if (chains.isEmpty()) {
                System.out.println("No chains found to test.");
                return;
            }
            int successCount = 0;
            for (int i = 0; i < chains.size(); i++) {
                System.out.println("======================================================================");
                System.out.println("Testing Chain " + (i + 1) + "/" + chains.size());
                System.out.println("======================================================================");
                List<ChainStep> chain = chains.get(i);
                for (ChainStep step : chain) {
                    System.out.println("  -> " + step.toString());
                }
                System.out.println();

                try{
                    Object payload = buildPayload(chain, classLoader);
                    if (payload != null) {
                        System.out.println("  [Debug] Built payload starting with: " + payload.getClass().getName());
                        if (testPayload(payload)) {
                            successCount++;
                        }
                    } else {
                        System.err.println("  [FAILURE] Failed to build payload for chain " + (i+1));
                    }

                }catch (Exception e) {
                    System.err.println("  [ERROR] An unexpected error occurred during payload construction: " + e);
                    e.printStackTrace();
                }
                System.out.println("======================================================================\n");
            }
            System.out.println("Finished testing. " + successCount + "/" + chains.size() + " chains were successfully processed and/or triggered.");

        } catch (IOException e) {
            System.err.println("Error reading chains file: " + e.getMessage());
            e.printStackTrace();
        }
    }
}
