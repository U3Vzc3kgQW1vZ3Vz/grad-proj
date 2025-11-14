/*
 * Tai-e: A Static Analysis Framework for Java
 *
 * Copyright (C) 2022 Tian Tan <tiantan@nju.edu.cn>
 * Copyright (C) 2022 Yue Li <yueli@nju.edu.cn>
 *
 * This file is part of Tai-e.
 *
 * Tai-e is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License
 * as published by the Free Software Foundation, either version 3
 * of the License, or (at your option) any later version.
 *
 * Tai-e is distributed in the hope that it will be useful,but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General
 * Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with Tai-e. If not, see <https://www.gnu.org/licenses/>.
 */
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
        Pattern methodPattern = Pattern.compile("<(.*): .* (.*)\\(.*\\)>");
        // Find the separator ->[map]
        Pattern separatorPattern = Pattern.compile("->(\\[[^\\]]*\\])");

        try (BufferedReader reader = new BufferedReader(new FileReader(filePath, StandardCharsets.UTF_8))) {
            String line;
            List<ChainStep> currentChain = new ArrayList<>();
            while ((line = reader.readLine()) != null) {
                line = line.trim();
                if (line.isEmpty()) {
                    if (!currentChain.isEmpty()) {
                        chains.add(new ArrayList<>(currentChain));
                        currentChain.clear();
                    }
                } else {
                    Matcher separatorMatcher = separatorPattern.matcher(line);
                    if (separatorMatcher.find()) {
                        String mapStr = separatorMatcher.group(1);
                        String sig1 = line.substring(0, separatorMatcher.start()).trim();
                        String sig2 = line.substring(separatorMatcher.end()).trim();

                        // If the chain is empty, add the source of the first link
                        if (currentChain.isEmpty()) {
                            Matcher m1 = methodPattern.matcher(sig1);
                            if (m1.find()) {
                                currentChain.add(new ChainStep(sig1, m1.group(1), m1.group(2), null));
                            } else {
                                continue; // Malformed line
                            }
                        }

                        // Add the destination of the link
                        Matcher m2 = methodPattern.matcher(sig2);
                        if (m2.find()) {
                            List<Integer> map = new ArrayList<>();
                            String[] mapValues = mapStr.replace("[", "").replace("]", "").split(",");
                            for (String val : mapValues) {
                                if (!val.trim().isEmpty()) {
                                    map.add(Integer.parseInt(val.trim()));
                                }
                            }
                            currentChain.add(new ChainStep(sig2, m2.group(1), m2.group(2), map));
                        }
                    }
                }
            }
            // Add the last chain if the file doesn't end with a blank line
            if (!currentChain.isEmpty()) {
                chains.add(currentChain);
            }
        }
        return chains;
    }


    @SuppressWarnings("unchecked")
    public static <T> T objectInit(String className, URLClassLoader classLoader) throws Exception {
        Class<?> targetClass = Class.forName(className, true, classLoader);
        if (Modifier.isAbstract(targetClass.getModifiers()) || targetClass.isInterface()) {
            String concreteClassName = findConcreteClass(className);
            if (concreteClassName != null) {
                targetClass = Class.forName(concreteClassName, true, classLoader);
            } else {
                throw new InstantiationException("Cannot instantiate abstract class or interface: " + className);
            }
        }
        try {
            Constructor<?> constructor = targetClass.getDeclaredConstructor();
            constructor.setAccessible(true);
            return (T) constructor.newInstance();
        } catch (NoSuchMethodException e) {
            Field unsafeField = Unsafe.class.getDeclaredField("theUnsafe");
            unsafeField.setAccessible(true);
            Unsafe unsafe = (Unsafe) unsafeField.get(null);
            return (T) unsafe.allocateInstance(targetClass);
        }
    }

    private static String findConcreteClass(String abstractClassName) {
        for (Map<String, Map<String, String>> module : classHierarchy.values()) {
            if (module.containsKey(abstractClassName)) {
                Map<String, String> subclasses = module.get(abstractClassName);
                if (!subclasses.isEmpty()) {
                    // Just return the first one for now.
                    return subclasses.keySet().iterator().next();
                }
            }
        }
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

        List<Object> chainObjects = new ArrayList<>(Collections.nCopies(chain.size(), null));

        // 1. Instantiate all objects in reverse order (sink to source)
        for (int i = chain.size() - 1; i >= 0; i--) {
            ChainStep step = chain.get(i);
            try {
                // Skip special classes that shouldn't be instantiated directly
                if (!step.className.equals("java.lang.Class") && !step.className.equals("java.lang.reflect.Method")) {
                    Object obj = objectInit(step.className, classLoader);
                    chainObjects.set(i, obj);
                }
            } catch (Exception e) {
                System.err.println("  Could not instantiate " + step.className + ": " + e.getMessage());
                return null; // If one object fails, the chain is broken.
            }
        }

        // 2. Link objects together using the controllability map, iterating forward.
        for (int i = 0; i < chain.size() - 1; i++) {
            ChainStep nextStep = chain.get(i + 1);
            List<Integer> map = nextStep.controllabilityMap;

            if (map == null || map.isEmpty()) {
                continue;
            }

            Object currentThis = chainObjects.get(i);
            Object nextThis = chainObjects.get(i + 1);

            if (currentThis == null || nextThis == null) {
                System.err.println("  Skipping linking due to null object.");
                continue;
            }

            // A value of -1 at index 0 means the 'this' of the next call is tainted
            // by the 'this' of the current call, implying it's a field.
            if (map.get(0) == -1) {
                boolean linked = findAndSetField(currentThis, nextThis);
                if (linked) {
                    System.out.println("  Linked " + currentThis.getClass().getName() + " -> " + nextThis.getClass().getName() + " via field assignment.");
                } else {
                    System.err.println("  Failed to link " + currentThis.getClass().getName() + " and " + nextThis.getClass().getName() + " using controllability map.");
                }
            }
        }
        return chainObjects.stream().filter(Objects::nonNull).findFirst().orElse(null);
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
            ValidatingObjectInputStream ois = new ValidatingObjectInputStream(new java.io.ByteArrayInputStream(barr.toByteArray()), SINKS);
            ois.readObject();
            return !ois.getCalledSinks().isEmpty();
        } catch (NullPointerException | java.io.NotSerializableException | java.io.InvalidClassException e) {
            // These exceptions often occur with generated payloads and aren't indicative of a successful gadget chain.
            System.err.println("  Payload failed during serialization: " + e.getClass().getSimpleName() + " - " + e.getMessage());
            return false;
        } catch (Exception e) {
            // Other exceptions might be part of the exploit (e.g., ClassCastException from the gadget).
            System.err.println("  Payload triggered an exception during deserialization: " + e);
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
                System.out.println("Chain " + (i + 1) + ":");
                List<ChainStep> chain = chains.get(i);
                for (ChainStep step : chain) {
                    System.out.println("  " + step);
                }

                try{
                    Object payload = buildPayload(chain, classLoader);
                    if (payload != null) {
                        System.out.println("  Built payload starting with: " + payload.getClass().getName());
                        if (testPayload(payload)) {
                            System.out.println("  Test finished for chain " + (i+1));
                            successCount++;
                        }
                    } else {
                        System.err.println("  Failed to build payload for chain " + (i+1));
                    }

                }catch (Exception e) {
                    System.err.println("  Could not build payload: " + e);
                    e.printStackTrace();
                }

                System.out.println();
            }
            System.out.println("Finished testing. " + successCount + "/" + chains.size() + " chains were processed.");

        } catch (IOException e) {
            System.err.println("Error reading chains file: " + e.getMessage());
            e.printStackTrace();
        }
    }
}
