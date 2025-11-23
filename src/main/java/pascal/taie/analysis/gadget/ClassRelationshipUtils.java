package pascal.taie.analysis.gadget;

import pascal.taie.World;
import pascal.taie.language.classes.ClassHierarchy;
import pascal.taie.language.classes.JClass;
import pascal.taie.language.classes.JMethod;

import java.util.Collection;
import java.util.HashSet;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Utility class for finding methods across the class hierarchy.
 * Adapted from jdd's ClassRelationshipUtils for Pascal Taie.
 *
 * This provides comprehensive method discovery across all subclasses,
 * which is critical for detecting sink methods that may be implemented
 * in custom subclasses.
 */
public class ClassRelationshipUtils {

    private static final ClassHierarchy hierarchy = World.get().getClassHierarchy();

    /**
     * Get all method signatures for methods matching a specific signature
     * across all subclasses of the declaring class.
     *
     * Example: "<java.io.OutputStream: void write(byte[])>"
     * Returns signatures for all subclasses that implement/override this method.
     *
     * @param baseSignature The base method signature
     * @return Set of all matching method signatures across the hierarchy
     */
    public static Set<String> getAllSubMethodSigs(String baseSignature) {
        Set<String> allSigs = new HashSet<>();

        try {
            // Parse the signature to extract class and subsignature
            // Format: <className: returnType methodName(params)>
            int colonIdx = baseSignature.indexOf(':');
            if (colonIdx == -1) {
                return allSigs;
            }

            String className = baseSignature.substring(1, colonIdx).trim();
            String subsignature = baseSignature.substring(colonIdx + 1, baseSignature.length() - 1).trim();

            // Get the base class
            JClass baseClass = World.get().getClassHierarchy().getClass(className);
            if (baseClass == null) {
                return allSigs;
            }

            // Add the base method signature if it exists
            JMethod baseMethod = findMethodBySubsignature(baseClass, subsignature);
            if (baseMethod != null) {
                allSigs.add(baseMethod.getSignature());
            }

            // Get all subclasses and find matching methods
            Collection<JClass> subClasses = hierarchy.getAllSubclassesOf(baseClass);
            for (JClass subClass : subClasses) {
                JMethod method = findMethodBySubsignature(subClass, subsignature);
                if (method != null) {
                    allSigs.add(method.getSignature());
                }
            }

        } catch (Exception e) {
            // If parsing fails, just return the base signature
            allSigs.add(baseSignature);
        }

        return allSigs;
    }

    /**
     * Get all method signatures for methods with a specific name pattern
     * in a list of classes and their subclasses.
     *
     * @param classNames List of base class names
     * @param methodNamePattern Method name pattern (e.g., "(defineClass)")
     * @return Set of all matching method signatures
     */
    public static Set<String> getAllSubMethodSigs(Collection<String> classNames, String methodNamePattern) {
        Set<String> allSigs = new HashSet<>();

        // Remove parentheses from pattern
        String methodName = methodNamePattern.replace("(", "").replace(")", "");

        for (String className : classNames) {
            try {
                JClass baseClass = hierarchy.getClass(className);
                if (baseClass == null) {
                    continue;
                }

                // Get methods from base class
                allSigs.addAll(getMethodsByName(baseClass, methodName));

                // Get methods from all subclasses
                Collection<JClass> subClasses = hierarchy.getAllSubclassesOf(baseClass);
                for (JClass subClass : subClasses) {
                    allSigs.addAll(getMethodsByName(subClass, methodName));
                }

            } catch (Exception e) {
                // Skip this class if there's an error
                continue;
            }
        }

        return allSigs;
    }

    /**
     * Get all subclasses of a given class (including the class itself).
     *
     * @param className The base class name
     * @return Set of all subclass names
     */
    public static Set<String> getAllSubclasses(String className) {
        Set<String> allClasses = new HashSet<>();

        try {
            JClass baseClass = hierarchy.getClass(className);
            if (baseClass == null) {
                return allClasses;
            }

            allClasses.add(baseClass.getName());

            Collection<JClass> subClasses = hierarchy.getAllSubclassesOf(baseClass);
            allClasses.addAll(subClasses.stream()
                .map(JClass::getName)
                .collect(Collectors.toSet()));

        } catch (Exception e) {
            // Return empty set on error
        }

        return allClasses;
    }

    /**
     * Get all implementors of an interface and their subclasses.
     *
     * @param interfaceName The interface name
     * @return Set of all implementing class names
     */
    public static Set<String> getAllImplementors(String interfaceName) {
        Set<String> allClasses = new HashSet<>();

        try {
            JClass interfaceClass = hierarchy.getClass(interfaceName);
            if (interfaceClass == null || !interfaceClass.isInterface()) {
                return allClasses;
            }

            Collection<JClass> implementors = hierarchy.getAllSubclassesOf(interfaceClass);
            for (JClass impl : implementors) {
                allClasses.add(impl.getName());
                // Also get subclasses of implementors
                Collection<JClass> subClasses = hierarchy.getAllSubclassesOf(impl);
                allClasses.addAll(subClasses.stream()
                    .map(JClass::getName)
                    .collect(Collectors.toSet()));
            }

        } catch (Exception e) {
            // Return empty set on error
        }

        return allClasses;
    }

    /**
     * Get all methods with a specific name from a class.
     *
     * @param jClass The class to search
     * @param methodName The method name to match
     * @return Set of method signatures matching the name
     */
    private static Set<String> getMethodsByName(JClass jClass, String methodName) {
        Set<String> signatures = new HashSet<>();

        for (JMethod method : jClass.getDeclaredMethods()) {
            if (method.getName().equals(methodName)) {
                signatures.add(method.getSignature());
            }
        }

        return signatures;
    }

    /**
     * Find a method in a class by its subsignature.
     *
     * @param jClass The class to search
     * @param subsignature The method subsignature
     * @return The matching method, or null if not found
     */
    private static JMethod findMethodBySubsignature(JClass jClass, String subsignature) {
        for (JMethod method : jClass.getDeclaredMethods()) {
            if (method.getSubsignature().toString().equals(subsignature)) {
                return method;
            }
        }
        return null;
    }

    /**
     * Check if a method signature matches a pattern.
     * Patterns support wildcards for matching method families.
     *
     * @param signature The method signature to check
     * @param pattern The pattern to match against
     * @return true if the signature matches the pattern
     */
    public static boolean matchesPattern(String signature, String pattern) {
        // Simple pattern matching - can be enhanced with regex if needed
        if (pattern.contains("*")) {
            String regex = pattern.replace("*", ".*");
            return signature.matches(regex);
        }
        return signature.equals(pattern);
    }
}
