package pascal.taie.analysis.dataflow.analysis.methodsummary.plugin;

import java.util.List;
import java.util.Map;
import java.util.WeakHashMap;
import java.util.stream.Collectors;

/**
 * Utility class for common signature operations, such as extracting sub-signatures.
 */
public class SignatureUtil {

    private static final Map<String, String> subSignatureCache = new WeakHashMap<>();

    /**
     * Extracts the sub-signature from a full method signature string.
     * The sub-signature is typically the method name and parameters, without the class name and return type.
     * Example: "<java.lang.String: void <init>()>" -> "void <init>()"
     * Results are cached for performance.
     * @param method The full method signature string.
     * @return The extracted sub-signature.
     */
    public static String getSubSignature(String method) {
        return subSignatureCache.computeIfAbsent(method, m -> {
            String sub = m.split(":")[1];
            return sub.substring(1, sub.length() - 1);
        });
    }

    /**
     * Extracts sub-signatures from a list of full method signatures.
     * @param signatures A list of full method signature strings.
     * @return A list of extracted sub-signatures.
     */
    public static List<String> getSubSignatures(List<String> signatures) {
        return signatures.stream()
            .map(SignatureUtil::getSubSignature)
            .collect(Collectors.toList());
    }
}
