package pascal.taie.analysis.gadget;

/**
 * Enumeration of dangerous sink types in gadget chains.
 * Adapted from jdd's SinkType for Pascal Taie.
 */
public enum SinkType {
    /**
     * Command execution sinks (Runtime.exec, ProcessBuilder, etc.)
     */
    EXEC,

    /**
     * JNDI lookup, RMI registry, SPI loading
     */
    JNDI,

    /**
     * Reflection-based method invocation (Method.invoke)
     */
    INVOKE,

    /**
     * File operations (read, write, delete)
     */
    FILE,

    /**
     * Class loading operations
     */
    CLASS_LOADER,

    /**
     * Second-order deserialization
     */
    SECOND_DESERIALIZATION,

    /**
     * Custom sink types (extensible)
     */
    CUSTOM;

    @Override
    public String toString() {
        return name();
    }
}
