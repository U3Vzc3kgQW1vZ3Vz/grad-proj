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
     * File write and delete operations
     */
    FILE,

    /**
     * File read operations (FileInputStream, etc.)
     */
    FILE_READ,

    /**
     * Class loading operations
     */
    CLASS_LOADER,

    /**
     * Second-order deserialization
     */
    SECOND_DESERIALIZATION,

    /**
     * Server-Side Request Forgery (URL.openConnection, HTTP requests)
     */
    SSRF,

    /**
     * SQL Injection (Statement.execute, PreparedStatement, etc.)
     */
    SQL,

    /**
     * Expression Language Injection (EL, SpEL, OGNL, MVEL)
     */
    EL_INJECTION,

    /**
     * Code/Script Execution (ScriptEngine, Groovy, Python, Clojure)
     */
    CODE_INJECTION,

    /**
     * Path Traversal (File constructors, Paths.get)
     */
    PATH_TRAVERSAL,

    /**
     * RMI operations (RMI transport, remote invocation)
     */
    RMI,

    /**
     * XPath Injection
     */
    XPATH,

    /**
     * LDAP Injection
     */
    LDAP,

    /**
     * XML External Entity (XXE)
     */
    XXE,

    /**
     * Template Injection (Freemarker, Velocity, etc.)
     */
    TEMPLATE_INJECTION,

    /**
     * Unsafe Native Operations (sun.misc.Unsafe)
     */
    UNSAFE,

    /**
     * Custom sink types (extensible)
     */
    CUSTOM;

    @Override
    public String toString() {
        return name();
    }
}
