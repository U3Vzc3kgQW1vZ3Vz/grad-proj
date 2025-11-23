package pascal.taie.analysis.gadget.sink;

import pascal.taie.analysis.gadget.SinkType;
import pascal.taie.ir.exp.Var;
import pascal.taie.ir.stmt.Invoke;
import pascal.taie.language.classes.JMethod;

import java.util.Set;

/**
 * Interface for sink detection rules.
 * Adapted from jdd's CheckRule for Pascal Taie.
 *
 * Each implementation detects a specific type of dangerous sink
 * (e.g., command execution, JNDI lookup, file operations).
 */
public interface SinkRule {

    /**
     * Get the sink type this rule detects
     */
    SinkType getSinkType();

    /**
     * Check if a method is a potential sink
     */
    boolean isSinkMethod(JMethod method);

    /**
     * Check if the invoke statement at this point is risky
     * (i.e., tainted data reaches a dangerous operation)
     *
     * @param invoke The invoke statement to check
     * @param taintedVars Set of currently tainted variables
     * @return true if this is a risky sink invocation
     */
    boolean isRisky(Invoke invoke, Set<Var> taintedVars);

    /**
     * Get a description of this sink rule
     */
    default String getDescription() {
        return getSinkType().toString() + " sink detection";
    }

    /**
     * Initialize the rule with configuration
     */
    default void initialize() {
        // Override if initialization is needed
    }
}
