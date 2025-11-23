package pascal.taie.analysis.gadget.sink;

import pascal.taie.analysis.gadget.SinkType;
import pascal.taie.ir.exp.Var;
import pascal.taie.ir.stmt.Invoke;

import java.util.Set;

/**
 * Detects second-order deserialization sinks.
 * Adapted from jdd's SecondDesCheckRule for Pascal Taie.
 *
 * Dangerous pattern:
 * - ObjectInputStream constructed from tainted data
 * - Then readObject() is called on that stream
 *
 * This represents a second deserialization where the first deserialization
 * produced byte[] data that is then deserialized again.
 */
public class SecondDeserializationSinkRule extends AbstractSinkRule {

    public SecondDeserializationSinkRule() {
        super(SinkType.SECOND_DESERIALIZATION);
    }

    @Override
    public void initialize() {
        // Find ALL readObject() implementations across ObjectInputStream hierarchy
        // This matches the jdd approach using ClassRelationshipUtils.getAllSubMethodSigs
        addAllSubclassSignatures("<java.io.ObjectInputStream: java.lang.Object readObject()>");

        // Also check readUnshared which can trigger deserialization
        addAllSubclassSignatures("<java.io.ObjectInputStream: java.lang.Object readUnshared()>");
    }

    @Override
    protected boolean checkTaintedArguments(Invoke invoke, Set<Var> taintedVars) {
        // For second-order deserialization, the ObjectInputStream receiver must be tainted
        // This indicates the stream was created from attacker-controlled byte[]
        return isReceiverTainted(invoke, taintedVars);
    }

    @Override
    public String getDescription() {
        return "Second-order deserialization sink (ObjectInputStream.readObject)";
    }
}
