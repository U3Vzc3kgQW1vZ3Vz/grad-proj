package pascal.taie.analysis.gadget.sink;

import pascal.taie.analysis.gadget.SinkType;
import pascal.taie.ir.exp.Var;
import pascal.taie.ir.stmt.Invoke;

import java.util.Set;

/**
 * Detects reflection-based method invocation sinks.
 * Adapted from jdd's InvokeCheckRule for Pascal Taie.
 *
 * Dangerous methods:
 * - java.lang.reflect.Method.invoke(Object, Object[])
 * - java.lang.reflect.Constructor.newInstance(Object[])
 */
public class InvokeSinkRule extends AbstractSinkRule {

    public InvokeSinkRule() {
        super(SinkType.INVOKE);
    }

    @Override
    public void initialize() {
        // Method.invoke - find ALL implementations across hierarchy
        addAllSubclassSignatures("<java.lang.reflect.Method: java.lang.Object invoke(java.lang.Object,java.lang.Object[])>");

        // Constructor.newInstance
        addAllSubclassSignatures("<java.lang.reflect.Constructor: java.lang.Object newInstance(java.lang.Object[])>");

        // Class.newInstance (deprecated but still dangerous)
        addAllSubclassSignatures("<java.lang.Class: java.lang.Object newInstance()>");
    }

    @Override
    protected boolean checkTaintedArguments(Invoke invoke, Set<Var> taintedVars) {
        String methodSig = invoke.getInvokeExp().getMethodRef().getSubsignature().toString();

        // For Method.invoke, check if the Method object itself is tainted
        // or if the target object (first arg) is tainted
        if (methodSig.contains("invoke")) {
            // Check receiver (the Method object)
            if (isReceiverTainted(invoke, taintedVars)) {
                return true;
            }
            // Check first argument (target object)
            if (invoke.getInvokeExp().getArgCount() > 0 && isArgumentTainted(invoke, 0, taintedVars)) {
                return true;
            }
        }

        // For Constructor.newInstance or Class.newInstance, check if the object is tainted
        if (methodSig.contains("newInstance")) {
            // Check receiver (the Constructor or Class object)
            if (isReceiverTainted(invoke, taintedVars)) {
                return true;
            }
        }

        return false;
    }

    @Override
    public String getDescription() {
        return "Reflection invocation sink (Method.invoke, Constructor.newInstance)";
    }
}
