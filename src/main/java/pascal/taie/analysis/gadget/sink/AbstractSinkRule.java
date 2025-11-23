package pascal.taie.analysis.gadget.sink;

import pascal.taie.analysis.gadget.ClassRelationshipUtils;
import pascal.taie.analysis.gadget.SinkType;
import pascal.taie.ir.exp.InvokeExp;
import pascal.taie.ir.exp.InvokeInstanceExp;
import pascal.taie.ir.exp.Var;
import pascal.taie.ir.stmt.Invoke;
import pascal.taie.language.classes.JMethod;
import pascal.taie.language.type.Type;

import java.util.Collection;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * Abstract base class for sink detection rules.
 * Provides common functionality for checking method signatures and tainted arguments.
 * Uses proper Tai-e API patterns.
 */
public abstract class AbstractSinkRule implements SinkRule {

    protected final SinkType sinkType;
    protected final Set<String> riskyMethodSignatures;
    protected final Set<String> riskyMethodSubsignatures;

    protected AbstractSinkRule(SinkType sinkType) {
        this.sinkType = sinkType;
        this.riskyMethodSignatures = new HashSet<>();
        this.riskyMethodSubsignatures = new HashSet<>();
    }

    @Override
    public SinkType getSinkType() {
        return sinkType;
    }

    @Override
    public boolean isSinkMethod(JMethod method) {
        return riskyMethodSignatures.contains(method.getSignature()) ||
               riskyMethodSubsignatures.contains(method.getSubsignature().toString());
    }

    @Override
    public boolean isRisky(Invoke invoke, Set<Var> taintedVars) {
        InvokeExp invokeExp = invoke.getInvokeExp();
        JMethod targetMethod = invokeExp.getMethodRef().resolve();

        if (!isSinkMethod(targetMethod)) {
            return false;
        }

        return checkTaintedArguments(invoke, taintedVars);
    }

    /**
     * Check if any relevant arguments to the invocation are tainted
     * Subclasses override this to implement specific taint checking logic
     */
    protected abstract boolean checkTaintedArguments(Invoke invoke, Set<Var> taintedVars);

    /**
     * Helper: Check if a variable is tainted
     */
    protected boolean isTainted(Var var, Set<Var> taintedVars) {
        return taintedVars.contains(var);
    }

    /**
     * Helper: Check if argument at index is tainted
     */
    protected boolean isArgumentTainted(Invoke invoke, int index, Set<Var> taintedVars) {
        List<Var> args = invoke.getInvokeExp().getArgs();
        if (index < 0 || index >= args.size()) {
            return false;
        }
        return isTainted(args.get(index), taintedVars);
    }

    /**
     * Helper: Check if 'this' receiver is tainted (for instance calls)
     */
    protected boolean isReceiverTainted(Invoke invoke, Set<Var> taintedVars) {
        InvokeExp invokeExp = invoke.getInvokeExp();
        if (invokeExp instanceof InvokeInstanceExp) {
            Var base = ((InvokeInstanceExp) invokeExp).getBase();
            return isTainted(base, taintedVars);
        }
        return false;
    }

    /**
     * Helper: Get receiver variable (for instance calls)
     */
    protected Var getReceiver(Invoke invoke) {
        InvokeExp invokeExp = invoke.getInvokeExp();
        if (invokeExp instanceof InvokeInstanceExp) {
            return ((InvokeInstanceExp) invokeExp).getBase();
        }
        return null;
    }

    /**
     * Helper: Check if type matches expected dangerous type
     */
    protected boolean isTypeCompatible(Type type, String expectedType) {
        return type.getName().equals(expectedType);
    }

    /**
     * Helper: Add a signature to risky methods
     */
    protected void addRiskySignature(String signature) {
        riskyMethodSignatures.add(signature);
    }

    /**
     * Helper: Add a subsignature to risky methods (for pattern matching across classes)
     */
    protected void addRiskySubsignature(String subsignature) {
        riskyMethodSubsignatures.add(subsignature);
    }

    /**
     * Helper: Add all method signatures across the class hierarchy for a base signature.
     * This finds ALL implementations/overrides in subclasses.
     *
     * Example: addAllSubclassSignatures("<java.io.OutputStream: void write(byte[])>")
     * will add signatures for FileOutputStream.write, BufferedOutputStream.write, etc.
     */
    protected void addAllSubclassSignatures(String baseSignature) {
        Set<String> allSigs = ClassRelationshipUtils.getAllSubMethodSigs(baseSignature);
        riskyMethodSignatures.addAll(allSigs);
    }

    /**
     * Helper: Add all method signatures for methods with a specific name
     * in a class hierarchy.
     *
     * Example: addAllMethodsByName(Arrays.asList("java.lang.ClassLoader"), "defineClass")
     */
    protected void addAllMethodsByName(Collection<String> classNames, String methodName) {
        Set<String> allSigs = ClassRelationshipUtils.getAllSubMethodSigs(classNames, "(" + methodName + ")");
        riskyMethodSignatures.addAll(allSigs);
    }

    /**
     * Helper: Add all method signatures for methods with a specific name,
     * then filter by a predicate (e.g., parameter type matching).
     */
    protected void addAllMethodsByNameFiltered(Collection<String> classNames, String methodName,
                                               java.util.function.Predicate<String> filter) {
        Set<String> allSigs = ClassRelationshipUtils.getAllSubMethodSigs(classNames, "(" + methodName + ")");
        riskyMethodSignatures.addAll(allSigs.stream()
            .filter(filter)
            .collect(java.util.stream.Collectors.toSet()));
    }
}
