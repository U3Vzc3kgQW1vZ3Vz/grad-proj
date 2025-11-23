package pascal.taie.analysis.gadget.sink;

import pascal.taie.World;
import pascal.taie.analysis.gadget.SinkType;
import pascal.taie.ir.exp.Var;
import pascal.taie.ir.stmt.Invoke;
import pascal.taie.language.classes.JClass;
import pascal.taie.language.classes.JMethod;
import pascal.taie.language.type.Type;

import java.util.Arrays;
import java.util.Collection;
import java.util.HashSet;
import java.util.Set;

/**
 * Detects custom framework-specific sinks.
 * Adapted from jdd's CustomCheckRule for Pascal Taie.
 *
 * Detects sinks in various frameworks:
 * - Groovy: Closure.call()
 * - Bsh (BeanShell): BshMethod.invoke()
 * - MyFaces: ValueExpression.getValue()
 * - Clojure: eval_opt
 * - Fastjson: Object write methods
 */
public class CustomSinkRule extends AbstractSinkRule {

    public CustomSinkRule() {
        super(SinkType.CUSTOM);
    }

    @Override
    public void initialize() {
        // Groovy - Closure.call - find ALL implementations across hierarchy
        addAllSubclassSignatures("<groovy.lang.Closure: java.lang.Object call()>");
        addAllSubclassSignatures("<groovy.lang.Closure: java.lang.Object call(java.lang.Object[])>");
        addAllSubclassSignatures("<groovy.lang.Closure: java.lang.Object call(java.lang.Object)>");

        // BeanShell - BshMethod.invoke
        addAllSubclassSignatures("<bsh.BshMethod: java.lang.Object invoke(java.lang.Object[],bsh.Interpreter,bsh.CallStack,bsh.SimpleNode)>");
        addAllSubclassSignatures("<bsh.BshMethod: java.lang.Object invoke(java.lang.Object[],bsh.Interpreter,bsh.CallStack,bsh.SimpleNode,boolean)>");

        // MyFaces - ValueExpression.getValue
        addAllSubclassSignatures("<javax.el.ValueExpression: java.lang.Object getValue(javax.el.ELContext)>");

        // Clojure - eval_opt
        addAllSubclassSignatures("<clojure.main$eval_opt: java.lang.Object invokeStatic(java.lang.Object)>");

        // Fastjson - dynamically find all write methods in fastjson Object* classes
        initializeFastjsonSinks();
    }

    /**
     * Initialize Fastjson sinks by finding all write methods in fastjson classes
     * that contain "Object" in the name and have java.lang.Object as second parameter.
     */
    private void initializeFastjsonSinks() {
        try {
            // Get all classes in the program
            Collection<JClass> allClasses = World.get().getClassHierarchy().allClasses().toList();

            for (JClass jClass : allClasses) {
                String className = jClass.getName();

                // Check if class is in fastjson package and contains "Object"
                if (className.contains("fastjson") && className.contains("Object")) {
                    // Check all methods named "write"
                    for (JMethod method : jClass.getDeclaredMethods()) {
                        if (method.getName().equals("write") &&
                            method.getParamCount() > 1 &&
                            method.getParamType(1).getName().equals("java.lang.Object")) {
                            addRiskySignature(method.getSignature());
                        }
                    }
                }
            }
        } catch (Exception e) {
            // If fastjson classes don't exist, skip
        }
    }

    @Override
    protected boolean checkTaintedArguments(Invoke invoke, Set<Var> taintedVars) {
        String methodSig = invoke.getInvokeExp().getMethodRef().getSubsignature().toString();

        // Groovy Closure.call - check receiver (Closure object) is tainted
        if (methodSig.contains("groovy.lang.Closure") && methodSig.contains("call")) {
            return checkGroovyClosure(invoke, taintedVars);
        }

        // BeanShell BshMethod.invoke - check receiver is tainted
        else if (methodSig.contains("bsh.BshMethod") && methodSig.contains("invoke")) {
            return isReceiverTainted(invoke, taintedVars);
        }

        // MyFaces ValueExpression.getValue - check receiver is tainted
        else if (methodSig.contains("javax.el.ValueExpression") && methodSig.contains("getValue")) {
            return isReceiverTainted(invoke, taintedVars);
        }

        // Clojure eval_opt - check receiver and argument are tainted
        else if (methodSig.contains("clojure.main$eval_opt") && methodSig.contains("invokeStatic")) {
            if (invoke.getInvokeExp().getArgCount() > 0) {
                Var arg0 = invoke.getInvokeExp().getArg(0);
                return isTainted(arg0, taintedVars) && isReceiverTainted(invoke, taintedVars);
            }
        }

        // Fastjson - check object write methods
        else if (methodSig.contains("fastjson") && methodSig.contains("Object") && methodSig.contains("write")) {
            return checkFastjsonWrite(invoke, taintedVars);
        }

        return false;
    }

    /**
     * Check Groovy Closure.call - receiver must be tainted and type must be Closure
     */
    private boolean checkGroovyClosure(Invoke invoke, Set<Var> taintedVars) {
        if (!isReceiverTainted(invoke, taintedVars)) {
            return false;
        }

        // Check type is actually Closure
        Var receiver = getReceiver(invoke);
        if (receiver != null) {
            Type receiverType = receiver.getType();
            String typeName = receiverType.getName();
            return typeName.equals("groovy.lang.Closure") ||
                   typeName.equals("org.codehaus.groovy.runtime.MethodClosure");
        }

        return false;
    }

    /**
     * Check Fastjson write - second argument (object) must be tainted
     */
    private boolean checkFastjsonWrite(Invoke invoke, Set<Var> taintedVars) {
        // Fastjson write methods have Object as second parameter
        if (invoke.getInvokeExp().getArgCount() > 1) {
            Var objArg = invoke.getInvokeExp().getArg(1);
            Type argType = objArg.getType();

            // Check it's Object type and tainted
            if (argType.getName().equals("java.lang.Object")) {
                return isTainted(objArg, taintedVars);
            }
        }
        return false;
    }

    @Override
    public String getDescription() {
        return "Custom framework sinks (Groovy, Bsh, MyFaces, Clojure, Fastjson)";
    }
}
