package pascal.taie.analysis.gadget.sink;

import pascal.taie.analysis.gadget.SinkType;
import pascal.taie.ir.exp.Var;
import pascal.taie.ir.stmt.Invoke;

import java.util.Set;

/**
 * Detects Expression Language (EL) and Script/Code Injection sinks.
 *
 * These sinks allow arbitrary code execution through dynamic script evaluation.
 *
 * Dangerous methods from priori-knowledge.yml:
 * - javax.el.ValueExpression.getValue(ELContext) - EL injection
 * - clojure.lang.Compiler.eval(Object) - Clojure code execution
 * - javax.script.ScriptEngineManager.&lt;init&gt;(ClassLoader) - ScriptEngine loading
 * - org.python.core.PyBaseCode.call(...) - Jython code execution
 *
 * References:
 * - EL Injection: https://owasp.org/www-community/vulnerabilities/Expression_Language_Injection
 * - Script Engine Security: https://docs.oracle.com/javase/8/docs/technotes/guides/scripting/prog_guide/security.html
 */
public class CodeInjectionSinkRule extends AbstractSinkRule {

    public CodeInjectionSinkRule() {
        super(SinkType.CODE_INJECTION);
    }

    @Override
    public void initialize() {
        // From priori-knowledge.yml:
        // - { method: "<javax.el.ValueExpression: java.lang.Object getValue(javax.el.ELContext)>", index: [base], type: "EL_INJECTION" }
        addAllSubclassSignatures("<javax.el.ValueExpression: java.lang.Object getValue(javax.el.ELContext)>");
        addAllSubclassSignatures("<javax.el.MethodExpression: java.lang.Object invoke(javax.el.ELContext,java.lang.Object[])>");

        // From priori-knowledge.yml:
        // - { method: "<clojure.lang.Compiler: java.lang.Object eval(java.lang.Object)>", index: [0], type: "CODE_INJECTION" }
        addAllSubclassSignatures("<clojure.lang.Compiler: java.lang.Object eval(java.lang.Object)>");
        addAllSubclassSignatures("<clojure.lang.Compiler: java.lang.Object eval(java.lang.Object,boolean)>");

        // From priori-knowledge.yml:
        // - { method: "<javax.script.ScriptEngineManager: void <init>(java.lang.ClassLoader)>", index: [0], type: "SCRIPT_ENGINE" }
        addAllSubclassSignatures("<javax.script.ScriptEngineManager: void <init>(java.lang.ClassLoader)>");
        // ScriptEngine is an interface
        addAllSubclassSignatures("<javax.script.ScriptEngine: java.lang.Object eval(java.lang.String)>");
        addAllSubclassSignatures("<javax.script.ScriptEngine: java.lang.Object eval(java.io.Reader)>");

        // From priori-knowledge.yml:
        // - { method: "<org.python.core.PyBaseCode: org.python.core.PyObject call(...)>", index: [base,1], type: "CODE_INJECTION" }
        // PyBaseCode methods - use subclass finding
        addAllSubclassSignatures("<org.python.core.PyBaseCode: org.python.core.PyObject call(org.python.core.ThreadState,org.python.core.PyObject[],java.lang.String[],org.python.core.PyObject,org.python.core.PyObject[],org.python.core.PyObject)>");
        addAllSubclassSignatures("<org.python.core.PyBaseCode: org.python.core.PyObject call(org.python.core.ThreadState)>");
        addAllSubclassSignatures("<org.python.core.PyBaseCode: org.python.core.PyObject call(org.python.core.ThreadState,org.python.core.PyObject)>");

        // Groovy
        addAllSubclassSignatures("<groovy.lang.Script: java.lang.Object evaluate(java.lang.String)>");
        addAllSubclassSignatures("<groovy.util.Eval: java.lang.Object me(java.lang.String)>");

        // SpEL (Spring Expression Language)
        addAllSubclassSignatures("<org.springframework.expression.ExpressionParser: org.springframework.expression.Expression parseExpression(java.lang.String)>");
        addAllSubclassSignatures("<org.springframework.expression.Expression: java.lang.Object getValue()>");
        addAllSubclassSignatures("<org.springframework.expression.Expression: java.lang.Object getValue(java.lang.Object)>");

        // OGNL (Struts)
        addAllSubclassSignatures("<ognl.Ognl: java.lang.Object getValue(java.lang.Object,java.lang.Object)>");
        addAllSubclassSignatures("<ognl.Ognl: void setValue(java.lang.Object,java.lang.Object,java.lang.Object)>");

        // MVEL
        addAllSubclassSignatures("<org.mvel2.MVEL: java.lang.Object eval(java.lang.String)>");
        addAllSubclassSignatures("<org.mvel2.MVEL: java.lang.Object eval(java.lang.String,java.lang.Object)>");
    }

    @Override
    protected boolean checkTaintedArguments(Invoke invoke, Set<Var> taintedVars) {
        String methodSig = invoke.getInvokeExp().getMethodRef().resolve().getSignature();

        // javax.el.ValueExpression.getValue(ELContext) - check receiver (base)
        if (methodSig.contains("javax.el.ValueExpression: java.lang.Object getValue") ||
            methodSig.contains("javax.el.MethodExpression: java.lang.Object invoke")) {
            return isReceiverTainted(invoke, taintedVars);
        }

        // Clojure Compiler.eval(Object) - check first argument
        if (methodSig.contains("clojure.lang.Compiler: java.lang.Object eval")) {
            return isArgumentTainted(invoke, 0, taintedVars);
        }

        // ScriptEngineManager constructor - check ClassLoader argument
        if (methodSig.contains("javax.script.ScriptEngineManager: void <init>")) {
            return isArgumentTainted(invoke, 0, taintedVars);
        }

        // ScriptEngine.eval - check script string argument
        if (methodSig.contains("javax.script.ScriptEngine: java.lang.Object eval")) {
            return isArgumentTainted(invoke, 0, taintedVars);
        }

        // PyBaseCode.call - check receiver and second argument (index [base, 1])
        if (methodSig.contains("org.python.core.PyBaseCode") && methodSig.contains("call(")) {
            boolean receiverTainted = isReceiverTainted(invoke, taintedVars);
            boolean arg1Tainted = invoke.getInvokeExp().getArgCount() > 1 &&
                                  isArgumentTainted(invoke, 1, taintedVars);
            return receiverTainted || arg1Tainted;
        }

        // For generic eval/parseExpression/getValue methods, check first argument or receiver
        if (methodSig.contains("eval(") || methodSig.contains("parseExpression(") ||
            methodSig.contains("getValue(") || methodSig.contains("parseClass(")) {
            // Check first argument for static methods, receiver for instance methods
            boolean argTainted = invoke.getInvokeExp().getArgCount() > 0 &&
                                isArgumentTainted(invoke, 0, taintedVars);
            return isReceiverTainted(invoke, taintedVars) || argTainted;
        }

        // Default: check first argument
        return isArgumentTainted(invoke, 0, taintedVars);
    }

    @Override
    public String getDescription() {
        return "Code/Script Injection - EL, ScriptEngine, Clojure, Jython, Groovy, SpEL, OGNL, MVEL";
    }
}
