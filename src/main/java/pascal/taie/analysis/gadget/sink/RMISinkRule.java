package pascal.taie.analysis.gadget.sink;

import pascal.taie.analysis.gadget.SinkType;
import pascal.taie.ir.exp.Var;
import pascal.taie.ir.stmt.Invoke;

import java.util.Set;

/**
 * Detects RMI (Remote Method Invocation) operation sinks.
 *
 * RMI operations can be dangerous when controlled by attackers,
 * potentially leading to remote code execution or unauthorized access.
 *
 * Dangerous methods from priori-knowledge.yml:
 * - sun.rmi.transport.tcp.TCPTransport.listen() - Starts RMI listener
 *
 * References:
 * - RMI Attacks: https://mogwailabs.de/en/blog/2019/03/attacking-java-rmi-services-after-jep-290/
 * - RMI Security: https://docs.oracle.com/javase/8/docs/technotes/guides/rmi/index.html
 */
public class RMISinkRule extends AbstractSinkRule {

    public RMISinkRule() {
        super(SinkType.RMI);
    }

    @Override
    public void initialize() {
        // From priori-knowledge.yml:
        // - { method: "<sun.rmi.transport.tcp.TCPTransport: void listen()>", index: [base], type: "RMI" }
        addRiskySignature("<sun.rmi.transport.tcp.TCPTransport: void listen()>");

        // Additional RMI sinks
        addRiskySubsignature("void exportObject(java.rmi.Remote,int)");
        addRiskySubsignature("java.rmi.Remote exportObject(java.rmi.Remote,int)");

        // RMI Registry operations
        addRiskySubsignature("void bind(java.lang.String,java.rmi.Remote)");
        addRiskySubsignature("void rebind(java.lang.String,java.rmi.Remote)");

        // RMI connection/transport operations
        addAllSubclassSignatures("<sun.rmi.transport.Transport: void listen()>");
    }

    @Override
    protected boolean checkTaintedArguments(Invoke invoke, Set<Var> taintedVars) {
        String methodSig = invoke.getInvokeExp().getMethodRef().resolve().getSignature();

        // For TCPTransport.listen(), check if receiver is tainted (index: [base])
        if (methodSig.contains("listen()")) {
            return isReceiverTainted(invoke, taintedVars);
        }

        // For exportObject, check Remote object being exported (first or second argument)
        if (methodSig.contains("exportObject(")) {
            boolean arg0Tainted = invoke.getInvokeExp().getArgCount() > 0 &&
                                 isArgumentTainted(invoke, 0, taintedVars);
            boolean arg1Tainted = invoke.getInvokeExp().getArgCount() > 1 &&
                                 isArgumentTainted(invoke, 1, taintedVars);
            return arg0Tainted || arg1Tainted;
        }

        // For bind/rebind, check name and Remote object
        if (methodSig.contains("bind(") || methodSig.contains("rebind(")) {
            boolean nameTainted = isArgumentTainted(invoke, 0, taintedVars);
            boolean objectTainted = invoke.getInvokeExp().getArgCount() > 1 &&
                                   isArgumentTainted(invoke, 1, taintedVars);
            return nameTainted || objectTainted;
        }

        // Default: check receiver
        return isReceiverTainted(invoke, taintedVars);
    }

    @Override
    public String getDescription() {
        return "RMI operations - TCPTransport.listen, exportObject, bind/rebind";
    }
}
