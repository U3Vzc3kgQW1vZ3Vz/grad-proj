package pascal.taie.analysis.gadget.sink;

import pascal.taie.analysis.gadget.SinkType;
import pascal.taie.ir.exp.InvokeExp;
import pascal.taie.ir.exp.Var;
import pascal.taie.ir.stmt.Invoke;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

/**
 * Detects JNDI, RMI, and SPI loading sinks.
 * Adapted from jdd's JNDICheckRule for Pascal Taie.
 *
 * Dangerous methods:
 * - javax.naming.Context.lookup(String)
 * - java.rmi.registry.Registry.lookup(String)
 * - java.util.ServiceLoader.load(Class, ClassLoader)
 * - Remote connection methods
 */
public class JNDISinkRule extends AbstractSinkRule {

    private static final Set<String> RISKY_PARAM_TYPES = new HashSet<>(Arrays.asList(
        "javax.naming.Name",
        "java.lang.String",
        "java.lang.Object",
        "javax.naming.Reference",
        "java.util.Hashtable",
        "javax.naming.Context"
    ));

    public JNDISinkRule() {
        super(SinkType.JNDI);
    }

    @Override
    public void initialize() {
        // JNDI lookup methods - find ALL implementations across hierarchy
        addAllSubclassSignatures("<javax.naming.Context: java.lang.Object lookup(java.lang.String)>");
        addAllSubclassSignatures("<javax.naming.Context: java.lang.Object lookup(javax.naming.Name)>");
        addAllSubclassSignatures("<javax.naming.InitialContext: java.lang.Object lookup(java.lang.String)>");
        addAllSubclassSignatures("<javax.naming.InitialContext: java.lang.Object lookup(javax.naming.Name)>");

        // RMI registry
        addAllSubclassSignatures("<java.rmi.registry.Registry: java.rmi.Remote lookup(java.lang.String)>");
        addAllSubclassSignatures("<java.rmi.registry.LocateRegistry: java.rmi.registry.Registry getRegistry(java.lang.String)>");

        // SPI loading
        addAllSubclassSignatures("<java.util.ServiceLoader: java.util.ServiceLoader load(java.lang.Class,java.lang.ClassLoader)>");
        addAllSubclassSignatures("<java.util.ServiceLoader: java.util.ServiceLoader load(java.lang.Class)>");

        // ObjectFactory
        addAllSubclassSignatures("<javax.naming.spi.ObjectFactory: java.lang.Object getObjectInstance(java.lang.Object,javax.naming.Name,javax.naming.Context,java.util.Hashtable)>");
        addAllSubclassSignatures("<javax.naming.spi.NamingManager: java.lang.Object getObjectInstance(java.lang.Object,javax.naming.Name,javax.naming.Context,java.util.Hashtable)>");

        // Spring JNDI
        addAllSubclassSignatures("<org.springframework.jndi.JndiTemplate: java.lang.Object lookup(java.lang.String)>");

        // Remote connection
        addAllSubclassSignatures("<sun.rmi.transport.LiveRef: sun.rmi.transport.Channel getChannel()>");
        addAllSubclassSignatures("<sun.rmi.transport.LiveRef: void exportObject(sun.rmi.transport.Target)>");

        // URL connections
        addAllSubclassSignatures("<java.net.URLConnection: java.io.InputStream getInputStream()>");
        addAllSubclassSignatures("<java.net.URLConnection: java.lang.Object getContent()>");
        addAllSubclassSignatures("<java.net.URL: java.io.InputStream openStream()>");

        // DNS lookup
        addAllSubclassSignatures("<java.net.InetAddress: java.net.InetAddress getByName(java.lang.String)>");
    }

    @Override
    protected boolean checkTaintedArguments(Invoke invoke, Set<Var> taintedVars) {
        InvokeExp invokeExp = invoke.getInvokeExp();
        String methodSig = invokeExp.getMethodRef().getSubsignature().toString();
        // JNDI lookup - check name/string parameter
        if (methodSig.contains("lookup") || methodSig.contains("getObjectInstance")) {
            for (int i = 0; i < invokeExp.getArgCount(); i++) {
                String paramType = invokeExp.getArg(i).getType().getName();
                if (RISKY_PARAM_TYPES.contains(paramType) && isArgumentTainted(invoke, i, taintedVars)) {
                    return true;
                }
            }
        }

        // SPI loading - check ClassLoader parameter (second argument)
        if (methodSig.contains("ServiceLoader") && methodSig.contains("load")) {
            if (invokeExp.getArgCount() >= 2 && isArgumentTainted(invoke, 1, taintedVars)) {
                return true;
            }
        }

        // Remote connection methods - check receiver
        if (methodSig.contains("LiveRef") || methodSig.contains("URLConnection") || methodSig.contains("URL")) {
            // Check if receiver is tainted
            if (isReceiverTainted(invoke, taintedVars)) {
                return true;
            }
        }

        // DNS lookup - check hostname parameter
        if (methodSig.contains("getByName")) {
            if (invokeExp.getArgCount() > 0 && isArgumentTainted(invoke, 0, taintedVars)) {
                return true;
            }
        }

        return false;
    }

    @Override
    public String getDescription() {
        return "JNDI/RMI/SPI loading sink";
    }
}
