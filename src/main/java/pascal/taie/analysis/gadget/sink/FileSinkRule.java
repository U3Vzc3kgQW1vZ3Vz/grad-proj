package pascal.taie.analysis.gadget.sink;

import pascal.taie.analysis.gadget.SinkType;
import pascal.taie.ir.exp.Var;
import pascal.taie.ir.stmt.Invoke;
import pascal.taie.language.type.Type;

import java.util.Set;

/**
 * Detects file writing sinks.
 * Adapted from jdd's FileCheckRule for Pascal Taie.
 *
 * Dangerous methods:
 * - java.io.FileOutputStream.write(byte[])
 * - java.io.OutputStream.write(byte[])
 * - File write operations with tainted content
 */
public class FileSinkRule extends AbstractSinkRule {

    public FileSinkRule() {
        super(SinkType.FILE);
    }

    @Override
    public void initialize() {
        // Find ALL implementations of write(byte[]) across FileOutputStream and OutputStream hierarchies
        // This matches the jdd approach using ClassRelationshipUtils.getAllSubMethodSigs
        addAllSubclassSignatures("<java.io.FileOutputStream: void write(byte[])>");
        addAllSubclassSignatures("<java.io.OutputStream: void write(byte[])>");

        // Also find all write(byte[], int, int) implementations
        addAllSubclassSignatures("<java.io.FileOutputStream: void write(byte[],int,int)>");
        addAllSubclassSignatures("<java.io.OutputStream: void write(byte[],int,int)>");

        // And write(int) implementations
        addAllSubclassSignatures("<java.io.FileOutputStream: void write(int)>");
        addAllSubclassSignatures("<java.io.OutputStream: void write(int)>");
    }

    @Override
    protected boolean checkTaintedArguments(Invoke invoke, Set<Var> taintedVars) {
        // For file write operations, check:
        // 1. The content being written (argument) is tainted
        // 2. The file object (receiver) is tainted

        boolean contentTainted = false;
        boolean receiverTainted = isReceiverTainted(invoke, taintedVars);

        // Check if the byte array content argument is tainted
        if (invoke.getInvokeExp().getArgCount() > 0) {
            Var contentArg = invoke.getInvokeExp().getArg(0);
            Type argType = contentArg.getType();

            // Check if it's byte array or similar type
            if (argType.getName().contains("byte[]") || argType.getName().contains("Byte[]")) {
                contentTainted = isTainted(contentArg, taintedVars);
            } else if (argType.getName().equals("int")) {
                // For write(int) methods
                contentTainted = isTainted(contentArg, taintedVars);
            }
        }

        // Both content and receiver should be tainted for a risky file write
        return contentTainted && receiverTainted;
    }

    @Override
    public String getDescription() {
        return "File writing sink (FileOutputStream, OutputStream)";
    }
}
