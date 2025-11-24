package pascal.taie.analysis.gadget.sink;

import pascal.taie.analysis.gadget.SinkType;
import pascal.taie.ir.exp.Var;
import pascal.taie.ir.stmt.Invoke;
import pascal.taie.language.type.Type;

import java.util.Set;

/**
 * Detects file writing and deletion sinks.
 * Adapted from jdd's FileCheckRule for Pascal Taie.
 *
 * Dangerous methods from priori-knowledge.yml:
 * - java.io.FileOutputStream.write(byte[]) - File write
 * - java.io.OutputStream.write(byte[]) - Stream write
 * - java.io.File.delete() - File deletion
 */
public class FileSinkRule extends AbstractSinkRule {

    public FileSinkRule() {
        super(SinkType.FILE);
    }

    @Override
    public void initialize() {
        // From priori-knowledge.yml:
        // - { method: "<java.io.FileOutputStream: void write(byte[])>", index: [base,0], type: "FILE_WRITE" }
        // - { method: "<java.io.OutputStream: void write(byte[])>", index: [base,0], type: "FILE_WRITE" }
        // - { method: "<java.io.OutputStream: void write(byte[],int,int)>", index: [base,0], type: "FILE_WRITE" }

        // Find ALL implementations of write(byte[]) across FileOutputStream and OutputStream hierarchies
        addAllSubclassSignatures("<java.io.FileOutputStream: void write(byte[])>");
        addAllSubclassSignatures("<java.io.OutputStream: void write(byte[])>");

        // Also find all write(byte[], int, int) implementations
        addAllSubclassSignatures("<java.io.FileOutputStream: void write(byte[],int,int)>");
        addAllSubclassSignatures("<java.io.OutputStream: void write(byte[],int,int)>");

        // And write(int) implementations
        addAllSubclassSignatures("<java.io.FileOutputStream: void write(int)>");
        addAllSubclassSignatures("<java.io.OutputStream: void write(int)>");

        // From priori-knowledge.yml:
        // - { method: "<java.io.File: boolean delete()>", index: [base], type: "FILE" }
        addRiskySignature("<java.io.File: boolean delete()>");
        addRiskySignature("<java.io.File: void deleteOnExit()>");
    }

    @Override
    protected boolean checkTaintedArguments(Invoke invoke, Set<Var> taintedVars) {
        String methodSig = invoke.getInvokeExp().getMethodRef().resolve().getSignature();

        // For File.delete() or deleteOnExit(), only check if the File object (receiver) is tainted
        // index: [base] means check the receiver
        if (methodSig.contains("java.io.File: boolean delete()") ||
            methodSig.contains("java.io.File: void deleteOnExit()")) {
            return isReceiverTainted(invoke, taintedVars);
        }

        // For file write operations, check:
        // index: [base, 0] means check both receiver and first argument
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
        return "File operations - write, delete (FileOutputStream, OutputStream, File)";
    }
}
