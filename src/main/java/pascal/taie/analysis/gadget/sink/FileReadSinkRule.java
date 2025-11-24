package pascal.taie.analysis.gadget.sink;

import pascal.taie.analysis.gadget.SinkType;
import pascal.taie.ir.exp.Var;
import pascal.taie.ir.stmt.Invoke;

import java.util.Set;

/**
 * Detects file reading sinks.
 *
 * File read operations can be dangerous when the file path is controlled
 * by an attacker, potentially leading to unauthorized file access.
 *
 * Dangerous methods from priori-knowledge.yml:
 * - java.io.FileInputStream.read(byte[], int, int) - Read file content
 *
 * References:
 * - Path Traversal: https://owasp.org/www-community/attacks/Path_Traversal
 */
public class FileReadSinkRule extends AbstractSinkRule {

    public FileReadSinkRule() {
        super(SinkType.FILE_READ);
    }

    @Override
    public void initialize() {
        // From priori-knowledge.yml:
        // - { method: "<java.io.FileInputStream: int read(byte[],int,int)>", index: [base], type: "FILE_READ" }
        addRiskySignature("<java.io.FileInputStream: int read(byte[],int,int)>");
        addRiskySignature("<java.io.FileInputStream: int read(byte[])>");
        addRiskySignature("<java.io.FileInputStream: int read()>");

        // All FileInputStream implementations
        addAllSubclassSignatures("<java.io.FileInputStream: int read()>");
        addAllSubclassSignatures("<java.io.FileInputStream: int read(byte[])>");
        addAllSubclassSignatures("<java.io.FileInputStream: int read(byte[],int,int)>");

        // Related file operations
        addRiskySignature("<java.io.RandomAccessFile: int read(byte[],int,int)>");
        addRiskySignature("<java.io.RandomAccessFile: int read(byte[])>");
        addRiskySignature("<java.io.RandomAccessFile: int read()>");

        // NIO file reads
        addRiskySubsignature("int read(java.nio.ByteBuffer)");
    }

    @Override
    protected boolean checkTaintedArguments(Invoke invoke, Set<Var> taintedVars) {
        // For FileInputStream.read(), check if receiver (the FileInputStream object) is tainted
        // index: [base] means check the receiver
        // The file path was tainted during FileInputStream construction
        return isReceiverTainted(invoke, taintedVars);
    }

    @Override
    public String getDescription() {
        return "File reading sink (FileInputStream, RandomAccessFile)";
    }
}
