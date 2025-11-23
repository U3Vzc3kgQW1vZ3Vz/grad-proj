package pascal.taie.analysis.gadget.sink;

import pascal.taie.analysis.gadget.SinkType;
import pascal.taie.ir.exp.Var;
import pascal.taie.ir.stmt.Invoke;

import java.util.Set;

/**
 * Detects command execution sinks.
 * Adapted from jdd's ExecCheckRule for Pascal Taie.
 *
 * Dangerous methods:
 * - java.lang.Runtime.exec(String)
 * - java.lang.ProcessBuilder.&lt;init&gt;(String...)
 * - Custom exec-like methods
 */
public class ExecSinkRule extends AbstractSinkRule {

    public ExecSinkRule() {
        super(SinkType.EXEC);
    }

    @Override
    public void initialize() {
        // Find ALL exec methods across Runtime hierarchy
        addAllSubclassSignatures("<java.lang.Runtime: java.lang.Process exec(java.lang.String)>");
        addAllSubclassSignatures("<java.lang.Runtime: java.lang.Process exec(java.lang.String,java.lang.String[])>");
        addAllSubclassSignatures("<java.lang.Runtime: java.lang.Process exec(java.lang.String,java.lang.String[],java.io.File)>");
        addAllSubclassSignatures("<java.lang.Runtime: java.lang.Process exec(java.lang.String[])>");
        addAllSubclassSignatures("<java.lang.Runtime: java.lang.Process exec(java.lang.String[],java.lang.String[])>");
        addAllSubclassSignatures("<java.lang.Runtime: java.lang.Process exec(java.lang.String[],java.lang.String[],java.io.File)>");

        // ProcessBuilder constructors and command methods
        addAllSubclassSignatures("<java.lang.ProcessBuilder: void <init>(java.lang.String[])>");
        addAllSubclassSignatures("<java.lang.ProcessBuilder: void <init>(java.util.List)>");
        addAllSubclassSignatures("<java.lang.ProcessBuilder: java.lang.ProcessBuilder command(java.lang.String[])>");
        addAllSubclassSignatures("<java.lang.ProcessBuilder: java.lang.ProcessBuilder command(java.util.List)>");

        // ProcessImpl (internal class) - if it exists
        addAllSubclassSignatures("<java.lang.ProcessImpl: void <init>(java.lang.String[],java.lang.String,java.lang.String[],java.io.File,java.io.FileDescriptor,java.io.FileDescriptor,java.io.FileDescriptor)>");
    }

    @Override
    protected boolean checkTaintedArguments(Invoke invoke, Set<Var> taintedVars) {
        // For Runtime.exec and ProcessBuilder, check if the command argument is tainted
        // Typically this is the first argument (command string or array)
        if (invoke.getInvokeExp().getArgCount() > 0) {
            // Check first argument
            if (isArgumentTainted(invoke, 0, taintedVars)) {
                return true;
            }
        }
        return false;
    }

    @Override
    public String getDescription() {
        return "Command execution sink (Runtime.exec, ProcessBuilder)";
    }
}
