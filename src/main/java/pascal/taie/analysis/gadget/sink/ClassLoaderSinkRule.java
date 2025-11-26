package pascal.taie.analysis.gadget.sink;

import pascal.taie.analysis.gadget.SinkType;
import pascal.taie.ir.exp.Var;
import pascal.taie.ir.stmt.Invoke;
import pascal.taie.language.type.Type;

import java.util.Arrays;
import java.util.Set;

/**
 * Detects class loading sinks that can lead to RCE.
 * Adapted from jdd's ClassLoaderCheckRule for Pascal Taie.
 *
 * Dangerous patterns:
 * (1) ClassLoader.defineClass(byte[]) -> Class.newInstance()
 * (2) URLClassLoader(URL[]) -> loadClass/forName -> newInstance()
 *
 * Methods detected:
 * - ClassLoader.defineClass
 * - URLClassLoader constructors
 * - URLClassLoader.loadClass
 * - Class.forName with ClassLoader parameter
 */
public class ClassLoaderSinkRule extends AbstractSinkRule {

    public ClassLoaderSinkRule() {
        super(SinkType.CLASS_LOADER);
    }

    @Override
    public void initialize() {
        // ClassLoader.defineClass - find ALL defineClass methods across ClassLoader hierarchy
        // Then filter to only keep those with byte[] parameter
        addAllMethodsByNameFiltered(
            Arrays.asList("java.lang.ClassLoader"),
            "defineClass",
            sig -> sig.contains("byte[]")
        );

        // URLClassLoader constructors - find ALL <init> methods
        addAllMethodsByName(Arrays.asList("java.net.URLClassLoader"), "<init>");

        // URLClassLoader.loadClass - find ALL loadClass methods across URLClassLoader hierarchy
        addAllMethodsByName(Arrays.asList("java.net.URLClassLoader"), "loadClass");

        // Class.forName - find ALL forName methods across Class hierarchy
        addAllMethodsByName(Arrays.asList("java.lang.Class"), "forName");
    }

    @Override
    protected boolean checkTaintedArguments(Invoke invoke, Set<Var> taintedVars) {
        String methodSig = invoke.getInvokeExp().getMethodRef().getSubsignature().toString();

        // ClassLoader.defineClass - check byte[] argument is tainted
        if (methodSig.contains("defineClass") && methodSig.contains("byte[]")) {
            // The byte[] is typically the second argument (index 1)
            if (invoke.getInvokeExp().getArgCount() > 1) {
                Var byteArrayArg = invoke.getInvokeExp().getArg(1);
                return isTainted(byteArrayArg, taintedVars);
            }
        }

        // URLClassLoader.<init> - check URL[] argument is tainted
        else if (methodSig.contains("URLClassLoader: void <init>") && methodSig.contains("java.net.URL[]")) {
            // The URL[] is typically the first argument
            if (invoke.getInvokeExp().getArgCount() > 0) {
                Var urlArrayArg = invoke.getInvokeExp().getArg(0);
                return isTainted(urlArrayArg, taintedVars);
            }
        }

        // URLClassLoader.loadClass - check receiver (this) is tainted
        else if (methodSig.contains("URLClassLoader") && methodSig.contains("loadClass")) {
            return isReceiverTainted(invoke, taintedVars);
        }

        // Class.forName - check ClassLoader argument is tainted AND class name is tainted
        else if (methodSig.contains("Class: java.lang.Class forName") && methodSig.contains("ClassLoader")) {
            if (invoke.getInvokeExp().getArgCount() >= 3) {
                Var classNameArg = invoke.getInvokeExp().getArg(0);
                Var classLoaderArg = invoke.getInvokeExp().getArg(2);

                // Both class name and classloader should be tainted
                return isTainted(classNameArg, taintedVars) && isTainted(classLoaderArg, taintedVars);
            }
        }

        return false;
    }

    @Override
    public String getDescription() {
        return "Class loading sink (ClassLoader.defineClass, URLClassLoader)";
    }
}
