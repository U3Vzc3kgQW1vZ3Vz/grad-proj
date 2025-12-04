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
 * (3) Attacker-controlled ClassLoader.loadClass(String)
 * (4) Attacker-controlled ClassLoader.findClass(String)
 *
 * Methods detected:
 * - ClassLoader.defineClass (with byte[] parameter)
 * - ClassLoader.loadClass (all ClassLoader subclasses)
 * - ClassLoader.findClass (all ClassLoader subclasses)
 * - URLClassLoader constructors
 * - Class.forName (all variants)
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

        // ClassLoader.loadClass - find ALL loadClass methods across ClassLoader hierarchy
        // This covers ClassLoader, URLClassLoader, and all other subclasses
        addAllMethodsByName(Arrays.asList("java.lang.ClassLoader"), "loadClass");

        // ClassLoader.findClass - another class loading method that can be dangerous
        addAllMethodsByName(Arrays.asList("java.lang.ClassLoader"), "findClass");

        // URLClassLoader constructors - find ALL <init> methods
        addAllMethodsByName(Arrays.asList("java.net.URLClassLoader"), "<init>");

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

        // ClassLoader.loadClass / findClass - check if class name (first arg) is tainted OR receiver is tainted
        else if (methodSig.contains("loadClass") || methodSig.contains("findClass")) {
            // Check if the class name argument is tainted
            boolean classNameTainted = false;
            if (invoke.getInvokeExp().getArgCount() > 0) {
                Var classNameArg = invoke.getInvokeExp().getArg(0);
                classNameTainted = isTainted(classNameArg, taintedVars);
            }

            // Also check if the ClassLoader receiver is tainted (attacker-controlled ClassLoader)
            boolean receiverTainted = isReceiverTainted(invoke, taintedVars);

            // Either tainted class name OR tainted classloader is dangerous
            return classNameTainted || receiverTainted;
        }

        // URLClassLoader.<init> - check URL[] argument is tainted
        else if (methodSig.contains("void <init>") && methodSig.contains("java.net.URL[]")) {
            // The URL[] is typically the first argument
            if (invoke.getInvokeExp().getArgCount() > 0) {
                Var urlArrayArg = invoke.getInvokeExp().getArg(0);
                return isTainted(urlArrayArg, taintedVars);
            }
        }

        // Class.forName - check ClassLoader argument is tainted OR class name is tainted
        else if (methodSig.contains("forName")) {
            // Class.forName(String) - check class name
            if (invoke.getInvokeExp().getArgCount() == 1) {
                Var classNameArg = invoke.getInvokeExp().getArg(0);
                return isTainted(classNameArg, taintedVars);
            }
            // Class.forName(String, boolean, ClassLoader) - check class name OR classloader
            else if (invoke.getInvokeExp().getArgCount() >= 3) {
                Var classNameArg = invoke.getInvokeExp().getArg(0);
                Var classLoaderArg = invoke.getInvokeExp().getArg(2);

                // Either class name or classloader tainted is dangerous
                return isTainted(classNameArg, taintedVars) || isTainted(classLoaderArg, taintedVars);
            }
        }

        return false;
    }

    @Override
    public String getDescription() {
        return "Class loading sink (ClassLoader.defineClass, URLClassLoader)";
    }
}
