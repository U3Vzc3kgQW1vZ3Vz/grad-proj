package pascal.taie.analysis.gadget.examples;

import pascal.taie.analysis.gadget.*;
import pascal.taie.analysis.gadget.sink.*;
import pascal.taie.analysis.gadget.source.SourceNode;
import pascal.taie.ir.stmt.Invoke;
import pascal.taie.language.classes.JMethod;

import java.io.FileWriter;
import java.io.IOException;
import java.util.*;

/**
 * Example demonstrating how to use the gadget analysis framework
 * integrated with DynamicTester for validation.
 *
 * This example shows:
 * 1. Setting up the analyzer
 * 2. Discovering and adding fragments
 * 3. Composing complete chains
 * 4. Exporting chains for DynamicTester validation
 */
public class GadgetAnalysisExample {

    public static void main(String[] args) throws IOException {
        System.out.println("===========================================");
        System.out.println("  Gadget Analysis Framework Examples");
        System.out.println("===========================================\n");

        // Example 1: Basic setup and analysis
        basicAnalysisExample();

        // Example 2: Custom sink detection
        customSinkExample();

        // Example 3: Fragment composition
        fragmentCompositionExample();

        // Example 4: Real usage pattern
        demonstrateRealUsage();

        // Example 5: Integration workflow
        integratedWorkflowExample();

        System.out.println("\n===========================================");
        System.out.println("  Examples Complete");
        System.out.println("===========================================");
    }

    /**
     * Example 1: Basic analysis workflow
     */
    private static void basicAnalysisExample() {
        System.out.println("=== Basic Analysis Example ===\n");

        // Initialize analyzer with default sink rules
        GadgetAnalyzer analyzer = new GadgetAnalyzer();
        analyzer.initialize();

        System.out.println("Initialized analyzer with " +
            analyzer.getFragmentContainer().getSinkRules().size() + " sink rules");

        // Simulate adding discovered fragments
        // In practice, these would be discovered during static analysis
        simulateFragmentDiscovery(analyzer);

        // Compose fragments into complete chains
        analyzer.composeChains();

        // Get results
        List<GadgetAnalyzer.GadgetChain> chains = analyzer.getGadgetChains();
        System.out.println("Discovered " + chains.size() + " gadget chains\n");

        // Print statistics
        analyzer.printStatistics();
    }

    /**
     * Example 2: Adding custom sink detection
     */
    private static void customSinkExample() {
        System.out.println("\n=== Custom Sink Example ===\n");

        GadgetAnalyzer analyzer = new GadgetAnalyzer();

        // Register default rules
        analyzer.initialize();

        // Add custom sink rule for SQL injection
        analyzer.registerSinkRule(new AbstractSinkRule(SinkType.CUSTOM) {
            @Override
            public void initialize() {
                addRiskySignature(
                    "<java.sql.Statement: java.sql.ResultSet executeQuery(java.lang.String)>");
                addRiskySignature(
                    "<java.sql.Statement: int executeUpdate(java.lang.String)>");
                addRiskySignature(
                    "<java.sql.Connection: java.sql.PreparedStatement prepareStatement(java.lang.String)>");
            }

            @Override
            protected boolean checkTaintedArguments(
                    pascal.taie.ir.stmt.Invoke invoke,
                    Set<pascal.taie.ir.exp.Var> taintedVars) {
                // Check if SQL query string is tainted
                return invoke.getInvokeExp().getArgCount() > 0 &&
                       isArgumentTainted(invoke, 0, taintedVars);
            }

            @Override
            public String getDescription() {
                return "SQL injection sink detection";
            }
        });

        System.out.println("Registered custom SQL injection sink rule");
        System.out.println("Total sink rules: " +
            analyzer.getFragmentContainer().getSinkRules().size());
    }

    /**
     * Example 3: Manual fragment composition
     */
    private static void fragmentCompositionExample() {
        System.out.println("\n=== Fragment Composition Example ===\n");

        System.out.println("This example demonstrates the fragment composition concept.");
        System.out.println("In real usage, fragments would be created from actual JMethod objects");
        System.out.println("obtained from Tai-e's class hierarchy.\n");

        System.out.println("Conceptual workflow:");
        System.out.println("1. Create SOURCE fragment: readObject -> hashCode");
        System.out.println("   - Represents entry point from deserialization");
        System.out.println("   - Tracks taint: hashCode's 'this' depends on readObject's param 0");
        System.out.println();

        System.out.println("2. Create FREE_STATE fragment: hashCode -> transform");
        System.out.println("   - Intermediate gadget in the chain");
        System.out.println("   - Connection requirement: needs hashCode as pre-linkable method");
        System.out.println();

        System.out.println("3. Create SINK fragment: transform -> exec");
        System.out.println("   - Reaches dangerous Runtime.exec sink");
        System.out.println("   - Taint requirement: 'this' must be tainted");
        System.out.println();

        System.out.println("4. Compose fragments:");
        System.out.println("   - Source + Intermediate = partial chain");
        System.out.println("   - Partial + Sink = complete gadget chain");
        System.out.println("   - Result: readObject -> hashCode -> transform -> exec");
        System.out.println();

        System.out.println("For actual implementation, see:");
        System.out.println("  - Fragment.java: Fragment composition logic");
        System.out.println("  - ConnectRequirement.java: Linking requirements");
        System.out.println("  - GadgetAnalyzer.java: Chain composition algorithm");
    }


    /**
     * Simulate fragment discovery during analysis
     * In practice, this would be done by the static analysis
     */
    private static void simulateFragmentDiscovery(GadgetAnalyzer analyzer) {
        // NOTE: This is a placeholder - in real usage, fragments are discovered
        // during static analysis and use actual JMethod objects from Tai-e's
        // World.get().getClassHierarchy()

        // For this example, we skip the actual fragment creation since we don't
        // have access to real JMethod objects

        System.out.println("  [Simulated] In real analysis, fragments would be discovered here");
        System.out.println("  [Simulated] Example: HashMap.readObject -> HashMap.hash -> Object.hashCode");

        // In real usage, you would:
        // 1. Get JMethod from Tai-e: World.get().getClassHierarchy().getClass("java.util.HashMap").getDeclaredMethod(...)
        // 2. Create fragments from discovered taint flows
        // 3. Add them to the analyzer

        // Example structure (commented out since we don't have real methods):
        /*
        JMethod readObject = World.get().getClassHierarchy()
            .getClass("java.util.HashMap")
            .getDeclaredMethod("readObject", ...);
        JMethod hash = ...;
        JMethod hashCode = ...;

        Fragment sourceFragment = new Fragment(
            readObject,
            hashCode,
            Arrays.asList(readObject, hash, hashCode),
            null,
            new HashSet<>()
        );
        sourceFragment.setState(Fragment.State.SOURCE);
        sourceFragment.setType(Fragment.Type.POLYMORPHISM);

        ConnectRequirement req = new ConnectRequirement(new HashSet<>(Arrays.asList(hashCode)));
        sourceFragment.setConnectRequirement(req);

        analyzer.addFragment(sourceFragment);
        */
    }

    /**
     * NOTE: In real usage, JMethod objects come from Tai-e's World
     *
     * Example of getting actual methods:
     * <pre>
     * World world = World.get();
     * JClass hashMapClass = world.getClassHierarchy().getClass("java.util.HashMap");
     * JMethod readObject = hashMapClass.getDeclaredMethod("readObject",
     *     Collections.singletonList(world.getTypeSystem().getClassType("java.io.ObjectInputStream")));
     * </pre>
     */
    private static void demonstrateRealUsage() {
        System.out.println("\n=== Real Usage Pattern ===\n");
        System.out.println("In a real Tai-e analysis, you would:");
        System.out.println("1. Access World.get() to get the program being analyzed");
        System.out.println("2. Use ClassHierarchy to get JClass objects");
        System.out.println("3. Use JClass.getDeclaredMethod() to get JMethod objects");
        System.out.println("4. Create fragments from discovered taint flows");
        System.out.println("5. Use GadgetAnalyzer to compose and find chains");
    }

    /**
     * Example: Integration with existing DynamicTester workflow
     */
    public static void integratedWorkflowExample() {
        System.out.println("\n=== Integrated Workflow Example ===\n");

        System.out.println("Step 1: Run static analysis to discover fragments");
        GadgetAnalyzer analyzer = new GadgetAnalyzer();
        analyzer.initialize();

        // Static analysis phase (using Pascal Taie)
        // - Dataflow analysis discovers tainted paths
        // - Fragment creation from discovered paths
        // - Sink detection using registered rules

        System.out.println("Step 2: Compose fragments into chains");
        analyzer.composeChains();

        System.out.println("Step 3: Export high-priority chains");
        List<GadgetAnalyzer.GadgetChain> chains = analyzer.getGadgetChains();
        // Filter to top chains
        chains.stream()
            .sorted(Comparator.comparingInt(GadgetAnalyzer.GadgetChain::getLength).reversed())
            .limit(10)
            .forEach(chain -> {
                System.out.println("  Exporting: " + chain.getSinkType() +
                    " chain with " + chain.getLength() + " methods");
            });

        System.out.println("Step 4: DynamicTester validates chains");
        System.out.println("  - Instantiate gadget objects");
        System.out.println("  - Build payload");
        System.out.println("  - Serialize and deserialize");
        System.out.println("  - Check if sink is triggered");

        System.out.println("\nIntegration complete!");
    }
}
