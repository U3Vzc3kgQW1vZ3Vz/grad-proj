package pascal.taie.analysis.gadget;

import pascal.taie.analysis.gadget.sink.*;
import pascal.taie.analysis.gadget.source.SourceNode;
import pascal.taie.language.classes.JMethod;

import java.util.*;

/**
 * Main facade for gadget chain analysis using the fragment system.
 * This class integrates with Pascal Taie's analysis framework and provides
 * a high-level API for gadget chain discovery.
 *
 * Usage example:
 * <pre>
 * GadgetAnalyzer analyzer = new GadgetAnalyzer();
 * analyzer.initialize();
 * analyzer.analyze();
 * List<GadgetChain> chains = analyzer.getGadgetChains();
 * </pre>
 */
public class GadgetAnalyzer {

    private final FragmentContainer fragmentContainer;
    private final List<GadgetChain> discoveredChains;

    public GadgetAnalyzer() {
        this.fragmentContainer = new FragmentContainer();
        this.discoveredChains = new ArrayList<>();
    }

    /**
     * Initialize the analyzer with default sink rules
     */
    public void initialize() {
        // Register default sink detection rules

        // Add more rules as needed
    }

    /**
     * Register a custom sink rule
     */
    public void registerSinkRule(SinkRule rule) {
        fragmentContainer.registerSinkRule(rule);
    }

    /**
     * Add a discovered fragment
     */
    public void addFragment(Fragment fragment) {
        fragmentContainer.addFragment(fragment);
    }

    /**
     * Get the fragment container
     */
    public FragmentContainer getFragmentContainer() {
        return fragmentContainer;
    }

    /**
     * Compose fragments into complete gadget chains
     */
    public void composeChains() {
        discoveredChains.clear();

        // Get all sink fragments sorted by priority
        List<Fragment> sinkFragments = fragmentContainer.getSinkFragmentsSortedByPriority();

        for (Fragment sinkFragment : sinkFragments) {
            // Try to find source fragments that can reach this sink
            Set<Fragment> sourceFragments = fragmentContainer.getFragmentsByState(Fragment.State.SOURCE);

            for (Fragment sourceFragment : sourceFragments) {
                Optional<GadgetChain> chain = tryBuildChain(sourceFragment, sinkFragment);
                chain.ifPresent(discoveredChains::add);
            }

            // Also consider the sink fragment alone if it's directly reachable from a source
            if (sinkFragment.getState() == Fragment.State.SOURCE ||
                canReachFromSource(sinkFragment)) {
                GadgetChain chain = new GadgetChain(sinkFragment);
                discoveredChains.add(chain);
            }
        }
    }

    /**
     * Try to build a complete chain from source to sink
     */
    private Optional<GadgetChain> tryBuildChain(Fragment source, Fragment sink) {
        // Check if source can directly link to sink
        if (canLink(source, sink)) {
            Optional<Fragment> composed = fragmentContainer.composeFragments(source, sink);
            return composed.map(GadgetChain::new);
        }

        // Try to find intermediate fragments
        Set<Fragment> freeFragments = fragmentContainer.getFragmentsByState(Fragment.State.FREE_STATE);

        for (Fragment intermediate : freeFragments) {
            if (canLink(source, intermediate) && canLink(intermediate, sink)) {
                Optional<Fragment> sourceToIntermediate = fragmentContainer.composeFragments(source, intermediate);
                if (sourceToIntermediate.isPresent()) {
                    Optional<Fragment> fullChain = fragmentContainer.composeFragments(
                        sourceToIntermediate.get(), sink);
                    if (fullChain.isPresent()) {
                        return Optional.of(new GadgetChain(fullChain.get()));
                    }
                }
            }
        }

        return Optional.empty();
    }

    /**
     * Check if two fragments can be linked
     */
    private boolean canLink(Fragment pre, Fragment suc) {
        if (suc.getConnectRequirement() == null) {
            return false;
        }

        // Check if pre's end method can invoke suc's head
        if (!suc.getConnectRequirement().canLinkWith(pre.getEnd())) {
            return false;
        }

        // Check taint requirements
        Set<Integer> preTaints = new HashSet<>();
        for (Set<Set<Integer>> taintSets : pre.getEndToHeadTaints().values()) {
            taintSets.forEach(preTaints::addAll);
        }

        Set<Set<Integer>> sucRequires = suc.getConnectRequirement().getParamsTaintRequire();
        if (sucRequires == null || sucRequires.isEmpty()) {
            return true;
        }

        return sucRequires.stream().anyMatch(req ->
            req.isEmpty() || preTaints.containsAll(req));
    }

    /**
     * Check if a fragment can be reached from a source
     */
    private boolean canReachFromSource(Fragment fragment) {
        // Simplified check - in practice would need more sophisticated reachability analysis
        return !fragment.getLinkedDynamicMethods().isEmpty() ||
               fragment.getState() == Fragment.State.SOURCE;
    }

    /**
     * Get all discovered gadget chains
     */
    public List<GadgetChain> getGadgetChains() {
        return Collections.unmodifiableList(discoveredChains);
    }

    /**
     * Get chains filtered by sink type
     */
    public List<GadgetChain> getChainsBySinkType(SinkType sinkType) {
        return discoveredChains.stream()
            .filter(chain -> chain.getSinkType() == sinkType)
            .collect(java.util.stream.Collectors.toList());
    }

    /**
     * Print statistics
     */
    public void printStatistics() {
        fragmentContainer.printStatistics();
        System.out.println("\n======== Gadget Chain Statistics ========");
        System.out.println("Total chains discovered: " + discoveredChains.size());

        Map<SinkType, Long> chainsBySinkType = discoveredChains.stream()
            .collect(java.util.stream.Collectors.groupingBy(
                GadgetChain::getSinkType,
                java.util.stream.Collectors.counting()));

        System.out.println("Chains by sink type:");
        chainsBySinkType.forEach((type, count) ->
            System.out.println("  " + type + ": " + count));
        System.out.println("=========================================");
    }

    /**
     * Clear all data
     */
    public void clear() {
        fragmentContainer.clear();
        discoveredChains.clear();
    }

    /**
     * Represents a complete gadget chain from source to sink
     */
    public static class GadgetChain {
        private final Fragment rootFragment;
        private final List<JMethod> methodChain;
        private final SinkType sinkType;
        private final JMethod entryPoint;
        private final JMethod sinkMethod;

        public GadgetChain(Fragment fragment) {
            this.rootFragment = fragment;
            this.methodChain = new ArrayList<>(fragment.getGadgetChain());
            this.sinkType = fragment.getSinkType();
            this.entryPoint = fragment.getHead();
            this.sinkMethod = fragment.getEnd();
        }

        public Fragment getRootFragment() {
            return rootFragment;
        }

        public List<JMethod> getMethodChain() {
            return Collections.unmodifiableList(methodChain);
        }

        public SinkType getSinkType() {
            return sinkType;
        }

        public JMethod getEntryPoint() {
            return entryPoint;
        }

        public JMethod getSinkMethod() {
            return sinkMethod;
        }

        public int getLength() {
            return methodChain.size();
        }

        @Override
        public String toString() {
            StringBuilder sb = new StringBuilder();
            sb.append("GadgetChain[").append(sinkType).append(", length=").append(methodChain.size()).append("]\n");
            sb.append("  Entry: ").append(entryPoint.getSignature()).append("\n");
            for (int i = 0; i < methodChain.size(); i++) {
                sb.append("  ").append(i + 1).append(". ").append(methodChain.get(i).getSignature()).append("\n");
            }
            sb.append("  Sink: ").append(sinkMethod.getSignature());
            return sb.toString();
        }

        /**
         * Export chain in format compatible with DynamicTester
         */
        public String toChainFormat() {
            StringBuilder sb = new StringBuilder();
            for (JMethod method : methodChain) {
                sb.append("<").append(method.getSignature()).append(">\n");
            }
            return sb.toString();
        }
    }
}
