package pascal.taie.analysis.gadget;

import pascal.taie.analysis.gadget.sink.SinkRule;
import pascal.taie.language.classes.JMethod;

import java.util.*;
import java.util.stream.Collectors;

/**
 * Container for managing all fragments discovered during gadget chain analysis.
 * Adapted from jdd's FragmentsContainer for Pascal Taie.
 *
 * This class provides:
 * - Storage and indexing of fragments
 * - Querying fragments by various criteria
 * - Fragment composition and linking
 */
public class FragmentContainer {

    // Core storage
    private final Map<Integer, Fragment> allFragments;

    // Indexed by state
    private final Map<Fragment.State, Set<Fragment>> fragmentsByState;

    // Indexed by type
    private final Map<Fragment.Type, Set<Fragment>> fragmentsByType;

    // Indexed by sink type
    private final Map<SinkType, Set<Fragment>> fragmentsBySinkType;

    // Sink fragments sorted by priority
    private final TreeMap<Integer, Set<Fragment>> sinkFragmentsByPriority;

    // Fragments indexed by taint requirements
    private final Map<Set<Integer>, Set<Fragment>> fragmentsByTaintRequirement;

    // Reverse index: Map method to fragments that can be linked after it
    private final Map<JMethod, Set<Fragment>> fragmentsLinkableByMethod;

    // Dynamic method tracking
    private final Map<JMethod, Set<JMethod>> dynamicSubMethods;
    private final Set<JMethod> dynamicMethods;

    // Registered sink rules
    private final List<SinkRule> sinkRules;

    // Statistics
    private int totalFragments = 0;
    private int sourceFragments = 0;
    private int sinkFragments = 0;
    private int freeFragments = 0;

    public FragmentContainer() {
        this.allFragments = new HashMap<>();
        this.fragmentsByState = new EnumMap<>(Fragment.State.class);
        this.fragmentsByType = new EnumMap<>(Fragment.Type.class);
        this.fragmentsBySinkType = new EnumMap<>(SinkType.class);
        this.sinkFragmentsByPriority = new TreeMap<>(Collections.reverseOrder());
        this.fragmentsByTaintRequirement = new HashMap<>();
        this.fragmentsLinkableByMethod = new HashMap<>();
        this.dynamicSubMethods = new HashMap<>();
        this.dynamicMethods = new HashSet<>();
        this.sinkRules = new ArrayList<>();

        // Initialize state map
        for (Fragment.State state : Fragment.State.values()) {
            fragmentsByState.put(state, new LinkedHashSet<>());
        }

        // Initialize type map
        for (Fragment.Type type : Fragment.Type.values()) {
            fragmentsByType.put(type, new LinkedHashSet<>());
        }

        // Initialize sink type map
        for (SinkType sinkType : SinkType.values()) {
            fragmentsBySinkType.put(sinkType, new LinkedHashSet<>());
        }
    }

    /**
     * Register a sink detection rule
     */
    public void registerSinkRule(SinkRule rule) {
        sinkRules.add(rule);
        rule.initialize();
    }

    /**
     * Check if a method is a sink according to any registered rule
     */
    public boolean isSinkMethod(JMethod method) {
        return sinkRules.stream().anyMatch(rule -> rule.isSinkMethod(method));
    }

    /**
     * Get sink type for a method
     */
    public Optional<SinkType> getSinkType(JMethod method) {
        return sinkRules.stream()
            .filter(rule -> rule.isSinkMethod(method))
            .map(SinkRule::getSinkType)
            .findFirst();
    }

    /**
     * Add a fragment to the container
     */
    public void addFragment(Fragment fragment) {
        if (!fragment.isValid()) {
            return;
        }

        int id = fragment.hashCode();
        allFragments.put(id, fragment);
        totalFragments++;

        // Index by state
        if (fragment.getState() != null) {
            fragmentsByState.get(fragment.getState()).add(fragment);
            updateStateStatistics(fragment.getState(), 1);
        }

        // Index by type
        if (fragment.getType() != null) {
            fragmentsByType.get(fragment.getType()).add(fragment);
        }

        // Index by sink type
        if (fragment.getSinkType() != null) {
            fragmentsBySinkType.get(fragment.getSinkType()).add(fragment);
        }

        // Index sink fragments by priority
        if (fragment.getState() == Fragment.State.SINK) {
            sinkFragmentsByPriority
                .computeIfAbsent(fragment.getPriority(), k -> new HashSet<>())
                .add(fragment);
        }

        // Index by taint requirement and linkable methods
        if (fragment.getConnectRequirement() != null) {
            Set<Set<Integer>> taintReqs = fragment.getConnectRequirement().getParamsTaintRequire();
            if (taintReqs != null) {
                for (Set<Integer> req : taintReqs) {
                    fragmentsByTaintRequirement
                        .computeIfAbsent(req, k -> new HashSet<>())
                        .add(fragment);
                }
            }
            
            // Index by pre-linkable methods
            for (JMethod method : fragment.getConnectRequirement().getPreLinkableMethods()) {
                fragmentsLinkableByMethod
                    .computeIfAbsent(method, k -> new HashSet<>())
                    .add(fragment);
            }
        }
    }

    /**
     * Get fragment by ID
     */
    public Fragment getFragment(int id) {
        return allFragments.get(id);
    }

    /**
     * Get all fragments with a specific state
     */
    public Set<Fragment> getFragmentsByState(Fragment.State state) {
        return Collections.unmodifiableSet(fragmentsByState.get(state));
    }

    /**
     * Get all fragments with a specific type
     */
    public Set<Fragment> getFragmentsByType(Fragment.Type type) {
        return Collections.unmodifiableSet(fragmentsByType.get(type));
    }

    /**
     * Get all fragments with a specific sink type
     */
    public Set<Fragment> getFragmentsBySinkType(SinkType sinkType) {
        return Collections.unmodifiableSet(fragmentsBySinkType.get(sinkType));
    }

    /**
     * Get fragments that can be linked after the given method.
     * i.e., fragments F where F.connectRequirement.preLinkableMethods contains method.
     */
    public Set<Fragment> getFragmentsLinkableByMethod(JMethod method) {
        return Collections.unmodifiableSet(
            fragmentsLinkableByMethod.getOrDefault(method, Collections.emptySet())
        );
    }

    /**
     * Get sink fragments sorted by priority (highest first)
     */
    public List<Fragment> getSinkFragmentsSortedByPriority() {
        return sinkFragmentsByPriority.values().stream()
            .flatMap(Set::stream)
            .collect(Collectors.toList());
    }

    /**
     * Get fragments that can be linked with the given method
     */
    public Set<Fragment> getLinkableFragments(JMethod method, Set<JMethod> invokableMethods) {
        Set<Fragment> result = new HashSet<>();

        for (Fragment fragment : fragmentsByState.get(Fragment.State.SINK)) {
            if (fragment.getConnectRequirement() != null &&
                fragment.getConnectRequirement().canLinkWith(method)) {

                // Check invokable methods constraint
                if (invokableMethods != null && !invokableMethods.isEmpty()) {
                    if (!invokableMethods.contains(fragment.getHead())) {
                        continue;
                    }
                }

                result.add(fragment);
            }
        }

        return result;
    }

    /**
     * Get fragments with specific head method
     */
    public Set<Fragment> getFragmentsByHead(JMethod head) {
        return allFragments.values().stream()
            .filter(f -> f.getHead().equals(head))
            .collect(Collectors.toSet());
    }

    /**
     * Get fragments with specific end method
     */
    public Set<Fragment> getFragmentsByEnd(JMethod end) {
        return allFragments.values().stream()
            .filter(f -> f.getEnd().equals(end))
            .collect(Collectors.toSet());
    }

    /**
     * Try to compose two fragments into a new fragment
     */
    public Optional<Fragment> composeFragments(Fragment preFragment, Fragment sucFragment) {
        Fragment composed = new Fragment(preFragment, sucFragment);
        if (composed.isValid()) {
            addFragment(composed);
            return Optional.of(composed);
        }
        return Optional.empty();
    }

    /**
     * Register a dynamic method and its possible implementations
     */
    public void registerDynamicMethod(JMethod superMethod, Set<JMethod> subMethods) {
        dynamicMethods.add(superMethod);
        dynamicSubMethods.put(superMethod, new HashSet<>(subMethods));
    }

    /**
     * Get possible implementations of a dynamic method
     */
    public Set<JMethod> getSubMethods(JMethod superMethod) {
        return dynamicSubMethods.getOrDefault(superMethod, Collections.emptySet());
    }

    /**
     * Check if a method is registered as dynamic
     */
    public boolean isDynamicMethod(JMethod method) {
        return dynamicMethods.contains(method);
    }

    /**
     * Clear all fragments
     */
    public void clear() {
        allFragments.clear();
        fragmentsByState.values().forEach(Set::clear);
        fragmentsByType.values().forEach(Set::clear);
        fragmentsBySinkType.values().forEach(Set::clear);
        sinkFragmentsByPriority.clear();
        fragmentsByTaintRequirement.clear();
        fragmentsLinkableByMethod.clear();
        dynamicSubMethods.clear();
        dynamicMethods.clear();
        totalFragments = 0;
        sourceFragments = 0;
        sinkFragments = 0;
        freeFragments = 0;
    }

    private void updateStateStatistics(Fragment.State state, int delta) {
        switch (state) {
            case SOURCE:
                sourceFragments += delta;
                break;
            case SINK:
                sinkFragments += delta;
                break;
            case FREE_STATE:
                freeFragments += delta;
                break;
        }
    }

    // Statistics getters

    public int getTotalFragments() {
        return totalFragments;
    }

    public int getSourceFragments() {
        return sourceFragments;
    }

    public int getSinkFragments() {
        return sinkFragments;
    }

    public int getFreeFragments() {
        return freeFragments;
    }

    public List<SinkRule> getSinkRules() {
        return Collections.unmodifiableList(sinkRules);
    }

    /**
     * Print statistics
     */
    public void printStatistics() {
        System.out.println("======== Fragment Container Statistics ========");
        System.out.println("Total fragments: " + totalFragments);
        System.out.println("  Source fragments: " + sourceFragments);
        System.out.println("  Free fragments: " + freeFragments);
        System.out.println("  Sink fragments: " + sinkFragments);
        System.out.println();
        System.out.println("Fragments by type:");
        for (Fragment.Type type : Fragment.Type.values()) {
            System.out.println("  " + type + ": " + fragmentsByType.get(type).size());
        }
        System.out.println();
        System.out.println("Sink fragments by type:");
        for (SinkType sinkType : SinkType.values()) {
            int count = fragmentsBySinkType.get(sinkType).size();
            if (count > 0) {
                System.out.println("  " + sinkType + ": " + count);
            }
        }
        System.out.println("===============================================");
    }
}
