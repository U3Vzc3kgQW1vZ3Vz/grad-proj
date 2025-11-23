package pascal.taie.analysis.gadget;

import pascal.taie.ir.stmt.Invoke;
import pascal.taie.language.classes.JMethod;

import java.util.*;

/**
 * Fragment data structure representing a segment of a gadget chain.
 * Adapted from jdd's Fragment system for Pascal Taie.
 *
 * A Fragment represents a reachable path from a head method to an end method,
 * which can be connected with other fragments to form complete gadget chains.
 */
public class Fragment {

    /**
     * Fragment state indicating its role in the gadget chain
     */
    public enum State {
        SOURCE,      // Entry point (e.g., readObject, readExternal)
        FREE_STATE,  // Intermediate fragment that can be linked
        SINK         // Reaches a dangerous sink
    }

    /**
     * Fragment type indicating how it connects to other fragments
     */
    public enum Type {
        POLYMORPHISM,   // Connected via polymorphic method calls
        DYNAMIC_PROXY,  // Connected via InvocationHandler
        REFLECTION      // Connected via reflection (Method.invoke)
    }

    // Core properties
    private boolean valid = true;
    private State state;
    private Type type;
    private SinkType sinkType;

    // Method chain
    private JMethod head;              // Entry method
    private JMethod end;               // Exit method (dynamic call site)
    private List<JMethod> gadgetChain; // Full method chain

    // Invocation information
    private Invoke invokeStmt;
    private Set<JMethod> endInvokableMethods; // Possible methods at call site

    // Taint tracking: maps end method parameters to head method parameters
    // Key: parameter index in end method (-1 for this)
    // Value: set of possible parameter combinations from head method
    private Map<Integer, Set<Set<Integer>>> endToHeadTaints;

    // Connection requirements
    private ConnectRequirement connectRequirement;

    // Priority for chain construction (higher = more gadgets)
    private int priority = 1;

    // Chain composition tracking
    private List<Integer> linkedFragmentIds;
    private List<JMethod> linkedDynamicMethods;

    /**
     * Create a basic fragment
     */
    public Fragment(JMethod head, JMethod end, List<JMethod> chain,
                    Invoke invokeStmt, Set<JMethod> endInvokableMethods) {
        this.head = head;
        this.end = end;
        this.gadgetChain = new ArrayList<>(chain);
        this.invokeStmt = invokeStmt;
        this.endInvokableMethods = endInvokableMethods != null ?
            new HashSet<>(endInvokableMethods) : new HashSet<>();
        this.endToHeadTaints = new HashMap<>();
        this.linkedFragmentIds = new ArrayList<>();
        this.linkedDynamicMethods = new ArrayList<>();
    }

    /**
     * Create a composed fragment by linking two fragments
     */
    public Fragment(Fragment preFragment, Fragment sucFragment) {
        // Validate connection
        if (!canLink(preFragment, sucFragment)) {
            this.valid = false;
            return;
        }

        // Set basic properties from successor
        this.type = sucFragment.type;
        this.sinkType = sucFragment.sinkType;
        this.state = preFragment.state;

        // Compose gadget chain
        this.gadgetChain = new ArrayList<>(preFragment.gadgetChain);
        this.gadgetChain.addAll(sucFragment.gadgetChain);

        // Set head and end
        this.head = preFragment.head;
        this.end = sucFragment.end;
        this.invokeStmt = sucFragment.invokeStmt;

        // Compose connection tracking
        this.linkedFragmentIds = new ArrayList<>(sucFragment.linkedFragmentIds);
        this.linkedFragmentIds.add(0, preFragment.hashCode());

        this.linkedDynamicMethods = new ArrayList<>();
        this.linkedDynamicMethods.add(preFragment.end);
        this.linkedDynamicMethods.addAll(sucFragment.linkedDynamicMethods);

        // Copy taint requirements
        this.endToHeadTaints = new HashMap<>(sucFragment.endToHeadTaints);

        // Compose connection requirements
        Set<Set<Integer>> paramsTaintRequires = computeTaintRequirements(preFragment, sucFragment);
        if (paramsTaintRequires.isEmpty()) {
            this.valid = false;
            return;
        }

        this.connectRequirement = new ConnectRequirement(
            paramsTaintRequires,
            preFragment.connectRequirement.getPreLinkableMethods()
        );
    }

    /**
     * Check if two fragments can be linked
     */
    private static boolean canLink(Fragment pre, Fragment suc) {
        // Check if pre's end method can invoke suc's head method
        if (!suc.connectRequirement.getPreLinkableMethods().contains(pre.end)) {
            return false;
        }

        // If pre has endInvokableMethods constraint, check if suc's head is in it
        if (pre.endInvokableMethods != null && !pre.endInvokableMethods.isEmpty()) {
            if (!pre.endInvokableMethods.contains(suc.head)) {
                return false;
            }
        }

        return true;
    }

    /**
     * Compute taint requirements for linking two fragments
     */
    private static Set<Set<Integer>> computeTaintRequirements(Fragment pre, Fragment suc) {
        Set<Set<Integer>> result = new HashSet<>();

        // For each parameter required by successor
        Set<Set<Integer>> sucRequires = suc.connectRequirement.getParamsTaintRequire();
        if (sucRequires == null || sucRequires.isEmpty()) {
            result.add(new HashSet<>()); // No requirements
            return result;
        }

        // Match with predecessor's taint map
        for (Set<Integer> sucParamSet : sucRequires) {
            Set<Integer> preParamSet = new HashSet<>();
            for (Integer sucParam : sucParamSet) {
                if (pre.endToHeadTaints.containsKey(sucParam)) {
                    for (Set<Integer> preParams : pre.endToHeadTaints.get(sucParam)) {
                        preParamSet.addAll(preParams);
                    }
                }
            }
            if (!preParamSet.isEmpty() || sucParamSet.isEmpty()) {
                result.add(preParamSet);
            }
        }

        return result;
    }

    /**
     * Add taint dependency: parameter 'paramIndex' in end method
     * depends on parameters 'headParams' in head method
     */
    public void addTaintDependency(int paramIndex, Set<Integer> headParams) {
        endToHeadTaints.computeIfAbsent(paramIndex, k -> new HashSet<>())
            .add(new HashSet<>(headParams));
    }

    /**
     * Calculate priority based on fragment complexity
     */
    public void calculatePriority() {
        this.priority = linkedFragmentIds.size() + gadgetChain.size();
    }

    // Getters and setters

    public boolean isValid() {
        return valid;
    }

    public void setValid(boolean valid) {
        this.valid = valid;
    }

    public State getState() {
        return state;
    }

    public void setState(State state) {
        this.state = state;
    }

    public Type getType() {
        return type;
    }

    public void setType(Type type) {
        this.type = type;
    }

    public SinkType getSinkType() {
        return sinkType;
    }

    public void setSinkType(SinkType sinkType) {
        this.sinkType = sinkType;
    }

    public JMethod getHead() {
        return head;
    }

    public JMethod getEnd() {
        return end;
    }

    public List<JMethod> getGadgetChain() {
        return Collections.unmodifiableList(gadgetChain);
    }

    public Invoke getInvokeStmt() {
        return invokeStmt;
    }

    public Set<JMethod> getEndInvokableMethods() {
        return Collections.unmodifiableSet(endInvokableMethods);
    }

    public Map<Integer, Set<Set<Integer>>> getEndToHeadTaints() {
        return Collections.unmodifiableMap(endToHeadTaints);
    }

    public ConnectRequirement getConnectRequirement() {
        return connectRequirement;
    }

    public void setConnectRequirement(ConnectRequirement req) {
        this.connectRequirement = req;
    }

    public int getPriority() {
        return priority;
    }

    public List<Integer> getLinkedFragmentIds() {
        return Collections.unmodifiableList(linkedFragmentIds);
    }

    public List<JMethod> getLinkedDynamicMethods() {
        return Collections.unmodifiableList(linkedDynamicMethods);
    }

    @Override
    public boolean equals(Object obj) {
        if (!(obj instanceof Fragment)) {
            return false;
        }
        Fragment other = (Fragment) obj;
        return gadgetChain.equals(other.gadgetChain) && end.equals(other.end);
    }

    @Override
    public int hashCode() {
        return Objects.hash(gadgetChain, end);
    }

    @Override
    public String toString() {
        return String.format("Fragment[%s -> %s, chain=%d, state=%s]",
            head.getName(), end.getName(), gadgetChain.size(), state);
    }
}
