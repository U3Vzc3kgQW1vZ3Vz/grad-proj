package pascal.taie.analysis.gadget;

import pascal.taie.language.classes.JMethod;

import java.util.*;

/**
 * Represents the requirements for connecting fragments in a gadget chain.
 * Adapted from jdd's ConnectRequire for Pascal Taie.
 */
public class ConnectRequirement {

    /**
     * Methods that can be invoked before this fragment (polymorphic dispatch)
     */
    private final Set<JMethod> preLinkableMethods;

    /**
     * Parameter taint requirements for linking.
     * Each set represents one possible way to satisfy the requirements.
     * The integers are parameter indices (-1 for 'this').
     */
    private Set<Set<Integer>> paramsTaintRequire;

    /**
     * Condition requirements for dynamic proxy connections
     */
    private final Set<Integer> conditionSet;

    /**
     * Flags for special connection types
     */
    private boolean dynamicProxyLinkCheck = false;
    private boolean reflectionCheck = false;

    /**
     * Create connection requirements with linkable methods
     */
    public ConnectRequirement(Set<JMethod> preLinkableMethods) {
        this.preLinkableMethods = new HashSet<>(preLinkableMethods);
        this.paramsTaintRequire = new HashSet<>();
        this.conditionSet = new HashSet<>();
    }

    /**
     * Create connection requirements with taint requirements and linkable methods
     */
    public ConnectRequirement(Set<Set<Integer>> paramsTaintRequire, Set<JMethod> preLinkableMethods) {
        this.preLinkableMethods = preLinkableMethods != null ?
            new HashSet<>(preLinkableMethods) : new HashSet<>();
        this.paramsTaintRequire = paramsTaintRequire != null ?
            new HashSet<>(paramsTaintRequire) : new HashSet<>();
        this.conditionSet = new HashSet<>();
    }

    /**
     * Check if a method can be linked before this fragment
     */
    public boolean canLinkWith(JMethod method) {
        return preLinkableMethods.contains(method);
    }

    /**
     * Check if parameter taints satisfy the requirements
     */
    public boolean satisfiesTaintRequirement(Set<Integer> availableTaints) {
        if (paramsTaintRequire.isEmpty()) {
            return true; // No requirements
        }

        for (Set<Integer> requirement : paramsTaintRequire) {
            if (requirement.isEmpty() || availableTaints.containsAll(requirement)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Add a condition requirement
     */
    public void addCondition(int conditionHash) {
        conditionSet.add(conditionHash);
    }

    // Getters and setters

    public Set<JMethod> getPreLinkableMethods() {
        return Collections.unmodifiableSet(preLinkableMethods);
    }

    public Set<Set<Integer>> getParamsTaintRequire() {
        return paramsTaintRequire;
    }

    public void setParamsTaintRequire(Set<Set<Integer>> paramsTaintRequire) {
        this.paramsTaintRequire = new HashSet<>(paramsTaintRequire);
    }

    public Set<Integer> getConditionSet() {
        return Collections.unmodifiableSet(conditionSet);
    }

    public boolean isDynamicProxyLinkCheck() {
        return dynamicProxyLinkCheck;
    }

    public void setDynamicProxyLinkCheck(boolean dynamicProxyLinkCheck) {
        this.dynamicProxyLinkCheck = dynamicProxyLinkCheck;
    }

    public boolean isReflectionCheck() {
        return reflectionCheck;
    }

    public void setReflectionCheck(boolean reflectionCheck) {
        this.reflectionCheck = reflectionCheck;
    }

    @Override
    public String toString() {
        return String.format("ConnectReq[methods=%d, taints=%s, proxy=%b, reflection=%b]",
            preLinkableMethods.size(), paramsTaintRequire, dynamicProxyLinkCheck, reflectionCheck);
    }
}
