package pascal.taie.analysis.dataflow.analysis.methodsummary.plugin;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import pascal.taie.World;
import pascal.taie.analysis.dataflow.analysis.methodsummary.Utils.ContrUtil;
import pascal.taie.analysis.gadget.*;
import pascal.taie.analysis.gadget.sink.*;
import pascal.taie.analysis.graph.callgraph.CallKind;
import pascal.taie.analysis.graph.callgraph.Edge;
import pascal.taie.analysis.pta.core.cs.CSCallGraph;
import pascal.taie.analysis.pta.core.cs.element.CSCallSite;
import pascal.taie.analysis.pta.core.cs.element.CSMethod;
import pascal.taie.language.classes.JMethod;
import pascal.taie.language.type.Type;
import pascal.taie.language.type.TypeSystem;
import pascal.taie.util.Strings;
import pascal.taie.util.collection.Lists;

import java.io.*;
import java.util.*;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

/**
 * Enhanced gadget chain collector using fragment-based approach.
 * Integrates the modular sink detection framework with backward DFS search.
 *
 * This combines:
 * - Original backward DFS algorithm from GCCollectorAfterProcess
 * - Fragment-based chain representation
 * - Extensible sink detection rules
 * - Improved modularity and maintainability
 */
public class GCCollectorAfterProcess implements Plugin {

    private static final Logger logger = LogManager.getLogger(GCCollectorAfterProcess.class);

    private final CSCallGraph csCallGraph;
    private final TypeSystem typeSystem;
    private final String output;
    private final GadgetAnalyzer gadgetAnalyzer;
    private final FragmentContainer fragmentContainer;

    // Configuration
    private static final int MAX_LEN = World.get().getOptions().getGC_MAX_LEN();
    private int SINK_MAX_TIME;
    private static final double LCS_THRESHOLD = World.get().getOptions().getLCS_THRESHOLD();

    // Output and deduplication
    private final Set<List<String>> discoveredChains;
    private final PrintWriter pw;
    private final Map<String, Set<List<String>>> dedupMap;

    public GCCollectorAfterProcess(CSCallGraph csCallGraph, String db_path) {
        super();
        this.csCallGraph = csCallGraph;
        this.typeSystem = World.get().getTypeSystem();
        this.output = db_path;
        this.discoveredChains = new HashSet<>();
        this.dedupMap = new HashMap<>();

        // Initialize gadget analyzer with sink rules
        this.gadgetAnalyzer = new GadgetAnalyzer();
        initializeSinkRules();
        this.fragmentContainer = gadgetAnalyzer.getFragmentContainer();

        // Setup output
        try {
            File output_file = new File(World.get().getOptions().getOutputDir(), this.output);
            this.pw = new PrintWriter(new BufferedWriter(new FileWriter(output_file)));
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * Initialize sink detection rules
     */
    private void initializeSinkRules() {
        // Core sink rules
        gadgetAnalyzer.registerSinkRule(new ExecSinkRule());
        gadgetAnalyzer.registerSinkRule(new JNDISinkRule());
        gadgetAnalyzer.registerSinkRule(new InvokeSinkRule());

        // Additional sink rules from jdd
        gadgetAnalyzer.registerSinkRule(new FileSinkRule());
        gadgetAnalyzer.registerSinkRule(new ClassLoaderSinkRule());
        gadgetAnalyzer.registerSinkRule(new SecondDeserializationSinkRule());
        gadgetAnalyzer.registerSinkRule(new CustomSinkRule());
        gadgetAnalyzer.registerSinkRule(new SSRFSinkRule());
        gadgetAnalyzer.registerSinkRule(new FileReadSinkRule());
        gadgetAnalyzer.registerSinkRule(new CodeInjectionSinkRule());
        gadgetAnalyzer.registerSinkRule(new RMISinkRule());

        logger.info("Initialized {} sink rules",
            gadgetAnalyzer.getFragmentContainer().getSinkRules().size());
    }

    @Override
    public void onFinish() {
        Set<JMethod> sinks = World.get().getSinks();

        logger.info("Starting gadget chain collection from {} sinks", sinks.size());

        for (JMethod sink : sinks) {
            logger.info("backward from {}", sink.toString());
            // Try to classify sink type, but process all sinks regardless
            Optional<SinkType> sinkType = fragmentContainer.getSinkType(sink);
            collectChainsFromSink(sink, sinkType.orElse(null));
        }

        logger.info("total gadget chains : {}", discoveredChains.size());
        pw.println("total gadget chains : " + discoveredChains.size());

        // Print statistics by sink type
        printStatisticsBySinkType();

        pw.flush();
    }

    /**
     * Collect gadget chains from a specific sink using backward DFS
     */
    private void collectChainsFromSink(JMethod sink, SinkType sinkType) {
        List<Edge> currentPath = new ArrayList<>();
        List<Integer> sinkTaintConstraints = Arrays.stream(sink.getSink())
            .boxed()
            .collect(Collectors.toList());

        Set<Edge<CSCallSite, CSMethod>> incomingEdges = new HashSet<>(csCallGraph.edgesInTo(sink));

        // Count valid edges for time allocation
        int validEdgeCount = 0;
        for (Edge<CSCallSite, CSMethod> edge : incomingEdges) {
            List<Integer> newTCList = getNewTCList(sinkTaintConstraints, edge.getCSIntContr());
            if (ContrUtil.allControllable(newTCList)) {
                validEdgeCount++;
            }
        }

        if (validEdgeCount == 0) {
            logger.debug("No valid incoming edges for sink {}", sink);
            return;
        }

        // Allocate time per edge
        SINK_MAX_TIME = (World.get().getOptions().getSINK_MAX_TIME() * 1000) / validEdgeCount;

        // Perform backward DFS from each incoming edge
        for (Edge<CSCallSite, CSMethod> edge : incomingEdges) {
            long startTime = System.currentTimeMillis();
            backwardDFS(sink, edge, currentPath, new HashSet<>(),
                       sinkTaintConstraints, startTime, sinkType);
        }
    }

    /**
     * Backward DFS to discover gadget chains from sink to source
     *
     * @param callee Current method being visited
     * @param curEdge Current edge in the call graph
     * @param currentPath Current chain being built
     * @param visited Methods already visited (for cycle detection)
     * @param taintConstraints Current taint constraints
     * @param startTime Search start time (for timeout)
     * @param sinkType Type of sink for classification
     */
    private void backwardDFS(JMethod callee, Edge curEdge, List<Edge> currentPath,
                            Set<JMethod> visited, List<Integer> taintConstraints,
                            Long startTime, SinkType sinkType) {

        // Check termination conditions
        if (!visited.add(callee) || System.currentTimeMillis() - startTime > SINK_MAX_TIME) {
            return;
        }

        // Check taint controllability
        List<Integer> newTaintConstraints = getNewTCList(taintConstraints, curEdge.getCSIntContr());
        if (!ContrUtil.allControllable(newTaintConstraints)) {
            visited.remove(callee);
            return;
        }

        JMethod caller = CSCallGraph.getCaller(curEdge);
        currentPath.add(curEdge);

        if (caller.isSource()) {
            // Found a complete chain from source to sink!
            List<Edge> completeChain = new ArrayList<>(currentPath);

            if (validateChain(completeChain)) {
                List<Edge> simplifiedChain = simplifyChain(completeChain);
                List<String> chainSignatures = getChainSignatures(simplifiedChain);

                if (deduplicateChain(chainSignatures) && discoveredChains.add(chainSignatures)) {
                    logAndWriteChain(simplifiedChain, sinkType);
                }
            }
        } else if (currentPath.size() >= MAX_LEN) {
            // Reached maximum chain length
            visited.remove(callee);
            currentPath.remove(currentPath.size() - 1);
            return;
        } else {
            // Continue backward search
            Set<Edge<CSCallSite, CSMethod>> incomingEdges = new HashSet<>(csCallGraph.edgesInTo(caller));
            for (Edge<CSCallSite, CSMethod> edge : incomingEdges) {
                backwardDFS(caller, edge, currentPath, visited,
                           newTaintConstraints, startTime, sinkType);
            }
        }

        // Backtrack
        visited.remove(callee);
        currentPath.remove(currentPath.size() - 1);
    }

    /**
     * Validate chain by applying filters
     */
    private boolean validateChain(List<Edge> chain) {
        return !filterChainByEdgeRules(chain) && typeCheckChain(chain);
    }

    /**
     * Deduplicate chains using LCS similarity
     */
    private boolean deduplicateChain(List<String> chainSignatures) {
        String key = chainSignatures.get(0) + "#" + chainSignatures.get(chainSignatures.size() - 1);
        List<String> subSignatures = getSubSignatures(chainSignatures);

        dedupMap.putIfAbsent(key, new HashSet<>());

        for (List<String> existingChain : dedupMap.get(key)) {
            if (computeLCSSimilarity(existingChain, subSignatures) >= LCS_THRESHOLD) {
                return false; // Too similar to existing chain
            }
        }

        dedupMap.get(key).add(subSignatures);
        return true;
    }

    public static int computeLCSLength(List<String> list1, List<String> list2) {
        int m = list1.size();
        int n = list2.size();
        int[][] dp = new int[m + 1][n + 1];

        for (int i = 1; i <= m; i++) {
            String s1 = list1.get(i - 1);
            for (int j = 1; j <= n; j++) {
                String s2 = list2.get(j - 1);
                if (s1.equals(s2)) {
                    dp[i][j] = dp[i - 1][j - 1] + 1;
                } else {
                    dp[i][j] = Math.max(dp[i - 1][j], dp[i][j - 1]);
                }
            }
        }

        return dp[m][n];
    }

    /**
     * Similarity of two gadget chains
     */
    private static double computeLCSSimilarity(List<String> list1, List<String> list2) {
        if (list1.isEmpty() || list2.isEmpty()) {
            return 0.0;
        }
        int lcsLength = computeLCSLength(list1, list2);
        return (2.0 * lcsLength) / (list1.size() + list2.size());
    }

    private List<String> getSubSignatures(List<String> signatures) {
        return signatures.stream()
            .map(this::getSubSignature)
            .collect(Collectors.toList());
    }

    private List<String> getChainSignatures(List<Edge> chainEdges) {
        List<String> signatures = new ArrayList<>();
        for (Edge edge : chainEdges) {
            signatures.add(CSCallGraph.getCaller(edge).toString());
        }
        signatures.add(CSCallGraph.getCallee(chainEdges.get(chainEdges.size() - 1)).toString());
        return signatures;
    }

    /**
     * Log and write discovered chain
     */
    private void logAndWriteChain(List<Edge> chainEdges, SinkType sinkType) {
        try {
            // Only print sink type if it's classified
            if (sinkType != null) {
                pw.println("# Sink Type: " + sinkType);
            }

            for (int i = 0; i < chainEdges.size(); i++) {
                Edge edge = chainEdges.get(i);
                String caller = CSCallGraph.getCaller(edge).toString();
                StringBuilder line = new StringBuilder(caller);
                line.append("->").append(edge.getCSIntContr());

                pw.println(line.toString());
            }

            String sink = CSCallGraph.getCallee(chainEdges.get(chainEdges.size() - 1)).toString();
            logger.info(sink);
            pw.println(sink);
            logger.info("");
            pw.println("");
            pw.flush();

        } catch (Exception e) {
            logger.info(e);
        }
    }

    private boolean filterChainByEdgeRules(List<Edge> edgeList) {
        for (int i = 0; i < edgeList.size(); i++) {
            Edge edge = edgeList.get(i);
            if (edge.needFilterByCaller()) {
                List<Edge> callers = edgeList.subList(i + 1, edgeList.size());
                return filterByCaller(edge, callers);
            }
        }
        return false;
    }

    /**
     * Simplify chain by removing redundant intermediate gadgets
     */
    private List<Edge> simplifyChain(List<Edge> edgeList) {
        List<Edge> gcEdgeList = new ArrayList<>(edgeList);
        Collections.reverse(gcEdgeList);

        List<String> subSigList = new ArrayList<>();
        List<Edge> simplifiedChain = new ArrayList<>();
        String source = CSCallGraph.getCaller(gcEdgeList.get(0)).toString();

        for (int i = 0; i < gcEdgeList.size(); i++) {
            Edge edge = gcEdgeList.get(i);
            String gadget = CSCallGraph.getCaller(edge).toString();
            String subSig = getSubSignature(gadget);

            if (subSigList.contains(subSig)) {
                int from = subSigList.lastIndexOf(subSig);
                if (from != 0) {
                    int end = subSigList.size();
                    Edge fromEdge = simplifiedChain.get(from - 1);

                    if (fromEdge.getKind() != CallKind.STATIC) {
                        List<Integer> tcList = getTCList(gadget, edgeList);
                        if (tcList != null) {
                            List<Edge> sourceEdgeList = new ArrayList<>(simplifiedChain.subList(0, from));
                            Collections.reverse(sourceEdgeList);
                            Map<String, List<Integer>> tcMap = recoveryTCMap(sourceEdgeList, tcList);

                            if (tcMap.containsKey(source)) {
                                // Remove redundant segment
                                Lists.clearList(subSigList, from, end);
                                Lists.clearList(simplifiedChain, from - 1, end);

                                // Create replacement edge
                                CSCallSite csCallSite = (CSCallSite) fromEdge.getCallSite();
                                CSMethod csCallee = csCallGraph.getCSMethod(gadget);
                                Edge replaceEdge = new Edge<>(fromEdge.getKind(), csCallSite, csCallee,
                                    fromEdge.getCSContr(), fromEdge.getLineNo(), fromEdge.getTypeList());
                                csCallGraph.addEdge(replaceEdge);
                                simplifiedChain.add(replaceEdge);
                            }
                        }
                    }
                }
            }

            subSigList.add(subSig);
            simplifiedChain.add(edge);
        }

        return simplifiedChain;
    }

    private List<Integer> getNewTCList(List<Integer> tcList, List<Integer> csIntContr) {
        List<Integer> tempTC = new ArrayList<>();
        for (int i = 0; i < tcList.size(); i++) {
            Integer tc = tcList.get(i);
            Integer newTC = tc > ContrUtil.iPOLLUTED ? csIntContr.get(tc + 1) : ContrUtil.iPOLLUTED;
            if (!tempTC.contains(newTC)) tempTC.add(newTC);
        }
        return tempTC;
    }

    private List<Integer> getTCList(String tcKey, List<Edge> edgeList) {
        JMethod sink = CSCallGraph.getCallee(edgeList.get(0));

        List<Edge> subEdgeList = new ArrayList<>();
        for (Edge edge : edgeList) {
            if (CSCallGraph.getCallee(edge).toString().equals(tcKey)) {
                break;
            } else {
                subEdgeList.add(edge);
            }
        }

        List<Integer> sinkTC = Arrays.stream(sink.getSink()).boxed().collect(Collectors.toList());
        Map<String, List<Integer>> tcMap = recoveryTCMap(subEdgeList, sinkTC);
        return tcMap.getOrDefault(tcKey, null);
    }

    /**
     * Filter edge containing reflection or invoke
     */
    private boolean filterByCaller(Edge edge, List<Edge> callers) {
        String filter = edge.getFilterByCaller();
        String value = filter.split(":")[1];

        if (filter.contains("name")) {
            if (callers.isEmpty()) {
                return true;
            }

            String name = value.split("#")[0];
            int idx = Strings.extractParamIndex(value.split("#")[1]) + 1;

            for (Edge caller : callers) {
                String edgeValue = (String) caller.getCSContr().get(idx);
                if (ContrUtil.isControllableParam(edgeValue)) {
                    idx = Strings.extractParamIndex(edgeValue) + 1;
                } else if (ContrUtil.isControllable(edgeValue)) {
                    return false;
                } else if (!ContrUtil.isControllable(edgeValue)) {
                    String invokeTarget = ((CSCallSite) caller.getCallSite())
                        .getCallSite().getInvokeExp().getMethodRef().getName();
                    return !invokeTarget.equals(name);
                }
            }
        } else {
            int idx = Strings.extractParamIndex(value) + 1;
            for (Edge caller : callers) {
                String edgeValue = (String) caller.getCSContr().get(idx);
                if (ContrUtil.hasCS(edgeValue) || ContrUtil.isThis(edgeValue)) {
                    String nameReg = ContrUtil.convert2Reg(edgeValue);
                    boolean hasStar = nameReg.contains("*");

                    Pattern pattern;
                    try {
                        pattern = Pattern.compile(nameReg);
                    } catch (Exception e) {
                        return true;
                    }

                    String callee = CSCallGraph.getCallee(edge).getName();
                    boolean match = hasStar ? pattern.matcher(callee).find() :
                                             callee.equals(nameReg);
                    if (!match) return true;
                    break;
                } else if (ContrUtil.isControllableParam(edgeValue)) {
                    idx = Strings.extractParamIndex(edgeValue) + 1;
                } else {
                    return true;
                }
            }
        }
        return false;
    }

    /**
     * Type check chain for compatibility
     */
    private boolean typeCheckChain(List<Edge> edgeList) {
        List<Edge> reversedChain = new ArrayList<>(edgeList);
        Collections.reverse(reversedChain);

        List<Type> passType = null;
        for (int i = 0; i < reversedChain.size(); i++) {
            Edge edge = reversedChain.get(i);

            JMethod callee = CSCallGraph.getCallee(edge);
            JMethod invokeRef = CSCallGraph.getInvokeRef(edge);

            if (invokeRef.hasImitatedBehavior()) {
                return true;
            }

            if (callee.isInvoke()) {
                return filterCast(reversedChain, i + 1);
            }

            List<Type> paramsType = getParamsType(callee);
            List<Integer> edgeContr = edge.getCSIntContr();
            passType = getNewPassType(edgeContr, edge.getTypeList(), passType, paramsType);

            if (!typeSystem.hasSubRelation(paramsType, passType)) {
                return false;
            }
        }
        return true;
    }

    private boolean filterCast(List<Edge> chainEdges, int startIndex) { // no cast in dynamic proxy
        List<Edge> tempEdgeList = chainEdges.subList(0, startIndex);
        Collections.reverse(tempEdgeList);

        List<Integer> tc = new ArrayList<>();
        tc.add(-1);

        for (Edge edge : tempEdgeList) {
            if (edge.isCasted(tc.get(0) + 1)) {
                return false;
            }
            tc = getNewTCList(tc, edge.getCSIntContr());
        }
        return true;
    }

    private String getSubSignature(String method) {
        String sub = method.split(":")[1];
        return sub.substring(1, sub.length() - 1);
    }

    private List<Type> getParamsType(JMethod method) {
        List<Type> ret = new ArrayList<>(method.getParamTypes());
        ret.add(0, method.getDeclaringClass().getType());
        return ret;
    }

    private Map<String, List<Integer>> recoveryTCMap(List<Edge> edgeList, List<Integer> tcList) {
        Map<String, List<Integer>> tempTCMap = new HashMap<>();
        for (Edge edge : edgeList) {
            tcList = getNewTCList(tcList, edge.getCSIntContr());
            if (!ContrUtil.allControllable(tcList)) return tempTCMap;
            JMethod sGadget = CSCallGraph.getCaller(edge);
            tempTCMap.put(sGadget.toString(), tcList);
        }
        return tempTCMap;
    }

    private List<Type> getNewPassType(List<Integer> edgeContr, List<Type> edgeType, List<Type> passType, List<Type> paramsType) {
        List<Type> ret = new ArrayList<>();
        for (int i = 0; i < edgeContr.size(); i++) {
            int c = edgeContr.get(i);
            if (c > ContrUtil.iTHIS) {
                ret.add(passType != null ? passType.get(c + 1) : edgeType.get(i));
            } else if (c == ContrUtil.iTHIS) {
                ret.add(edgeType.get(i));
            } else {
                ret.add(paramsType.get(i));
            }
        }
        return ret;
    }

    /**
     * Print statistics by sink type
     */
    private void printStatisticsBySinkType() {
        pw.println("\n=== Statistics ===");
        pw.println("Total unique chains: " + discoveredChains.size());

        for (SinkRule rule : fragmentContainer.getSinkRules()) {
            pw.println("Sink rule: " + rule.getDescription());
        }
    }
}
