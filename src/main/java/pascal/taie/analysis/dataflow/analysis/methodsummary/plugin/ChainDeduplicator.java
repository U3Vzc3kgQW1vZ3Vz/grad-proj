package pascal.taie.analysis.dataflow.analysis.methodsummary.plugin;

import pascal.taie.analysis.gadget.SinkType;
import pascal.taie.analysis.graph.callgraph.Edge;
import pascal.taie.analysis.dataflow.analysis.methodsummary.plugin.SignatureUtil;

import java.util.*;
import java.util.stream.Collectors;

public class ChainDeduplicator {
    
    public static class ChainData {
        public final List<Edge> edges;
        public final SinkType sinkType;
        
        public ChainData(List<Edge> edges, SinkType sinkType) {
            this.edges = edges;
            this.sinkType = sinkType;
        }
    }

    private final Map<List<String>, ChainData> discoveredChains;
    private final Map<String, Set<List<String>>> dedupMap;
    private final double lcsThreshold;

    public ChainDeduplicator(double lcsThreshold) {
        this.lcsThreshold = lcsThreshold;
        this.discoveredChains = new java.util.concurrent.ConcurrentHashMap<>();
        this.dedupMap = new java.util.concurrent.ConcurrentHashMap<>();
    }

    public synchronized boolean addChain(List<String> chainSignatures, List<Edge> chainEdges, SinkType sinkType) {
        String key = chainSignatures.get(0);
        List<String> subSignatures = SignatureUtil.getSubSignatures(chainSignatures);

        dedupMap.putIfAbsent(key, new HashSet<>());
        Set<List<String>> bucket = dedupMap.get(key);
        Iterator<List<String>> it = bucket.iterator();

        while (it.hasNext()) {
            List<String> existingChain = it.next();

            if (isPrefix(chainSignatures, existingChain)) {
                return false; // New is subset of existing
            }

            if (isPrefix(existingChain, chainSignatures)) {
                discoveredChains.remove(existingChain); // Remove existing shorter chain
                it.remove();
                continue;
            }

            List<String> existingSub = SignatureUtil.getSubSignatures(existingChain);
            if (computeLCSSimilarity(existingSub, subSignatures) >= lcsThreshold) {
                return false; // Too similar
            }
        }

        bucket.add(chainSignatures);
        discoveredChains.put(chainSignatures, new ChainData(chainEdges, sinkType));
        return true;
    }

    public Collection<ChainData> getDiscoveredChains() {
        return discoveredChains.values();
    }
    
    public int getChainCount() {
        return discoveredChains.size();
    }

    private boolean isPrefix(List<String> shortList, List<String> longList) {
        if (shortList.size() > longList.size()) {
            return false;
        }
        return longList.subList(0, shortList.size()).equals(shortList);
    }



    private static int computeLCSLength(List<String> list1, List<String> list2) {
        int m = list1.size();
        int n = list2.size();

        if (m == 0 || n == 0) {
            return 0;
        }

        // Always use the smaller list for the rows to minimize space
        List<String> sList; // smaller list
        List<String> lList; // larger list
        if (m < n) {
            sList = list1;
            lList = list2;
            int temp = m; // swap m and n
            m = n;
            n = temp;
        } else {
            sList = list2;
            lList = list1;
        }

        int[] dp = new int[n + 1]; // dp[j] stores LCS length for sList[...i-1] and lList[...j-1]
        int[] prevDp = new int[n + 1]; // dp for the previous row

        for (int i = 1; i <= m; i++) {
            // Swap current and previous dp arrays
            int[] temp = prevDp;
            prevDp = dp;
            dp = temp;

            for (int j = 1; j <= n; j++) {
                if (lList.get(i - 1).equals(sList.get(j - 1))) {
                    dp[j] = prevDp[j - 1] + 1;
                } else {
                    dp[j] = Math.max(dp[j - 1], prevDp[j]);
                }
            }
        }
        return dp[n];
    }

    private static double computeLCSSimilarity(List<String> list1, List<String> list2) {
        if (list1.isEmpty() || list2.isEmpty()) {
            return 0.0;
        }
        int lcsLength = computeLCSLength(list1, list2);
        return (2.0 * lcsLength) / (list1.size() + list2.size());
    }
}
