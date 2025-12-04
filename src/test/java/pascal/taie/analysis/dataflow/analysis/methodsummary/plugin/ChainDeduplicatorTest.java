package pascal.taie.analysis.dataflow.analysis.methodsummary.plugin;

import org.junit.jupiter.api.Test;
import pascal.taie.analysis.gadget.SinkType;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

public class ChainDeduplicatorTest {

    @Test
    public void testDeduplication() {
        // LCS threshold 0.8
        ChainDeduplicator deduplicator = new ChainDeduplicator(0.8);

        List<String> chain1 = Arrays.asList(
            "<A: void source()>", 
            "<B: void step1()>", 
            "<C: void sink()>"
        );
        
        List<String> chain2 = Arrays.asList(
            "<A: void source()>", 
            "<B: void step1()>", 
            "<C: void sink()>",
            "<D: void innerSink()>"
        );

        // Chain 1 is added
        assertTrue(deduplicator.addChain(chain1, Collections.emptyList(), null));
        assertEquals(1, deduplicator.getChainCount());

        // Chain 2 (super-chain of Chain 1) is added. Chain 1 should be removed.
        assertTrue(deduplicator.addChain(chain2, Collections.emptyList(), null));
        assertEquals(1, deduplicator.getChainCount());
        
        // Add Chain 1 again. Should be rejected because Chain 2 (longer) exists.
        assertFalse(deduplicator.addChain(chain1, Collections.emptyList(), null));
        assertEquals(1, deduplicator.getChainCount());
    }
    
    @Test
    public void testReverseOrder() {
        ChainDeduplicator deduplicator = new ChainDeduplicator(0.8);

        List<String> chain1 = Arrays.asList(
            "<A: void source()>", 
            "<B: void step1()>", 
            "<C: void sink()>"
        );
        
        List<String> chain2 = Arrays.asList(
            "<A: void source()>", 
            "<B: void step1()>", 
            "<C: void sink()>",
            "<D: void innerSink()>"
        );

        // Add longer chain FIRST
        assertTrue(deduplicator.addChain(chain2, Collections.emptyList(), null));
        assertEquals(1, deduplicator.getChainCount());

        // Add shorter chain (prefix). Should be rejected.
        assertFalse(deduplicator.addChain(chain1, Collections.emptyList(), null));
        assertEquals(1, deduplicator.getChainCount());
    }
    
    @Test
    public void testExactDuplicate() {
        ChainDeduplicator deduplicator = new ChainDeduplicator(0.8);
        List<String> chain = Arrays.asList("<A: void source()>", "<B: void sink()>");
        
        assertTrue(deduplicator.addChain(chain, Collections.emptyList(), null));
        assertFalse(deduplicator.addChain(chain, Collections.emptyList(), null)); // Exact duplicate
        assertEquals(1, deduplicator.getChainCount());
    }
    
    @Test
    public void testDifferentSources() {
        ChainDeduplicator deduplicator = new ChainDeduplicator(0.8);
        List<String> chain1 = Arrays.asList("<A: void source()>", "<B: void sink()>");
        List<String> chain2 = Arrays.asList("<X: void source()>", "<B: void sink()>"); // Different source
        
        assertTrue(deduplicator.addChain(chain1, Collections.emptyList(), null));
        assertTrue(deduplicator.addChain(chain2, Collections.emptyList(), null));
        assertEquals(2, deduplicator.getChainCount());
    }
    
    @Test
    public void testLCS() {
        // Use very high threshold to ensure LCS triggers rejection for similar chains
        ChainDeduplicator deduplicator = new ChainDeduplicator(0.5); 
        // A->B->C (len 3)
        // A->X->C (len 3). LCS = A, C (len 2). Sim = 4/6 = 0.66 > 0.5.
        // So they should be duplicates.
        
        List<String> chain1 = Arrays.asList("<A: void source()>", "<B: void step()>", "<C: void sink()>");
        List<String> chain2 = Arrays.asList("<A: void source()>", "<X: void step()>", "<C: void sink()>");
        
        assertTrue(deduplicator.addChain(chain1, Collections.emptyList(), null));
        assertFalse(deduplicator.addChain(chain2, Collections.emptyList(), null));
        assertEquals(1, deduplicator.getChainCount());
    }
}
