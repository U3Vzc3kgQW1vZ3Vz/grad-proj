
import re
import sys

def parse_log_file(log_content):
    chain_tests = log_content.split('======================================================================\nTesting Chain ')
    
    vulnerable_chains = []
    for test in chain_tests:
        if '[Success] Exception during deserialization:' in test:
            chain_lines = []
            for line in test.split('\n'):
                if line.strip().startswith('-> ChainStep'):
                    chain_lines.append(line.strip())
            vulnerable_chains.append(chain_lines)
            
    return vulnerable_chains

if __name__ == '__main__':
    log_content = sys.stdin.read()
    vulnerable_chains = parse_log_file(log_content)
    
    if vulnerable_chains:
        print("Vulnerable Gadget Chains:")
        print("=========================")
        for i, chain in enumerate(vulnerable_chains, 1):
            print(f"\nChain {i}:")
            for step in chain:
                print(step)

