import sys

print("Vulnerable Gadget Chains:")
print("=========================")

chain_num = 1
for line in sys.stdin:
    if line.strip().startswith('-> ChainStep'):
        if 'readObject' in line:
            print(f"\nChain {chain_num}:")
            chain_num += 1
        print(line.strip())