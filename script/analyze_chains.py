#!/usr/bin/env python3
"""
Chain Analysis Tool for Flash Gadget Chain Discovery Framework

This script analyzes the output chain files from Flash to extract:
1. Chain length statistics (min, max, average, median, distribution)
2. Sink type distribution (count and percentage by sink category)

Usage:
    python analyze_chains.py <chain_file>
    python analyze_chains.py output/chains-groovy-1
    python analyze_chains.py output/chains-*  # Analyze all chain files
"""

import sys
import re
from collections import Counter, defaultdict
from pathlib import Path


def parse_chain_file(filepath):
    """
    Parse a chain file and extract chain information.

    Returns:
        tuple: (chains, sink_distribution)
            - chains: list of chain lengths
            - sink_distribution: dict mapping sink types to counts
    """
    chains = []
    sink_distribution = defaultdict(int)

    with open(filepath, 'r') as f:
        content = f.read()

    current_sink = None
    current_chain = []

    for line in content.split('\n'):
        line = line.strip()

        # Parse total count header
        if line.startswith('total gadget chains'):
            match = re.search(r'total gadget chains\s*:\s*(\d+)', line)
            if match:
                total_count = int(match.group(1))

        # Parse sink type
        elif line.startswith('# Sink Type:'):
            # Save previous chain if exists
            if current_chain and current_sink:
                chains.append(len(current_chain))
                sink_distribution[current_sink] += 1

            # Extract sink type
            match = re.search(r'# Sink Type:\s*(\w+)', line)
            if match:
                current_sink = match.group(1)
            current_chain = []

        # Parse method signature (chain element)
        elif line.startswith('<') and '>' in line:
            current_chain.append(line)

        # Empty line indicates end of chain
        elif not line and current_chain:
            if current_sink:
                chains.append(len(current_chain))
                sink_distribution[current_sink] += 1
            current_chain = []
            current_sink = None

    # Handle last chain if file doesn't end with empty line
    if current_chain and current_sink:
        chains.append(len(current_chain))
        sink_distribution[current_sink] += 1

    return chains, dict(sink_distribution)


def calculate_statistics(chains):
    """Calculate statistical measures for chain lengths."""
    if not chains:
        return None

    sorted_chains = sorted(chains)
    length_dist = Counter(chains)

    stats = {
        'count': len(chains),
        'min': min(chains),
        'max': max(chains),
        'average': sum(chains) / len(chains),
        'median': sorted_chains[len(chains) // 2],
        'distribution': dict(length_dist)
    }

    return stats


def print_chain_statistics(filepath, chains, sink_dist):
    """Print formatted chain statistics."""
    filename = Path(filepath).name

    print(f"\n{'='*80}")
    print(f"Analysis of: {filename}")
    print(f"{'='*80}")

    if not chains:
        print("No chains found in file.")
        return

    stats = calculate_statistics(chains)

    # Chain length statistics
    print(f"\n📊 CHAIN LENGTH STATISTICS")
    print(f"{'─'*80}")
    print(f"  Total Chains:     {stats['count']}")
    print(f"  Minimum Length:   {stats['min']} methods")
    print(f"  Maximum Length:   {stats['max']} methods")
    print(f"  Average Length:   {stats['average']:.2f} methods")
    print(f"  Median Length:    {stats['median']} methods")

    # Length distribution histogram
    print(f"\n  Length Distribution:")
    max_count = max(stats['distribution'].values())
    for length in sorted(stats['distribution'].keys()):
        count = stats['distribution'][length]
        percentage = (count / stats['count']) * 100
        bar_length = int((count / max_count) * 40)
        bar = '█' * bar_length
        print(f"    {length:2d} methods: {bar:<40s} {count:4d} ({percentage:5.1f}%)")

    # Sink type distribution
    print(f"\n🎯 SINK TYPE DISTRIBUTION")
    print(f"{'─'*80}")
    total_sinks = sum(sink_dist.values())

    if total_sinks > 0:
        # Sort by count (descending)
        sorted_sinks = sorted(sink_dist.items(), key=lambda x: x[1], reverse=True)

        for sink_type, count in sorted_sinks:
            percentage = (count / total_sinks) * 100
            bar_length = int((count / total_sinks) * 50)
            bar = '▓' * bar_length
            print(f"  {sink_type:20s}: {bar:<50s} {count:4d} ({percentage:5.1f}%)")
    else:
        print("  No sink type information found.")


def print_summary_table(results):
    """Print a summary table comparing all analyzed files."""
    if len(results) <= 1:
        return

    print(f"\n{'='*80}")
    print(f"SUMMARY COMPARISON")
    print(f"{'='*80}\n")

    # Chain length comparison table
    print(f"Chain Length Statistics:")
    print(f"{'─'*80}")
    print(f"{'Library':<25} {'Chains':>8} {'Min':>6} {'Max':>6} {'Avg':>8} {'Median':>8}")
    print(f"{'─'*80}")

    for filename, (chains, _) in results.items():
        if chains:
            stats = calculate_statistics(chains)
            lib_name = filename.replace('chains-', '').replace('-1', '')
            print(f"{lib_name:<25} {stats['count']:>8} {stats['min']:>6} "
                  f"{stats['max']:>6} {stats['average']:>8.2f} {stats['median']:>8}")

    # Sink type comparison
    print(f"\n{'─'*80}")
    print(f"Sink Type Distribution by Library:")
    print(f"{'─'*80}")

    # Collect all unique sink types
    all_sinks = set()
    for _, (_, sink_dist) in results.items():
        all_sinks.update(sink_dist.keys())

    if all_sinks:
        # Print header
        libs = [filename.replace('chains-', '').replace('-1', '') for filename in results.keys()]
        print(f"{'Sink Type':<20}", end='')
        for lib in libs:
            print(f"{lib:>15}", end='')
        print()
        print(f"{'─'*80}")

        # Print each sink type
        for sink_type in sorted(all_sinks):
            print(f"{sink_type:<20}", end='')
            for filename in results.keys():
                _, sink_dist = results[filename]
                count = sink_dist.get(sink_type, 0)
                if count > 0:
                    total = sum(sink_dist.values())
                    pct = (count / total * 100) if total > 0 else 0
                    print(f"{count:>7} ({pct:4.1f}%)", end='')
                else:
                    print(f"{'':>15}", end='')
            print()


def main():
    """Main entry point."""
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)

    # Collect all matching files
    chain_files = []
    for arg in sys.argv[1:]:
        path = Path(arg)
        if path.is_file():
            chain_files.append(path)
        elif '*' in arg or '?' in arg:
            # Handle glob patterns
            import glob
            chain_files.extend([Path(p) for p in glob.glob(arg)])

    if not chain_files:
        print("Error: No valid chain files found.")
        sys.exit(1)

    # Analyze each file
    results = {}
    for filepath in chain_files:
        try:
            chains, sink_dist = parse_chain_file(filepath)
            results[filepath.name] = (chains, sink_dist)
            print_chain_statistics(filepath, chains, sink_dist)
        except Exception as e:
            print(f"Error analyzing {filepath}: {e}", file=sys.stderr)

    # Print summary if multiple files
    if len(results) > 1:
        print_summary_table(results)

    print(f"\n{'='*80}")
    print(f"Analysis complete. Processed {len(results)} file(s).")
    print(f"{'='*80}\n")


if __name__ == '__main__':
    main()
