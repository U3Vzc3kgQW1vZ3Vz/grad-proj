#!/usr/bin/env python3
"""
Performance Analysis Tool for Flash Gadget Chain Discovery Framework

This script analyzes execution logs from Flash to extract performance and scalability metrics:
1. World Building Time
2. Call Graph Construction Time
3. Dataflow Analysis Time
4. Gadget Collection Time
5. Total Execution Time
6. Codebase Size (classes and methods)
7. Scalability Analysis (time vs. size relationships)

Usage:
    python3 analyze_performance.py <log_file>
    python3 analyze_performance.py output/log/log-groovy.log
    python3 analyze_performance.py output/log/*.log  # Analyze all logs
"""

import sys
import re
import os
from pathlib import Path
from collections import defaultdict


def get_jar_info(library_name):
    """
    Get JAR file information (size and version) for a library.

    Returns:
        tuple: (total_size_bytes, jar_files_info_list)
    """
    # Map library names to target directories
    lib_map = {
        'groovy': 'Groovy',
        'cb': 'CB',
        'cb-1': 'CB',
        'c3p0': 'C3P0',
        'fileupload': 'FileUpload',
        'fileupload-1': 'FileUpload',
        'vaadin': 'Vaadin'
    }

    target_dir_name = lib_map.get(library_name.lower())
    if not target_dir_name:
        return None, []

    # Try to find the target directory
    possible_paths = [
        Path(f'java-benchmarks/JDV/target/{target_dir_name}'),
        Path(f'./java-benchmarks/JDV/target/{target_dir_name}'),
        Path(f'../java-benchmarks/JDV/target/{target_dir_name}'),
    ]

    target_dir = None
    for path in possible_paths:
        if path.exists() and path.is_dir():
            target_dir = path
            break

    if not target_dir:
        return None, []

    # Collect JAR file information
    jar_files = []
    total_size = 0

    for jar_file in target_dir.glob('*.jar'):
        size = jar_file.stat().st_size
        total_size += size

        # Extract version from filename
        filename = jar_file.name
        # Try to match version patterns like: name-1.2.3.jar or name-1.2.3-SNAPSHOT.jar
        version_match = re.search(r'-(\d+(?:\.\d+)*(?:-[A-Za-z0-9]+)?)', filename.replace('.jar', ''))
        version = version_match.group(1) if version_match else 'unknown'

        jar_files.append({
            'name': filename,
            'version': version,
            'size': size
        })

    return total_size, jar_files


def parse_log_file(filepath):
    """
    Parse a Flash execution log and extract performance metrics.

    Returns:
        dict: Performance metrics including times and codebase statistics
    """
    metrics = {
        'world_building_time': None,
        'call_graph_time': None,
        'dataflow_time': None,
        'gadget_collection_time': None,
        'total_time': None,
        'num_classes': None,
        'num_methods': None,
        'num_sinks': None,
        'total_chains': None
    }

    with open(filepath, 'r') as f:
        content = f.read()

    # Extract world building time and codebase size
    # Pattern: "9786 classes with 90757 methods in the world"
    world_pattern = r'(\d+)\s+classes\s+with\s+(\d+)\s+methods\s+in\s+the\s+world'
    match = re.search(world_pattern, content)
    if match:
        metrics['num_classes'] = int(match.group(1))
        metrics['num_methods'] = int(match.group(2))

    # Extract world building time
    # Pattern: "WorldBuilder finishes, elapsed time: 18.68s"
    world_time_pattern = r'WorldBuilder finishes,\s+elapsed time:\s+([\d.]+)s'
    match = re.search(world_time_pattern, content)
    if match:
        metrics['world_building_time'] = float(match.group(1))

    # Extract call graph construction time
    # Pattern: "deserialization call graph finishes, elapsed time: 24.68s"
    cg_pattern = r'deserialization call graph finishes,\s+elapsed time:\s+([\d.]+)s'
    match = re.search(cg_pattern, content)
    if match:
        metrics['call_graph_time'] = float(match.group(1))

    # Extract dataflow analysis time
    # Pattern: "[Dataflow analysis] elapsed time: 24.73s"
    df_pattern = r'\[Dataflow analysis\]\s+elapsed time:\s+([\d.]+)s'
    match = re.search(df_pattern, content)
    if match:
        metrics['dataflow_time'] = float(match.group(1))

    # Extract number of sinks
    # Pattern: "Starting gadget chain collection from 37 sinks"
    sinks_pattern = r'Starting gadget chain collection from\s+(\d+)\s+sinks'
    match = re.search(sinks_pattern, content)
    if match:
        metrics['num_sinks'] = int(match.group(1))

    # Extract gadget collection time
    # Pattern: "collect gc finishes, elapsed time: 272.49s"
    gc_pattern = r'collect gc finishes,\s+elapsed time:\s+([\d.]+)s'
    match = re.search(gc_pattern, content)
    if match:
        metrics['gadget_collection_time'] = float(match.group(1))

    # Extract total chains discovered
    # Pattern: "total gadget chains : 1534"
    chains_pattern = r'total gadget chains\s*:\s*(\d+)'
    match = re.search(chains_pattern, content)
    if match:
        metrics['total_chains'] = int(match.group(1))

    # Calculate total time (sum of all phases)
    if all([metrics['world_building_time'], metrics['call_graph_time'],
            metrics['gadget_collection_time']]):
        metrics['total_time'] = (
            metrics['world_building_time'] +
            metrics['call_graph_time'] +
            metrics['gadget_collection_time']
        )

    return metrics


def format_time(seconds):
    """Format time in human-readable format."""
    if seconds is None:
        return "N/A"
    if seconds < 60:
        return f"{seconds:.2f}s"
    elif seconds < 3600:
        minutes = int(seconds // 60)
        secs = seconds % 60
        return f"{minutes}m {secs:.2f}s"
    else:
        hours = int(seconds // 3600)
        minutes = int((seconds % 3600) // 60)
        secs = seconds % 60
        return f"{hours}h {minutes}m {secs:.2f}s"


def calculate_rates(metrics):
    """Calculate performance rates (chains/sec, methods/sec, etc.)."""
    rates = {}

    if metrics['total_time'] and metrics['total_chains']:
        rates['chains_per_second'] = metrics['total_chains'] / metrics['total_time']

    if metrics['call_graph_time'] and metrics['num_methods']:
        rates['methods_per_second_cg'] = metrics['num_methods'] / metrics['call_graph_time']

    if metrics['gadget_collection_time'] and metrics['num_sinks']:
        rates['time_per_sink'] = metrics['gadget_collection_time'] / metrics['num_sinks']

    if metrics['total_time'] and metrics['num_methods']:
        rates['methods_per_second_total'] = metrics['num_methods'] / metrics['total_time']

    return rates


def format_size(size_bytes):
    """Format bytes in human-readable format."""
    if size_bytes is None:
        return "N/A"
    for unit in ['B', 'KB', 'MB', 'GB']:
        if size_bytes < 1024.0:
            return f"{size_bytes:.2f} {unit}"
        size_bytes /= 1024.0
    return f"{size_bytes:.2f} TB"


def print_performance_report(filepath, metrics):
    """Print detailed performance report for a single log file."""
    filename = Path(filepath).name
    library_name = filename.replace('log-', '').replace('.log', '')

    print(f"\n{'='*80}")
    print(f"Performance Analysis: {library_name.upper()}")
    print(f"{'='*80}")

    # JAR File Information
    total_jar_size, jar_files = get_jar_info(library_name)
    if jar_files:
        print(f"\n📚 LIBRARY INFORMATION")
        print(f"{'─'*80}")
        for jar in jar_files:
            print(f"  {jar['name']}")
            print(f"    Version: {jar['version']:<15s} Size: {format_size(jar['size'])}")
        if len(jar_files) > 1:
            print(f"  {'─'*78}")
            print(f"  Total JAR Size:       {format_size(total_jar_size)}")

    # Codebase Size
    print(f"\n📦 CODEBASE SIZE")
    print(f"{'─'*80}")
    if metrics['num_classes'] is not None:
        print(f"  Classes:              {metrics['num_classes']:>8,}")
        print(f"  Methods:              {metrics['num_methods']:>8,}")
    else:
        print("  Codebase size information not available")

    if metrics['num_sinks'] is not None:
        print(f"  Identified Sinks:     {metrics['num_sinks']:>8,}")
    if metrics['total_chains'] is not None:
        print(f"  Discovered Chains:    {metrics['total_chains']:>8,}")

    # Timing Breakdown
    print(f"\n⏱️  EXECUTION TIME BREAKDOWN")
    print(f"{'─'*80}")

    times = [
        ("World Building", metrics['world_building_time']),
        ("Call Graph Construction", metrics['call_graph_time']),
        ("Dataflow Analysis", metrics['dataflow_time']),
        ("Gadget Collection", metrics['gadget_collection_time']),
    ]

    total = metrics['total_time']
    max_time = max([t for _, t in times if t is not None] or [0])

    for phase, time in times:
        if time is not None:
            percentage = (time / total * 100) if total else 0
            bar_length = int((time / max_time) * 40) if max_time > 0 else 0
            bar = '█' * bar_length
            print(f"  {phase:<25s}: {bar:<40s} {format_time(time):>10s} ({percentage:>5.1f}%)")
        else:
            print(f"  {phase:<25s}: {'N/A':>51s}")

    if total:
        print(f"  {'─'*78}")
        print(f"  {'TOTAL EXECUTION TIME':<25s}: {' '*40} {format_time(total):>10s}")

    # Performance Rates
    rates = calculate_rates(metrics)
    if rates:
        print(f"\n📊 PERFORMANCE RATES")
        print(f"{'─'*80}")

        if 'chains_per_second' in rates:
            print(f"  Chain Discovery Rate:     {rates['chains_per_second']:>10.2f} chains/second")

        if 'methods_per_second_cg' in rates:
            print(f"  Call Graph Analysis:      {rates['methods_per_second_cg']:>10.2f} methods/second")

        if 'time_per_sink' in rates:
            print(f"  Avg Time per Sink:        {rates['time_per_sink']:>10.2f} seconds/sink")

        if 'methods_per_second_total' in rates:
            print(f"  Overall Throughput:       {rates['methods_per_second_total']:>10.2f} methods/second")


def print_comparison_table(results):
    """Print comparison table for multiple log files."""
    if len(results) <= 1:
        return

    print(f"\n{'='*80}")
    print(f"PERFORMANCE COMPARISON ACROSS LIBRARIES")
    print(f"{'='*80}\n")

    # Library Information Comparison
    print(f"Library Versions and Sizes:")
    print(f"{'─'*80}")
    print(f"{'Library':<20} {'Version':<20} {'JAR Size':>15}")
    print(f"{'─'*80}")

    for lib_name in sorted(results.keys()):
        total_size, jar_files = get_jar_info(lib_name)
        if jar_files:
            # Show primary JAR (usually the first/main one)
            primary_jar = jar_files[0]
            version = primary_jar['version']
            size_str = format_size(total_size if len(jar_files) > 1 else primary_jar['size'])
            if len(jar_files) > 1:
                size_str += f" ({len(jar_files)} JARs)"
            print(f"{lib_name:<20} {version:<20} {size_str:>15}")
        else:
            print(f"{lib_name:<20} {'unknown':<20} {'N/A':>15}")

    # Codebase Size Comparison
    print(f"\n{'─'*80}")
    print(f"Codebase Size:")
    print(f"{'─'*80}")
    print(f"{'Library':<20} {'Classes':>10} {'Methods':>12} {'Sinks':>8} {'Chains':>10}")
    print(f"{'─'*80}")

    for lib_name, metrics in sorted(results.items()):
        classes = metrics['num_classes'] or 0
        methods = metrics['num_methods'] or 0
        sinks = metrics['num_sinks'] or 0
        chains = metrics['total_chains'] or 0
        print(f"{lib_name:<20} {classes:>10,} {methods:>12,} {sinks:>8,} {chains:>10,}")

    # Timing Comparison
    print(f"\n{'─'*80}")
    print(f"Execution Time (seconds):")
    print(f"{'─'*80}")
    print(f"{'Library':<20} {'World':>10} {'CallGraph':>12} {'Dataflow':>12} {'Collection':>12} {'Total':>10}")
    print(f"{'─'*80}")

    for lib_name, metrics in sorted(results.items()):
        wb = metrics['world_building_time'] or 0
        cg = metrics['call_graph_time'] or 0
        df = metrics['dataflow_time'] or 0
        gc = metrics['gadget_collection_time'] or 0
        total = metrics['total_time'] or 0
        print(f"{lib_name:<20} {wb:>10.2f} {cg:>12.2f} {df:>12.2f} {gc:>12.2f} {total:>10.2f}")

    # Scalability Analysis
    print(f"\n{'─'*80}")
    print(f"Scalability Metrics:")
    print(f"{'─'*80}")
    print(f"{'Library':<20} {'Methods/sec':>14} {'Chains/sec':>12} {'Sec/Sink':>12}")
    print(f"{'─'*80}")

    for lib_name, metrics in sorted(results.items()):
        rates = calculate_rates(metrics)
        methods_per_sec = rates.get('methods_per_second_total', 0)
        chains_per_sec = rates.get('chains_per_second', 0)
        time_per_sink = rates.get('time_per_sink', 0)
        print(f"{lib_name:<20} {methods_per_sec:>14.2f} {chains_per_sec:>12.2f} {time_per_sink:>12.2f}")

    # Efficiency Analysis
    print(f"\n{'─'*80}")
    print(f"Efficiency Analysis:")
    print(f"{'─'*80}")

    # Find most/least efficient
    if results:
        # By total time
        by_time = sorted(results.items(), key=lambda x: x[1]['total_time'] or float('inf'))
        fastest = by_time[0]
        slowest = by_time[-1]

        print(f"  Fastest Analysis:   {fastest[0]:<20} ({format_time(fastest[1]['total_time'])})")
        print(f"  Slowest Analysis:   {slowest[0]:<20} ({format_time(slowest[1]['total_time'])})")

        # By methods throughput
        by_throughput = sorted(
            [(name, calculate_rates(m).get('methods_per_second_total', 0))
             for name, m in results.items()],
            key=lambda x: x[1],
            reverse=True
        )
        if by_throughput:
            best = by_throughput[0]
            print(f"  Best Throughput:    {best[0]:<20} ({best[1]:.2f} methods/sec)")

        # Scalability observation
        print(f"\n  Scalability Observations:")

        # Check if time scales linearly with methods
        data_points = [(m['num_methods'], m['total_time'])
                      for m in results.values()
                      if m['num_methods'] and m['total_time']]

        if len(data_points) >= 2:
            # Calculate rough correlation
            sorted_by_size = sorted(data_points, key=lambda x: x[0])
            smallest = sorted_by_size[0]
            largest = sorted_by_size[-1]

            size_ratio = largest[0] / smallest[0]
            time_ratio = largest[1] / smallest[1]

            if time_ratio < size_ratio * 0.8:
                scaling = "sublinear (efficient scaling)"
            elif time_ratio > size_ratio * 1.2:
                scaling = "superlinear (challenging scaling)"
            else:
                scaling = "approximately linear"

            print(f"    • Time complexity appears {scaling}")
            print(f"    • {size_ratio:.1f}x code size → {time_ratio:.1f}x analysis time")


def main():
    """Main entry point."""
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)

    # Collect all log files
    log_files = []
    for arg in sys.argv[1:]:
        path = Path(arg)
        if path.is_file():
            log_files.append(path)
        elif '*' in arg or '?' in arg:
            import glob
            log_files.extend([Path(p) for p in glob.glob(arg)])

    if not log_files:
        print("Error: No valid log files found.")
        sys.exit(1)

    # Analyze each log file
    results = {}
    for filepath in log_files:
        try:
            metrics = parse_log_file(filepath)
            lib_name = filepath.stem.replace('log-', '')
            results[lib_name] = metrics
            print_performance_report(filepath, metrics)
        except Exception as e:
            print(f"Error analyzing {filepath}: {e}", file=sys.stderr)

    # Print comparison if multiple files
    if len(results) > 1:
        print_comparison_table(results)

    print(f"\n{'='*80}")
    print(f"Performance analysis complete. Processed {len(results)} log file(s).")
    print(f"{'='*80}\n")


if __name__ == '__main__':
    main()
