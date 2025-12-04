#!/usr/bin/env python3
"""
Chain Visualization Tool for Flash Gadget Chain Discovery Framework

This script generates visual graphs and charts for sink distribution analysis
across multiple chain files.

Usage:
    python visualize_chains.py [output_directory]
    python visualize_chains.py output/
"""

import sys
import re
from collections import defaultdict
from pathlib import Path
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
import numpy as np


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

        # Parse sink type
        if line.startswith('# Sink Type:'):
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


def extract_library_name(filename):
    """Extract library name from chain filename."""
    # Remove 'chains-' prefix and '-1' suffix
    name = filename.replace('chains-', '').replace('-1', '')
    return name.upper()


def collect_all_data(output_dir):
    """Collect data from all chain files in the output directory."""
    output_path = Path(output_dir)

    if not output_path.exists():
        print(f"Error: Directory {output_dir} does not exist.")
        sys.exit(1)

    # Find all chain files
    chain_files = sorted([f for f in output_path.glob('chains-*') if f.is_file()])

    if not chain_files:
        print(f"Error: No chain files found in {output_dir}")
        sys.exit(1)

    results = {}
    all_sink_types = set()

    for filepath in chain_files:
        try:
            chains, sink_dist = parse_chain_file(filepath)
            lib_name = extract_library_name(filepath.name)
            results[lib_name] = {
                'chains': chains,
                'sink_dist': sink_dist
            }
            all_sink_types.update(sink_dist.keys())
            print(f"Parsed {filepath.name}: {len(chains)} chains, {len(sink_dist)} sink types")
        except Exception as e:
            print(f"Warning: Error parsing {filepath.name}: {e}")

    return results, sorted(all_sink_types)


def create_sink_distribution_by_library(results, all_sink_types, output_file):
    """Create a grouped bar chart showing sink distribution by library."""
    libraries = sorted(results.keys())

    # Prepare data
    x = np.arange(len(all_sink_types))
    width = 0.8 / len(libraries)

    fig, ax = plt.subplots(figsize=(14, 8))

    # Color palette
    colors = plt.cm.Set3(np.linspace(0, 1, len(libraries)))

    # Plot bars for each library
    for i, lib in enumerate(libraries):
        sink_dist = results[lib]['sink_dist']
        counts = [sink_dist.get(sink, 0) for sink in all_sink_types]
        offset = width * (i - len(libraries)/2 + 0.5)
        ax.bar(x + offset, counts, width, label=lib, color=colors[i], alpha=0.8)

    ax.set_xlabel('Sink Type', fontsize=12, fontweight='bold')
    ax.set_ylabel('Number of Chains', fontsize=12, fontweight='bold')
    ax.set_title('Gadget Chain Sink Distribution by Library', fontsize=14, fontweight='bold')
    ax.set_xticks(x)
    ax.set_xticklabels(all_sink_types, rotation=45, ha='right')
    ax.legend(loc='upper right')
    ax.grid(axis='y', alpha=0.3, linestyle='--')

    plt.tight_layout()
    plt.savefig(output_file, dpi=300, bbox_inches='tight')
    print(f"✓ Saved: {output_file}")
    plt.close()


def create_sink_distribution_pie_charts(results, output_file):
    """Create pie charts showing sink distribution for each library."""
    libraries = sorted(results.keys())

    # Calculate grid size
    n_libs = len(libraries)
    cols = 3
    rows = (n_libs + cols - 1) // cols

    fig, axes = plt.subplots(rows, cols, figsize=(16, 5*rows))

    # Flatten axes array for easy indexing
    if n_libs == 1:
        axes = [axes]
    else:
        axes = axes.flatten() if rows > 1 else axes

    colors = plt.cm.Pastel1(np.linspace(0, 1, 10))

    for i, lib in enumerate(libraries):
        sink_dist = results[lib]['sink_dist']

        if not sink_dist:
            axes[i].text(0.5, 0.5, 'No Data', ha='center', va='center')
            axes[i].set_title(lib, fontweight='bold')
            continue

        # Sort by count
        sorted_sinks = sorted(sink_dist.items(), key=lambda x: x[1], reverse=True)
        labels = [s[0] for s in sorted_sinks]
        sizes = [s[1] for s in sorted_sinks]

        # Create pie chart
        wedges, texts, autotexts = axes[i].pie(
            sizes,
            labels=labels,
            autopct='%1.1f%%',
            colors=colors[:len(labels)],
            startangle=90
        )

        # Style
        for text in texts:
            text.set_fontsize(9)
        for autotext in autotexts:
            autotext.set_color('white')
            autotext.set_fontweight('bold')
            autotext.set_fontsize(8)

        total_chains = sum(sizes)
        axes[i].set_title(f'{lib}\n({total_chains} chains)', fontweight='bold')

    # Hide unused subplots
    for i in range(n_libs, len(axes)):
        axes[i].axis('off')

    plt.suptitle('Sink Distribution by Library', fontsize=16, fontweight='bold', y=0.995)
    plt.tight_layout()
    plt.savefig(output_file, dpi=300, bbox_inches='tight')
    print(f"✓ Saved: {output_file}")
    plt.close()


def create_stacked_bar_chart(results, all_sink_types, output_file):
    """Create a stacked bar chart showing sink distribution."""
    libraries = sorted(results.keys())

    # Prepare data
    data = {}
    for sink in all_sink_types:
        data[sink] = [results[lib]['sink_dist'].get(sink, 0) for lib in libraries]

    # Create figure
    fig, ax = plt.subplots(figsize=(12, 8))

    # Colors
    colors = plt.cm.Set3(np.linspace(0, 1, len(all_sink_types)))

    # Plot stacked bars
    bottom = np.zeros(len(libraries))
    for i, sink in enumerate(all_sink_types):
        values = data[sink]
        ax.bar(libraries, values, label=sink, bottom=bottom, color=colors[i], alpha=0.8)
        bottom += values

    ax.set_xlabel('Library', fontsize=12, fontweight='bold')
    ax.set_ylabel('Number of Chains', fontsize=12, fontweight='bold')
    ax.set_title('Stacked Sink Distribution by Library', fontsize=14, fontweight='bold')
    ax.legend(loc='upper right', title='Sink Type')
    ax.grid(axis='y', alpha=0.3, linestyle='--')

    plt.tight_layout()
    plt.savefig(output_file, dpi=300, bbox_inches='tight')
    print(f"✓ Saved: {output_file}")
    plt.close()


def create_heatmap(results, all_sink_types, output_file):
    """Create a heatmap showing sink distribution intensity."""
    libraries = sorted(results.keys())

    # Prepare data matrix
    data_matrix = []
    for lib in libraries:
        row = [results[lib]['sink_dist'].get(sink, 0) for sink in all_sink_types]
        data_matrix.append(row)

    data_matrix = np.array(data_matrix)

    # Create figure
    fig, ax = plt.subplots(figsize=(12, 8))

    # Create heatmap
    im = ax.imshow(data_matrix, cmap='YlOrRd', aspect='auto')

    # Set ticks
    ax.set_xticks(np.arange(len(all_sink_types)))
    ax.set_yticks(np.arange(len(libraries)))
    ax.set_xticklabels(all_sink_types)
    ax.set_yticklabels(libraries)

    # Rotate x labels
    plt.setp(ax.get_xticklabels(), rotation=45, ha="right", rotation_mode="anchor")

    # Add colorbar
    cbar = plt.colorbar(im, ax=ax)
    cbar.set_label('Number of Chains', rotation=270, labelpad=20)

    # Add text annotations
    for i in range(len(libraries)):
        for j in range(len(all_sink_types)):
            value = data_matrix[i, j]
            if value > 0:
                text = ax.text(j, i, int(value), ha="center", va="center",
                             color="white" if value > data_matrix.max()/2 else "black",
                             fontsize=9, fontweight='bold')

    ax.set_title('Sink Distribution Heatmap', fontsize=14, fontweight='bold')
    plt.tight_layout()
    plt.savefig(output_file, dpi=300, bbox_inches='tight')
    print(f"✓ Saved: {output_file}")
    plt.close()


def create_chain_length_comparison(results, output_file):
    """Create box plots comparing chain lengths across libraries."""
    libraries = sorted(results.keys())

    # Prepare data
    chain_data = []
    labels = []
    for lib in libraries:
        chains = results[lib]['chains']
        if chains:
            chain_data.append(chains)
            labels.append(f"{lib}\n(n={len(chains)})")

    if not chain_data:
        print("Warning: No chain length data available")
        return

    # Create figure
    fig, ax = plt.subplots(figsize=(12, 7))

    # Create box plot
    bp = ax.boxplot(chain_data, labels=labels, patch_artist=True,
                     notch=True, showmeans=True)

    # Customize colors
    colors = plt.cm.Set3(np.linspace(0, 1, len(chain_data)))
    for patch, color in zip(bp['boxes'], colors):
        patch.set_facecolor(color)
        patch.set_alpha(0.7)

    # Customize other elements
    for element in ['whiskers', 'fliers', 'means', 'medians', 'caps']:
        plt.setp(bp[element], color='black', linewidth=1.5)

    ax.set_xlabel('Library', fontsize=12, fontweight='bold')
    ax.set_ylabel('Chain Length (number of methods)', fontsize=12, fontweight='bold')
    ax.set_title('Gadget Chain Length Distribution by Library', fontsize=14, fontweight='bold')
    ax.grid(axis='y', alpha=0.3, linestyle='--')

    plt.tight_layout()
    plt.savefig(output_file, dpi=300, bbox_inches='tight')
    print(f"✓ Saved: {output_file}")
    plt.close()


def create_summary_statistics(results, output_file):
    """Create a summary statistics visualization."""
    libraries = sorted(results.keys())

    fig, ((ax1, ax2), (ax3, ax4)) = plt.subplots(2, 2, figsize=(16, 12))

    # 1. Total chains per library
    total_chains = [len(results[lib]['chains']) for lib in libraries]
    colors = plt.cm.Set3(np.linspace(0, 1, len(libraries)))
    ax1.bar(libraries, total_chains, color=colors, alpha=0.8)
    ax1.set_ylabel('Number of Chains', fontweight='bold')
    ax1.set_title('Total Gadget Chains per Library', fontweight='bold')
    ax1.grid(axis='y', alpha=0.3, linestyle='--')

    # Add value labels on bars
    for i, v in enumerate(total_chains):
        ax1.text(i, v, str(v), ha='center', va='bottom', fontweight='bold')

    # 2. Average chain length
    avg_lengths = []
    for lib in libraries:
        chains = results[lib]['chains']
        avg = sum(chains) / len(chains) if chains else 0
        avg_lengths.append(avg)

    ax2.bar(libraries, avg_lengths, color=colors, alpha=0.8)
    ax2.set_ylabel('Average Chain Length', fontweight='bold')
    ax2.set_title('Average Chain Length per Library', fontweight='bold')
    ax2.grid(axis='y', alpha=0.3, linestyle='--')

    for i, v in enumerate(avg_lengths):
        ax2.text(i, v, f'{v:.1f}', ha='center', va='bottom', fontweight='bold')

    # 3. Number of unique sink types
    unique_sinks = [len(results[lib]['sink_dist']) for lib in libraries]
    ax3.bar(libraries, unique_sinks, color=colors, alpha=0.8)
    ax3.set_ylabel('Number of Sink Types', fontweight='bold')
    ax3.set_title('Unique Sink Types per Library', fontweight='bold')
    ax3.grid(axis='y', alpha=0.3, linestyle='--')

    for i, v in enumerate(unique_sinks):
        ax3.text(i, v, str(v), ha='center', va='bottom', fontweight='bold')

    # 4. Chain length distribution (histogram)
    for lib in libraries:
        chains = results[lib]['chains']
        if chains:
            ax4.hist(chains, bins=range(min(chains), max(chains)+2),
                    alpha=0.5, label=lib, edgecolor='black')

    ax4.set_xlabel('Chain Length', fontweight='bold')
    ax4.set_ylabel('Frequency', fontweight='bold')
    ax4.set_title('Chain Length Distribution (All Libraries)', fontweight='bold')
    ax4.legend()
    ax4.grid(axis='y', alpha=0.3, linestyle='--')

    plt.suptitle('Flash Gadget Chain Analysis - Summary Statistics',
                 fontsize=16, fontweight='bold', y=0.995)
    plt.tight_layout()
    plt.savefig(output_file, dpi=300, bbox_inches='tight')
    print(f"✓ Saved: {output_file}")
    plt.close()


def main():
    """Main entry point."""
    # Get output directory
    if len(sys.argv) > 1:
        output_dir = sys.argv[1]
    else:
        output_dir = 'output/'

    print(f"\n{'='*80}")
    print(f"Flash Chain Visualization Tool")
    print(f"{'='*80}\n")
    print(f"Analyzing chain files in: {output_dir}\n")

    # Collect data
    results, all_sink_types = collect_all_data(output_dir)

    print(f"\nFound {len(results)} libraries with {len(all_sink_types)} unique sink types\n")
    print(f"Generating visualizations...\n")

    # Create visualizations
    try:
        create_sink_distribution_by_library(results, all_sink_types,
                                           'sink_distribution_grouped.png')
        create_sink_distribution_pie_charts(results,
                                           'sink_distribution_pies.png')
        create_stacked_bar_chart(results, all_sink_types,
                                'sink_distribution_stacked.png')
        create_heatmap(results, all_sink_types,
                      'sink_distribution_heatmap.png')
        create_chain_length_comparison(results,
                                      'chain_length_comparison.png')
        create_summary_statistics(results,
                                 'summary_statistics.png')

        print(f"\n{'='*80}")
        print(f"✓ All visualizations generated successfully!")
        print(f"{'='*80}\n")

        print("Generated files:")
        print("  • sink_distribution_grouped.png  - Grouped bar chart by library")
        print("  • sink_distribution_pies.png     - Pie charts for each library")
        print("  • sink_distribution_stacked.png  - Stacked bar chart")
        print("  • sink_distribution_heatmap.png  - Heatmap visualization")
        print("  • chain_length_comparison.png    - Box plot comparison")
        print("  • summary_statistics.png         - Overall summary dashboard")
        print()

    except Exception as e:
        print(f"\n✗ Error generating visualizations: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == '__main__':
    main()
