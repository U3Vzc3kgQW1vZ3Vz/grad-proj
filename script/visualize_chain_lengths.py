#!/usr/bin/env python3
"""
Chain Length Visualization Tool for Flash Gadget Chain Discovery Framework

This script generates detailed visualizations focused on chain length analysis
across multiple chain files.

Usage:
    python visualize_chain_lengths.py [output_directory]
    python visualize_chain_lengths.py output/
"""

import sys
import re
from collections import defaultdict, Counter
from pathlib import Path
import matplotlib.pyplot as plt
import numpy as np
from matplotlib.patches import Rectangle


def parse_chain_file(filepath):
    """
    Parse a chain file and extract chain lengths.

    Returns:
        list: List of chain lengths (number of methods in each chain)
    """
    chains = []

    with open(filepath, 'r') as f:
        content = f.read()

    current_chain = []

    for line in content.split('\n'):
        line = line.strip()

        # Parse sink type - start of new chain
        if line.startswith('# Sink Type:'):
            # Save previous chain if exists
            if current_chain:
                chains.append(len(current_chain))
            current_chain = []

        # Parse method signature (chain element)
        elif line.startswith('<') and '>' in line:
            current_chain.append(line)

        # Empty line indicates end of chain
        elif not line and current_chain:
            chains.append(len(current_chain))
            current_chain = []

    # Handle last chain if file doesn't end with empty line
    if current_chain:
        chains.append(len(current_chain))

    return chains


def extract_library_name(filename):
    """Extract library name from chain filename."""
    name = filename.replace('chains-', '').replace('-1', '')
    return name.upper().replace('-', '_')


def collect_all_data(output_dir):
    """Collect chain length data from all chain files."""
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

    for filepath in chain_files:
        try:
            chains = parse_chain_file(filepath)
            lib_name = extract_library_name(filepath.name)
            results[lib_name] = chains
            print(f"Parsed {filepath.name}: {len(chains)} chains")
        except Exception as e:
            print(f"Warning: Error parsing {filepath.name}: {e}")

    return results


def create_distribution_histogram(results, output_file):
    """Create overlapping histograms showing chain length distribution."""
    fig, ax = plt.subplots(figsize=(14, 8))

    libraries = sorted(results.keys())
    colors = plt.cm.Set3(np.linspace(0, 1, len(libraries)))

    # Calculate global min and max for consistent bins
    all_chains = [c for chains in results.values() for c in chains]
    if not all_chains:
        print("Warning: No chain data available")
        return

    min_length = min(all_chains)
    max_length = max(all_chains)
    bins = range(min_length, max_length + 2)

    # Plot histogram for each library
    for i, lib in enumerate(libraries):
        chains = results[lib]
        if chains:
            ax.hist(chains, bins=bins, alpha=0.6, label=lib,
                   color=colors[i], edgecolor='black', linewidth=0.5)

    ax.set_xlabel('Chain Length (number of methods)', fontsize=12, fontweight='bold')
    ax.set_ylabel('Frequency', fontsize=12, fontweight='bold')
    ax.set_title('Gadget Chain Length Distribution by Library', fontsize=14, fontweight='bold')
    ax.legend(loc='upper right', fontsize=10)
    ax.grid(axis='y', alpha=0.3, linestyle='--')

    plt.tight_layout()
    plt.savefig(output_file, dpi=300, bbox_inches='tight')
    print(f"✓ Saved: {output_file}")
    plt.close()


def create_violin_plot(results, output_file):
    """Create violin plots showing chain length distribution with density."""
    libraries = sorted(results.keys())
    chain_data = [results[lib] for lib in libraries if results[lib]]

    if not chain_data:
        print("Warning: No chain data available")
        return

    fig, ax = plt.subplots(figsize=(14, 8))

    # Create violin plot
    parts = ax.violinplot(chain_data, positions=range(len(chain_data)),
                          showmeans=True, showmedians=True, showextrema=True)

    # Customize violin colors
    colors = plt.cm.Set3(np.linspace(0, 1, len(chain_data)))
    for i, pc in enumerate(parts['bodies']):
        pc.set_facecolor(colors[i])
        pc.set_alpha(0.7)

    # Customize other elements
    for partname in ('cbars', 'cmins', 'cmaxes', 'cmedians', 'cmeans'):
        if partname in parts:
            parts[partname].set_edgecolor('black')
            parts[partname].set_linewidth(1.5)

    # Set labels
    ax.set_xticks(range(len(chain_data)))
    ax.set_xticklabels([f"{lib}\n(n={len(results[lib])})" for lib in libraries])
    ax.set_ylabel('Chain Length (number of methods)', fontsize=12, fontweight='bold')
    ax.set_title('Chain Length Distribution - Violin Plot', fontsize=14, fontweight='bold')
    ax.grid(axis='y', alpha=0.3, linestyle='--')

    plt.tight_layout()
    plt.savefig(output_file, dpi=300, bbox_inches='tight')
    print(f"✓ Saved: {output_file}")
    plt.close()


def create_box_plot_detailed(results, output_file):
    """Create detailed box plots with statistics annotations."""
    libraries = sorted(results.keys())
    chain_data = [results[lib] for lib in libraries if results[lib]]

    if not chain_data:
        print("Warning: No chain data available")
        return

    fig, ax = plt.subplots(figsize=(14, 8))

    # Create box plot
    bp = ax.boxplot(chain_data, patch_artist=True, notch=True,
                    showmeans=True, showcaps=True, showfliers=True,
                    flierprops=dict(marker='o', markerfacecolor='red',
                                   markersize=4, alpha=0.5))

    # Customize colors
    colors = plt.cm.Set3(np.linspace(0, 1, len(chain_data)))
    for patch, color in zip(bp['boxes'], colors):
        patch.set_facecolor(color)
        patch.set_alpha(0.7)

    # Add statistical annotations
    for i, lib in enumerate(libraries):
        chains = results[lib]
        if chains:
            stats_text = (
                f"μ={np.mean(chains):.1f}\n"
                f"σ={np.std(chains):.1f}"
            )
            ax.text(i+1, max(chains) + 0.5, stats_text,
                   ha='center', va='bottom', fontsize=8,
                   bbox=dict(boxstyle='round', facecolor='wheat', alpha=0.3))

    # Set labels
    ax.set_xticklabels([f"{lib}\n(n={len(results[lib])})" for lib in libraries])
    ax.set_ylabel('Chain Length (number of methods)', fontsize=12, fontweight='bold')
    ax.set_title('Chain Length Box Plot with Statistics (μ=mean, σ=std dev)',
                fontsize=14, fontweight='bold')
    ax.grid(axis='y', alpha=0.3, linestyle='--')

    # Add legend
    legend_elements = [
        Rectangle((0, 0), 1, 1, fc='white', ec='black', label='Box: IQR (Q1-Q3)'),
        plt.Line2D([0], [0], color='orange', linewidth=2, label='Median'),
        plt.Line2D([0], [0], color='green', marker='^', linewidth=0,
                  markersize=8, label='Mean'),
        plt.Line2D([0], [0], color='red', marker='o', linewidth=0,
                  markersize=6, alpha=0.5, label='Outliers')
    ]
    ax.legend(handles=legend_elements, loc='upper right')

    plt.tight_layout()
    plt.savefig(output_file, dpi=300, bbox_inches='tight')
    print(f"✓ Saved: {output_file}")
    plt.close()


def create_cumulative_distribution(results, output_file):
    """Create cumulative distribution function (CDF) plot."""
    fig, ax = plt.subplots(figsize=(14, 8))

    libraries = sorted(results.keys())
    colors = plt.cm.Set3(np.linspace(0, 1, len(libraries)))

    for i, lib in enumerate(libraries):
        chains = results[lib]
        if chains:
            sorted_chains = np.sort(chains)
            cumulative = np.arange(1, len(sorted_chains) + 1) / len(sorted_chains)
            ax.plot(sorted_chains, cumulative, label=lib,
                   color=colors[i], linewidth=2, alpha=0.8)

    ax.set_xlabel('Chain Length (number of methods)', fontsize=12, fontweight='bold')
    ax.set_ylabel('Cumulative Probability', fontsize=12, fontweight='bold')
    ax.set_title('Cumulative Distribution Function (CDF) of Chain Lengths',
                fontsize=14, fontweight='bold')
    ax.legend(loc='lower right', fontsize=10)
    ax.grid(alpha=0.3, linestyle='--')
    ax.set_ylim([0, 1.05])

    plt.tight_layout()
    plt.savefig(output_file, dpi=300, bbox_inches='tight')
    print(f"✓ Saved: {output_file}")
    plt.close()


def create_percentile_comparison(results, output_file):
    """Create bar chart comparing percentiles across libraries."""
    libraries = sorted(results.keys())

    percentiles = [25, 50, 75, 90, 95, 99]
    data = {p: [] for p in percentiles}

    for lib in libraries:
        chains = results[lib]
        if chains:
            for p in percentiles:
                data[p].append(np.percentile(chains, p))
        else:
            for p in percentiles:
                data[p].append(0)

    fig, ax = plt.subplots(figsize=(14, 8))

    x = np.arange(len(libraries))
    width = 0.13

    colors = plt.cm.viridis(np.linspace(0, 1, len(percentiles)))

    for i, p in enumerate(percentiles):
        offset = width * (i - len(percentiles)/2 + 0.5)
        ax.bar(x + offset, data[p], width, label=f'{p}th', color=colors[i], alpha=0.8)

    ax.set_xlabel('Library', fontsize=12, fontweight='bold')
    ax.set_ylabel('Chain Length (number of methods)', fontsize=12, fontweight='bold')
    ax.set_title('Chain Length Percentiles by Library', fontsize=14, fontweight='bold')
    ax.set_xticks(x)
    ax.set_xticklabels(libraries, rotation=45, ha='right')
    ax.legend(title='Percentile', loc='upper left')
    ax.grid(axis='y', alpha=0.3, linestyle='--')

    plt.tight_layout()
    plt.savefig(output_file, dpi=300, bbox_inches='tight')
    print(f"✓ Saved: {output_file}")
    plt.close()


def create_statistics_table(results, output_file):
    """Create a visual statistics table as an image."""
    libraries = sorted(results.keys())

    # Calculate statistics
    stats_data = []
    for lib in libraries:
        chains = results[lib]
        if chains:
            stats_data.append([
                lib,
                len(chains),
                min(chains),
                max(chains),
                f"{np.mean(chains):.2f}",
                f"{np.median(chains):.0f}",
                f"{np.std(chains):.2f}",
                f"{np.percentile(chains, 25):.0f}",
                f"{np.percentile(chains, 75):.0f}"
            ])

    fig, ax = plt.subplots(figsize=(14, 6))
    ax.axis('tight')
    ax.axis('off')

    # Create table
    table_data = [['Library', 'Count', 'Min', 'Max', 'Mean', 'Median', 'Std Dev', 'Q1', 'Q3']]
    table_data.extend(stats_data)

    table = ax.table(cellText=table_data, cellLoc='center', loc='center',
                    colWidths=[0.15, 0.1, 0.08, 0.08, 0.12, 0.12, 0.12, 0.1, 0.1])

    table.auto_set_font_size(False)
    table.set_fontsize(10)
    table.scale(1, 2)

    # Style header row
    for i in range(len(table_data[0])):
        cell = table[(0, i)]
        cell.set_facecolor('#4472C4')
        cell.set_text_props(weight='bold', color='white')

    # Alternate row colors
    for i in range(1, len(table_data)):
        for j in range(len(table_data[0])):
            cell = table[(i, j)]
            if i % 2 == 0:
                cell.set_facecolor('#E7E6E6')
            else:
                cell.set_facecolor('#F2F2F2')

    plt.title('Chain Length Statistics Summary', fontsize=14, fontweight='bold', pad=20)
    plt.savefig(output_file, dpi=300, bbox_inches='tight')
    print(f"✓ Saved: {output_file}")
    plt.close()


def create_length_frequency_heatmap(results, output_file):
    """Create a heatmap showing frequency of each chain length by library."""
    libraries = sorted(results.keys())

    # Find all unique chain lengths
    all_lengths = set()
    for chains in results.values():
        all_lengths.update(chains)
    all_lengths = sorted(all_lengths)

    # Create frequency matrix
    freq_matrix = []
    for lib in libraries:
        chains = results[lib]
        if chains:
            length_counter = Counter(chains)
            row = [length_counter.get(length, 0) for length in all_lengths]
            freq_matrix.append(row)
        else:
            freq_matrix.append([0] * len(all_lengths))

    freq_matrix = np.array(freq_matrix)

    # Create heatmap
    fig, ax = plt.subplots(figsize=(16, 8))

    im = ax.imshow(freq_matrix, cmap='YlOrRd', aspect='auto')

    # Set ticks
    ax.set_xticks(np.arange(len(all_lengths)))
    ax.set_yticks(np.arange(len(libraries)))
    ax.set_xticklabels(all_lengths)
    ax.set_yticklabels(libraries)

    # Only show every nth x-tick label if too many
    if len(all_lengths) > 30:
        step = len(all_lengths) // 20
        for i, label in enumerate(ax.get_xticklabels()):
            if i % step != 0:
                label.set_visible(False)

    ax.set_xlabel('Chain Length (number of methods)', fontsize=12, fontweight='bold')
    ax.set_ylabel('Library', fontsize=12, fontweight='bold')
    ax.set_title('Chain Length Frequency Heatmap', fontsize=14, fontweight='bold')

    # Add colorbar
    cbar = plt.colorbar(im, ax=ax)
    cbar.set_label('Frequency', rotation=270, labelpad=20, fontweight='bold')

    # Add text annotations for high-frequency cells
    max_freq = freq_matrix.max()
    for i in range(len(libraries)):
        for j in range(len(all_lengths)):
            value = freq_matrix[i, j]
            if value > max_freq * 0.1:  # Only annotate significant values
                text = ax.text(j, i, int(value), ha="center", va="center",
                             color="white" if value > max_freq/2 else "black",
                             fontsize=7)

    plt.tight_layout()
    plt.savefig(output_file, dpi=300, bbox_inches='tight')
    print(f"✓ Saved: {output_file}")
    plt.close()


def create_range_comparison(results, output_file):
    """Create a range plot showing min-max range for each library."""
    libraries = sorted(results.keys())

    fig, ax = plt.subplots(figsize=(12, 8))

    colors = plt.cm.Set3(np.linspace(0, 1, len(libraries)))

    for i, lib in enumerate(libraries):
        chains = results[lib]
        if chains:
            min_val = min(chains)
            max_val = max(chains)
            mean_val = np.mean(chains)
            median_val = np.median(chains)

            # Draw range line
            ax.plot([i, i], [min_val, max_val], color=colors[i],
                   linewidth=8, alpha=0.3, solid_capstyle='round')

            # Draw IQR box
            q1 = np.percentile(chains, 25)
            q3 = np.percentile(chains, 75)
            ax.plot([i, i], [q1, q3], color=colors[i],
                   linewidth=14, alpha=0.7, solid_capstyle='round')

            # Mark mean and median
            ax.plot(i, mean_val, 'D', color='green', markersize=10,
                   markeredgecolor='black', markeredgewidth=1)
            ax.plot(i, median_val, 'o', color='orange', markersize=10,
                   markeredgecolor='black', markeredgewidth=1)

    ax.set_xticks(range(len(libraries)))
    ax.set_xticklabels(libraries, rotation=45, ha='right')
    ax.set_ylabel('Chain Length (number of methods)', fontsize=12, fontweight='bold')
    ax.set_title('Chain Length Range Comparison', fontsize=14, fontweight='bold')
    ax.grid(axis='y', alpha=0.3, linestyle='--')

    # Legend
    legend_elements = [
        plt.Line2D([0], [0], color='gray', linewidth=8, alpha=0.3,
                  label='Full Range (Min-Max)'),
        plt.Line2D([0], [0], color='gray', linewidth=14, alpha=0.7,
                  label='IQR (Q1-Q3)'),
        plt.Line2D([0], [0], marker='D', color='w', markerfacecolor='green',
                  markersize=10, label='Mean', markeredgecolor='black'),
        plt.Line2D([0], [0], marker='o', color='w', markerfacecolor='orange',
                  markersize=10, label='Median', markeredgecolor='black')
    ]
    ax.legend(handles=legend_elements, loc='upper right')

    plt.tight_layout()
    plt.savefig(output_file, dpi=300, bbox_inches='tight')
    print(f"✓ Saved: {output_file}")
    plt.close()


def create_comprehensive_dashboard(results, output_file):
    """Create a 2x2 dashboard with 4 graphs."""
    libraries = sorted(results.keys())

    # Create figure with 2x2 grid layout
    fig = plt.figure(figsize=(18, 12))
    gs = fig.add_gridspec(2, 2, hspace=0.4, wspace=0.3)

    colors = plt.cm.Set3(np.linspace(0, 1, len(libraries)))

    # Top-left: Total chains bar chart
    ax1 = fig.add_subplot(gs[0, 0])
    total_chains = [len(results[lib]) for lib in libraries]
    ax1.bar(range(len(libraries)), total_chains, color=colors, alpha=0.8, edgecolor='black', linewidth=1.5)
    ax1.set_xticks(range(len(libraries)))
    ax1.set_xticklabels(libraries, rotation=0, fontsize=13)
    ax1.set_ylabel('Count', fontweight='bold', fontsize=13)
    ax1.set_title('Total Gadget Chains per Library', fontweight='bold', fontsize=15, pad=15)
    ax1.grid(axis='y', alpha=0.3, linestyle='--')
    for i, v in enumerate(total_chains):
        ax1.text(i, v, str(v), ha='center', va='bottom', fontsize=12, fontweight='bold')

    # Top-right: Mean chain length
    ax2 = fig.add_subplot(gs[0, 1])
    means = [np.mean(results[lib]) if results[lib] else 0 for lib in libraries]
    ax2.bar(range(len(libraries)), means, color=colors, alpha=0.8, edgecolor='black', linewidth=1.5)
    ax2.set_xticks(range(len(libraries)))
    ax2.set_xticklabels(libraries, rotation=0, fontsize=13)
    ax2.set_ylabel('Methods', fontweight='bold', fontsize=13)
    ax2.set_title('Mean Chain Length per Library', fontweight='bold', fontsize=15, pad=15)
    ax2.grid(axis='y', alpha=0.3, linestyle='--')
    for i, v in enumerate(means):
        ax2.text(i, v, f'{v:.1f}', ha='center', va='bottom', fontsize=12, fontweight='bold')

    # Bottom-left: Max chain length
    ax3 = fig.add_subplot(gs[1, 0])
    maxs = [max(results[lib]) if results[lib] else 0 for lib in libraries]
    ax3.bar(range(len(libraries)), maxs, color=colors, alpha=0.8, edgecolor='black', linewidth=1.5)
    ax3.set_xticks(range(len(libraries)))
    ax3.set_xticklabels(libraries, rotation=0, fontsize=13)
    ax3.set_ylabel('Methods', fontweight='bold', fontsize=13)
    ax3.set_title('Maximum Chain Length per Library', fontweight='bold', fontsize=15, pad=15)
    ax3.grid(axis='y', alpha=0.3, linestyle='--')
    for i, v in enumerate(maxs):
        ax3.text(i, v, str(v), ha='center', va='bottom', fontsize=12, fontweight='bold')

    # Bottom-right: Distribution histogram
    ax4 = fig.add_subplot(gs[1, 1])
    all_chains = [c for chains in results.values() for c in chains]
    if all_chains:
        min_length = min(all_chains)
        max_length = max(all_chains)
        bins = range(min_length, max_length + 2)
        for i, lib in enumerate(libraries):
            chains = results[lib]
            if chains:
                ax4.hist(chains, bins=bins, alpha=0.6, label=lib,
                        color=colors[i], edgecolor='black', linewidth=1)
    ax4.set_xlabel('Chain Length (number of methods)', fontweight='bold', fontsize=13)
    ax4.set_ylabel('Frequency', fontweight='bold', fontsize=13)
    ax4.set_title('Chain Length Distribution by Library', fontweight='bold', fontsize=15, pad=15)
    ax4.legend(fontsize=12, loc='upper right')
    ax4.grid(axis='y', alpha=0.3, linestyle='--')

    plt.suptitle('Chain Length Analysis Dashboard', fontsize=18, fontweight='bold', y=0.98)
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
    print(f"Flash Chain Length Visualization Tool")
    print(f"{'='*80}\n")
    print(f"Analyzing chain files in: {output_dir}\n")

    # Collect data
    results = collect_all_data(output_dir)

    all_chains = [c for chains in results.values() for c in chains]
    print(f"\nFound {len(results)} libraries with {len(all_chains)} total chains")
    if all_chains:
        print(f"Chain length range: {min(all_chains)} - {max(all_chains)} methods")
        print(f"Overall mean: {np.mean(all_chains):.2f} methods\n")

    print(f"Generating chain length dashboard...\n")

    # Create dashboard only
    try:
        create_comprehensive_dashboard(results, 'chain_length_dashboard.png')

        print(f"\n{'='*80}")
        print(f"✓ Chain length dashboard generated successfully!")
        print(f"{'='*80}\n")

        print("Generated file:")
        print("  • chain_length_dashboard.png - Comprehensive vertically-spaced dashboard")
        print()

    except Exception as e:
        print(f"\n✗ Error generating visualizations: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == '__main__':
    main()
