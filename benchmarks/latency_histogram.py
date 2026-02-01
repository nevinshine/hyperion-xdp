#!/usr/bin/env python3
"""
Hyperion XDP Latency Histogram Benchmark

Captures packet latency measurements and generates histogram visualizations
to compare latency across different filter configurations.
"""

import argparse
import subprocess
import sys
import json
import statistics
from collections import defaultdict
from typing import List, Dict
import time

try:
    import matplotlib.pyplot as plt
    import numpy as np
    HAS_MATPLOTLIB = True
except ImportError:
    HAS_MATPLOTLIB = False
    print("WARNING: matplotlib not installed. Visual plots will be disabled.")
    print("Install with: pip3 install matplotlib numpy")

# Color codes for terminal output
GREEN = '\033[0;32m'
BLUE = '\033[0;34m'
YELLOW = '\033[1;33m'
RED = '\033[0;31m'
NC = '\033[0m'


def parse_ping_output(output: str) -> List[float]:
    """Extract latency values from ping output."""
    latencies = []
    for line in output.split('\n'):
        if 'time=' in line:
            try:
                # Extract time value from "time=X.XX ms"
                time_str = line.split('time=')[1].split()[0]
                latencies.append(float(time_str))
            except (IndexError, ValueError):
                continue
    return latencies


def calculate_statistics(latencies: List[float]) -> Dict[str, float]:
    """Calculate statistical metrics for latency data."""
    if not latencies:
        return {}
    
    sorted_latencies = sorted(latencies)
    n = len(sorted_latencies)
    
    return {
        'min': min(sorted_latencies),
        'max': max(sorted_latencies),
        'mean': statistics.mean(sorted_latencies),
        'median': statistics.median(sorted_latencies),
        'stdev': statistics.stdev(sorted_latencies) if n > 1 else 0,
        'p50': sorted_latencies[int(n * 0.50)],
        'p95': sorted_latencies[int(n * 0.95)] if n > 20 else sorted_latencies[-1],
        'p99': sorted_latencies[int(n * 0.99)] if n > 100 else sorted_latencies[-1],
    }


def run_latency_test(target: str, count: int, interval: float) -> List[float]:
    """Run ping test and collect latency measurements."""
    print(f"{BLUE}Running ping test: {count} packets to {target}{NC}")
    
    try:
        cmd = ['ping', '-c', str(count), '-i', str(interval), target]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=count*interval+10)
        latencies = parse_ping_output(result.stdout)
        
        if not latencies:
            print(f"{RED}ERROR: No latency data collected{NC}")
            return []
        
        print(f"{GREEN}Collected {len(latencies)} latency samples{NC}")
        return latencies
        
    except subprocess.TimeoutExpired:
        print(f"{RED}ERROR: Ping command timed out{NC}")
        return []
    except Exception as e:
        print(f"{RED}ERROR: {e}{NC}")
        return []


def plot_histogram(data_sets: Dict[str, List[float]], output_file: str):
    """Generate and save histogram comparing latency distributions."""
    if not HAS_MATPLOTLIB:
        print(f"{YELLOW}Skipping histogram generation (matplotlib not installed){NC}")
        return
    
    plt.figure(figsize=(12, 6))
    
    colors = ['blue', 'green', 'red', 'orange']
    for i, (label, latencies) in enumerate(data_sets.items()):
        if latencies:
            plt.hist(latencies, bins=50, alpha=0.5, label=label, color=colors[i % len(colors)])
    
    plt.xlabel('Latency (ms)')
    plt.ylabel('Frequency')
    plt.title('Hyperion XDP Latency Distribution Comparison')
    plt.legend()
    plt.grid(True, alpha=0.3)
    
    plt.savefig(output_file, dpi=150, bbox_inches='tight')
    print(f"{GREEN}Histogram saved to: {output_file}{NC}")
    
    plt.close()


def plot_percentiles(data_sets: Dict[str, List[float]], output_file: str):
    """Generate and save percentile comparison chart."""
    if not HAS_MATPLOTLIB:
        return
    
    fig, ax = plt.subplots(figsize=(10, 6))
    
    percentiles = [50, 75, 90, 95, 99]
    x = np.arange(len(percentiles))
    width = 0.2
    
    colors = ['blue', 'green', 'red', 'orange']
    for i, (label, latencies) in enumerate(data_sets.items()):
        if latencies:
            sorted_lat = sorted(latencies)
            n = len(sorted_lat)
            values = [sorted_lat[int(n * p / 100)] for p in percentiles]
            ax.bar(x + i * width, values, width, label=label, color=colors[i % len(colors)])
    
    ax.set_xlabel('Percentile')
    ax.set_ylabel('Latency (ms)')
    ax.set_title('Hyperion XDP Latency Percentiles')
    ax.set_xticks(x + width * 1.5)
    ax.set_xticklabels([f'p{p}' for p in percentiles])
    ax.legend()
    ax.grid(True, alpha=0.3, axis='y')
    
    plt.savefig(output_file, dpi=150, bbox_inches='tight')
    print(f"{GREEN}Percentile chart saved to: {output_file}{NC}")
    
    plt.close()


def print_statistics_table(data_sets: Dict[str, List[float]]):
    """Print formatted statistics table."""
    print(f"\n{BLUE}{'='*80}{NC}")
    print(f"{BLUE}Latency Statistics Summary{NC}")
    print(f"{BLUE}{'='*80}{NC}\n")
    
    # Header
    print(f"{'Metric':<15}", end='')
    for label in data_sets.keys():
        print(f"{label:<20}", end='')
    print()
    print('-' * 80)
    
    # Get all stats
    all_stats = {label: calculate_statistics(latencies) 
                 for label, latencies in data_sets.items()}
    
    # Print each metric
    metrics = ['min', 'max', 'mean', 'median', 'stdev', 'p50', 'p95', 'p99']
    for metric in metrics:
        print(f"{metric.upper():<15}", end='')
        for label in data_sets.keys():
            stats = all_stats[label]
            value = stats.get(metric, 0)
            print(f"{value:<20.3f}", end='')
        print()
    
    print()


def main():
    parser = argparse.ArgumentParser(
        description='Hyperion XDP Latency Benchmark',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Quick test with default settings
  %(prog)s
  
  # Custom target and count
  %(prog)s --target 192.168.1.1 --count 200
  
  # Save results to specific location
  %(prog)s --output ./latency_results
        """
    )
    
    parser.add_argument('--target', default='127.0.0.1',
                       help='Target IP address for ping tests (default: 127.0.0.1)')
    parser.add_argument('--count', type=int, default=100,
                       help='Number of ping packets per test (default: 100)')
    parser.add_argument('--interval', type=float, default=0.01,
                       help='Interval between pings in seconds (default: 0.01)')
    parser.add_argument('--output', default='/tmp/hyperion_latency',
                       help='Output directory for results (default: /tmp/hyperion_latency)')
    
    args = parser.parse_args()
    
    print(f"{BLUE}{'='*80}{NC}")
    print(f"{BLUE}Hyperion XDP Latency Benchmark{NC}")
    print(f"{BLUE}{'='*80}{NC}\n")
    print(f"Target: {args.target}")
    print(f"Packets per test: {args.count}")
    print(f"Interval: {args.interval}s")
    print()
    
    results = {}
    
    # Test 1: Baseline (no XDP)
    print(f"\n{GREEN}[1/3] Baseline Test (No XDP){NC}")
    results['Baseline'] = run_latency_test(args.target, args.count, args.interval)
    
    # Test 2: Header filtering
    print(f"\n{GREEN}[2/3] Header Filtering Test{NC}")
    print(f"{YELLOW}Start Hyperion with: sudo ./bin/hyperion_ctrl -iface lo -sig \"\"{NC}")
    input("Press ENTER when ready (or Ctrl+C to skip)...")
    results['Header Filter'] = run_latency_test(args.target, args.count, args.interval)
    
    # Test 3: Full DPI
    print(f"\n{GREEN}[3/3] Full DPI Test{NC}")
    print(f"{YELLOW}Start Hyperion with: sudo ./bin/hyperion_ctrl -iface lo -sig \"malware,hack\"{NC}")
    input("Press ENTER when ready (or Ctrl+C to skip)...")
    results['Full DPI'] = run_latency_test(args.target, args.count, args.interval)
    
    # Remove empty results
    results = {k: v for k, v in results.items() if v}
    
    if not results:
        print(f"{RED}No data collected. Exiting.{NC}")
        return 1
    
    # Print statistics
    print_statistics_table(results)
    
    # Generate plots
    if HAS_MATPLOTLIB:
        plot_histogram(results, f"{args.output}_histogram.png")
        plot_percentiles(results, f"{args.output}_percentiles.png")
    
    # Save raw data
    output_json = f"{args.output}_data.json"
    with open(output_json, 'w') as f:
        json.dump({
            'config': {
                'target': args.target,
                'count': args.count,
                'interval': args.interval
            },
            'results': results,
            'statistics': {label: calculate_statistics(latencies) 
                          for label, latencies in results.items()}
        }, f, indent=2)
    
    print(f"\n{GREEN}Raw data saved to: {output_json}{NC}")
    print(f"{GREEN}Benchmark complete!{NC}\n")
    
    return 0


if __name__ == '__main__':
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print(f"\n{YELLOW}Benchmark interrupted by user{NC}")
        sys.exit(1)
