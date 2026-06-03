import pandas as pd
import matplotlib.pyplot as plt
import matplotlib.dates as mdates
from datetime import datetime

# Common Styling
plt.style.use('seaborn-v0_8-whitegrid')
plt.rcParams['font.family'] = 'sans-serif'
plt.rcParams['axes.titlesize'] = 12
plt.rcParams['axes.labelsize'] = 10
plt.rcParams['lines.linewidth'] = 2

metadata_stamp = f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} | Kernel: 6.6.15-amd64 | NIC: Simulated"

# 1. Queue Scaling Efficiency
def plot_queue_scaling():
    df = pd.read_csv('benchmarks/results/queue_scaling.csv')
    fig, ax1 = plt.subplots(figsize=(8, 5))
    
    color = 'tab:blue'
    ax1.set_xlabel('AF_XDP RX Queues')
    ax1.set_ylabel('RX Packets Per Second (PPS)', color=color)
    bars = ax1.bar(df['Queues'].astype(str), df['Rx_PPS'], color=color, alpha=0.7)
    ax1.tick_params(axis='y', labelcolor=color)
    
    # Add efficiency labels on top of bars
    for bar, eff in zip(bars, df['Scaling_Efficiency']):
        yval = bar.get_height()
        ax1.text(bar.get_x() + bar.get_width()/2, yval + 100000, f'{eff}x', ha='center', va='bottom', fontweight='bold')

    plt.title('Hyperion 1:1 Queue-to-Core Scaling Efficiency')
    plt.figtext(0.01, 0.01, metadata_stamp, fontsize=8, color='gray')
    
    # Add subtle watermark
    plt.figtext(0.5, 0.5, 'MODELED', fontsize=40, color='gray', ha='center', va='center', alpha=0.15, rotation=30)
    
    plt.tight_layout(rect=[0, 0.03, 1, 1])
    plt.savefig('benchmarks/results/queue_efficiency.png', dpi=150)
    plt.close()

# 2. Verifier Complexity Timeline
def plot_verifier_timeline():
    df = pd.read_csv('benchmarks/results/verifier_history.csv')
    df['Date'] = pd.to_datetime(df['Date'])
    
    fig, ax1 = plt.subplots(figsize=(8, 5))
    
    color1 = '#333333'
    ax1.set_xlabel('Date')
    ax1.set_ylabel('Peak States', color=color1)
    ax1.plot(df['Date'], df['PeakStates'], marker='o', color=color1, label='Peak States')
    ax1.tick_params(axis='y', labelcolor=color1)
    
    ax2 = ax1.twinx()
    color2 = '#555555'
    ax2.set_ylabel('Instruction Count', color=color2)
    ax2.plot(df['Date'], df['Instructions'], marker='s', linestyle='--', color=color2, label='Instructions')
    ax2.tick_params(axis='y', labelcolor=color2)
    
    fig.legend(loc="upper left", bbox_to_anchor=(0.1,0.9))
    
    plt.title('eBPF Verifier Complexity Drift Over Time')
    # Add kernel version annotations
    for i, row in df.iterrows():
        ax1.annotate(row['Kernel'], (row['Date'], row['PeakStates']), textcoords="offset points", xytext=(0,10), ha='center', fontsize=8)

    plt.figtext(0.01, 0.01, metadata_stamp, fontsize=8, color='gray')
    plt.tight_layout(rect=[0, 0.03, 1, 1])
    plt.savefig('benchmarks/results/verifier_complexity.png', dpi=150)
    plt.close()

# 3. Saturation Curve
def plot_saturation():
    df = pd.read_csv('benchmarks/results/saturation_curve.csv')
    
    fig, ax1 = plt.subplots(figsize=(8, 5))
    
    ax1.set_xlabel('Offered Load (Mbps)')
    ax1.set_ylabel('Latency p99 (ms) / Drops', color='black')
    
    ax1.plot(df['Offered_Mbps'], df['p99_ms'], marker='o', color='#2ca02c', label='p99 Latency (ms)')
    ax1.plot(df['Offered_Mbps'], df['Drops'], marker='x', linestyle=':', color='#d62728', label='NIC Drops')
    
    # Identify scheduler collapse / starvation
    collapse_point = df[df['p99_ms'] > 50.0]
    if not collapse_point.empty:
        x_val = collapse_point.iloc[0]['Offered_Mbps']
        ax1.axvline(x=x_val, color='red', linestyle='--', alpha=0.7, label='Scheduler Starvation (p99 > 50ms)')
    
    ax1.tick_params(axis='y', labelcolor='black')
    
    ax2 = ax1.twinx()
    ax2.set_ylabel('CPU Usage (%)', color='#1f77b4')
    ax2.plot(df['Offered_Mbps'], df['CPU_Usage'], marker='s', linestyle='--', color='#1f77b4', label='CPU %')
    ax2.tick_params(axis='y', labelcolor='#1f77b4')
    
    fig.legend(loc="upper left", bbox_to_anchor=(0.1,0.9))
    plt.title('Dataplane Saturation & Scheduler Collapse')
    plt.figtext(0.01, 0.01, metadata_stamp, fontsize=8, color='gray')
    
    # Add subtle watermark
    plt.figtext(0.5, 0.5, 'SYNTHETIC', fontsize=40, color='gray', ha='center', va='center', alpha=0.15, rotation=30)
    
    plt.tight_layout(rect=[0, 0.03, 1, 1])
    plt.savefig('benchmarks/results/saturation.png', dpi=150)
    plt.close()

if __name__ == "__main__":
    try:
        plot_queue_scaling()
        print("Generated queue_efficiency.png")
        plot_verifier_timeline()
        print("Generated verifier_complexity.png")
        plot_saturation()
        print("Generated saturation.png")
    except Exception as e:
        print(f"Failed to plot: {e}")
