#!/usr/bin/env python3

import argparse
import os
import subprocess
import glob
import math
import ipaddress
import pandas as pd
import matplotlib.pyplot as plt
from datetime import datetime, timedelta
import re

def parse_capinfos(pcap_file):
    """
    Runs capinfos to get:
      - Start time (datetime)
      - End time (datetime)
      - Total capture duration (float, in seconds)
    Returns (start_dt, end_dt, duration_seconds).
    """
    cmd = ['capinfos', '-a', '-e', '-z', pcap_file]
    output = subprocess.check_output(cmd).decode('utf-8').splitlines()
    
    # Look for start and end time lines
    start_line = None
    end_line = None
    dur_line = None
    
    for line in output:
        if 'First packet time:' in line:
            start_line = line
        elif 'Last packet time:' in line:
            end_line = line
        elif any(pattern in line for pattern in ['Capture duration:', 'Duration:', 'duration:']):
            dur_line = line
    
    if not start_line or not end_line:
        raise ValueError("Could not find start or end time in capinfos output.")
        
    # Parse the times from these lines
    start_str = start_line.split(':', 1)[1].strip()
    end_str = end_line.split(':', 1)[1].strip()
    
    # Potential datetime formats that capinfos might use
    dt_formats = [
        '%Y-%m-%d %H:%M:%S',
        '%Y-%m-%d %H:%M:%S.%f',
        '%m/%d/%Y %H:%M:%S',
        '%m/%d/%Y %H:%M:%S.%f'
    ]
    
    def try_parse(dt_str):
        for fmt in dt_formats:
            try:
                return datetime.strptime(dt_str, fmt)
            except ValueError:
                continue
        raise ValueError(f"Could not parse datetime string: {dt_str}")
    
    start_dt = try_parse(start_str)
    end_dt = try_parse(end_str)
    
    # Parse the duration in seconds or calculate it
    if dur_line:
        # Try multiple regex patterns to extract the duration
        patterns = [
            r'(?:Capture duration|Duration|duration):\s+([\d\.]+)\s+seconds',
            r'(?:Capture duration|Duration|duration):.+\((\d+)\s+seconds\)',
            r'(?:Capture duration|Duration|duration):\s+([\d\.]+)'
        ]
        
        for pattern in patterns:
            match = re.search(pattern, dur_line)
            if match:
                duration_seconds = float(match.group(1))
                break
        else:
            # If no patterns match, calculate from timestamps
            duration_seconds = (end_dt - start_dt).total_seconds()
    else:
        # No duration line found, calculate from timestamps
        duration_seconds = (end_dt - start_dt).total_seconds()
        
    return start_dt, end_dt, duration_seconds

def create_slices_and_csvs(pcap_file, output_dir):
    """
    Creates 12 slices (4 each for intervals 5, 10, 15 minutes).
    Returns a list of the CSV filenames in the order created.
    """
    # Ensure output directory exists
    os.makedirs(output_dir, exist_ok=True)

    # Parse PCAP info
    start_dt, end_dt, total_dur = parse_capinfos(pcap_file)

    intervals = [
        (300,  "5m"),   # 5 minutes in seconds
        (600, "10m"),   # 10 minutes
        (900, "15m")    # 15 minutes
    ]

    csv_files = []

    for (interval_sec, label) in intervals:
        for i in range(4):
            # Each slice is interval_sec long
            slice_start = start_dt + timedelta(seconds=i * interval_sec)
            slice_end   = start_dt + timedelta(seconds=(i+1) * interval_sec)

            # If slice_end extends beyond the capture, clamp it
            if slice_end > end_dt:
                slice_end = end_dt

            # If slice_start is already beyond end_dt, we can skip
            if slice_start >= end_dt:
                break

            # Create PCAP slice name
            pcap_slice = os.path.join(output_dir, f"{label}_slice_{i}.pcap")

            # Editcap command
            cmd_editcap = [
                'editcap',
                '-A', slice_start.strftime('%Y-%m-%d %H:%M:%S'),
                '-B', slice_end.strftime('%Y-%m-%d %H:%M:%S'),
                pcap_file,
                pcap_slice
            ]
            print(f"Creating {pcap_slice} for interval {label}, slice {i}...")
            subprocess.run(cmd_editcap, check=True)

            # Convert the slice to CSV
            csv_slice = os.path.join(output_dir, f"{label}_slice_{i}.csv")
            cmd_tshark = [
                'tshark',
                '-r', pcap_slice,
                '-T', 'fields',
                '-E', 'header=y',
                '-E', 'separator=,',
                '-E', 'occurrence=f',  # only first occurrence of each field
                '-e', 'ip.src',
                '-e', 'ip.dst',
                '-e', 'tcp.srcport',
                '-e', 'tcp.dstport',
                '-e', 'udp.srcport',
                '-e', 'udp.dstport',
                '-e', 'ip.proto',
                '-e', 'frame.len'
            ]
            print(f"  -> {csv_slice}")
            with open(csv_slice, 'w') as f:
                subprocess.run(cmd_tshark, stdout=f, check=True)

            csv_files.append(csv_slice)

    return csv_files

# ----- Entropy Analysis Code -----

def is_odd(ip_str):
    """Return True if the IP (converted to an integer) is odd."""
    try:
        ip_val = int(ipaddress.ip_address(ip_str))
        return (ip_val % 2 == 1)
    except Exception:
        return False

def is_even(ip_str):
    """Return True if the IP (converted to an integer) is even."""
    try:
        ip_val = int(ipaddress.ip_address(ip_str))
        return (ip_val % 2 == 0)
    except Exception:
        return False

def compute_entropy(counts):
    """Compute  entropy from an array of counts."""
    total = sum(counts)
    if total == 0:
        return 0.0
    entropy = 0.0
    for c in counts:
        p = c / total
        if p > 0:
            entropy -= p * math.log2(p)
    return entropy

def analyze_csv(csv_file):
    """
    Reads a CSV file, creates 4 subsets:
      - odd source address
      - even source address
      - odd destination address
      - even destination address
    Each subset is grouped by (sport, dport) to compute Shannon entropy.
    Returns (entropy_odd_s, entropy_even_s, entropy_odd_d, entropy_even_d).
    """
    # Read CSV (skip lines that cause parsing errors)
    df = pd.read_csv(csv_file, on_bad_lines='skip')
    
    # Check if the expected columns exist
    has_tcp_sport = 'tcp.srcport' in df.columns
    has_tcp_dport = 'tcp.dstport' in df.columns
    has_udp_sport = 'udp.srcport' in df.columns
    has_udp_dport = 'udp.dstport' in df.columns
    
    # Create unified sport/dport columns (TCP first, fallback on UDP)
    if 'sport' not in df.columns:
        if has_tcp_sport and has_udp_sport:
            df['sport'] = df['tcp.srcport'].fillna(df['udp.srcport'])
        elif has_tcp_sport:
            df['sport'] = df['tcp.srcport']
        elif has_udp_sport:
            df['sport'] = df['udp.srcport']
        else:
            df['sport'] = 0  # Fallback
    
    if 'dport' not in df.columns:
        if has_tcp_dport and has_udp_dport:
            df['dport'] = df['tcp.dstport'].fillna(df['udp.dstport'])
        elif has_tcp_dport:
            df['dport'] = df['tcp.dstport']
        elif has_udp_dport:
            df['dport'] = df['udp.dstport']
        else:
            df['dport'] = 0  # Fallback
    
    # Ensure the IP address columns exist
    if 'ip.src' not in df.columns or 'ip.dst' not in df.columns:
        return 0.0, 0.0, 0.0, 0.0
    
    # Drop rows missing essential data
    df = df.dropna(subset=['ip.src', 'ip.dst', 'sport', 'dport'])
    
    # Create subsets based on IP address parity
    odd_saddr_df  = df[df['ip.src'].apply(is_odd)]
    even_saddr_df = df[df['ip.src'].apply(is_even)]
    odd_daddr_df  = df[df['ip.dst'].apply(is_odd)]
    even_daddr_df = df[df['ip.dst'].apply(is_even)]
    
    # Calculate entropies (group by (sport, dport))
    e_odd_s = compute_entropy(odd_saddr_df.groupby(['sport', 'dport']).size().values) if not odd_saddr_df.empty else 0.0
    e_even_s = compute_entropy(even_saddr_df.groupby(['sport', 'dport']).size().values) if not even_saddr_df.empty else 0.0
    e_odd_d = compute_entropy(odd_daddr_df.groupby(['sport', 'dport']).size().values) if not odd_daddr_df.empty else 0.0
    e_even_d = compute_entropy(even_daddr_df.groupby(['sport', 'dport']).size().values) if not even_daddr_df.empty else 0.0
    
    return (e_odd_s, e_even_s, e_odd_d, e_even_d)

def main():
    parser = argparse.ArgumentParser(
        description="Create 12 CSV slices from a PCAP (5/10/15 min intervals) and analyze entropies."
    )
    parser.add_argument("--pcap", required=True, help="Path to the input PCAP file")
    parser.add_argument("--output-dir", default="output_slices", help="Output directory for slices and CSV files")
    args = parser.parse_args()

    # 1) Create the 12 CSV slices
    csv_files = create_slices_and_csvs(args.pcap, args.output_dir)
    if not csv_files:
        print("No CSV files were created. Check your PCAP or times.")
        return

    # 2) Analyze each CSV file and group results by interval label
    groups = {"5m": {"odd_s": [], "even_s": [], "odd_d": [], "even_d": []},
              "10m": {"odd_s": [], "even_s": [], "odd_d": [], "even_d": []},
              "15m": {"odd_s": [], "even_s": [], "odd_d": [], "even_d": []}}
    
    print("\n--- Entropy Analysis ---")
    for csv_f in csv_files:
        # Assume filename starts with the label (e.g. "5m_slice_0.csv")
        label = os.path.basename(csv_f).split("_")[0]
        e_odd_s, e_even_s, e_odd_d, e_even_d = analyze_csv(csv_f)
        print(f"{csv_f}")
        print(f"   Odd Saddr   : {e_odd_s:.3f}")
        print(f"   Even Saddr  : {e_even_s:.3f}")
        print(f"   Odd Daddr   : {e_odd_d:.3f}")
        print(f"   Even Daddr  : {e_even_d:.3f}\n")
        
        if label in groups:
            groups[label]["odd_s"].append(e_odd_s)
            groups[label]["even_s"].append(e_even_s)
            groups[label]["odd_d"].append(e_odd_d)
            groups[label]["even_d"].append(e_even_d)
        else:
            print(f"Warning: Unknown label '{label}' in file {csv_f}")

    # 3) Plot separate graphs for each interval group
    for label, data in groups.items():
        slices = range(1, len(data["odd_s"]) + 1)
        plt.figure(figsize=(10, 6))
        plt.plot(slices, data["odd_s"], marker='o', label='Odd Source Addr')
        plt.plot(slices, data["even_s"], marker='x', label='Even Source Addr')
        plt.plot(slices, data["odd_d"], marker='s', label='Odd Destination Addr')
        plt.plot(slices, data["even_d"], marker='^', label='Even Destination Addr')
        plt.xlabel(f"Slice Number for {label} Interval")
        plt.ylabel("Entropy (bits)")
        plt.title(f"Entropy Analysis for {label} Slices")
        plt.legend()
        plt.grid(True)
    
    # Show all figures (each interval in its own graph)
    plt.show()

if __name__ == "__main__":
    main()

