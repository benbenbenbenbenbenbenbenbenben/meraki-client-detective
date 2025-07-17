#!/usr/bin/env python3
"""
Test script to validate night cycle logic with 30-day history data.
This script tests that we properly capture evening and morning connections
in the target date analysis.
"""

import csv
import os
import sys
from datetime import datetime, timedelta
from typing import List, Dict

# Add the current directory to the path to import functions from app.py
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app import analyze_out_of_hours_patterns, is_out_of_hours

def find_history_files():
    """Find available history files in the dist/history folder"""
    history_base = os.path.join("dist", "history")
    if not os.path.exists(history_base):
        history_base = "history"  # Fallback to current directory
    
    history_files = []
    
    if os.path.exists(history_base):
        for item in os.listdir(history_base):
            item_path = os.path.join(history_base, item)
            if os.path.isdir(item_path):
                csv_file = os.path.join(item_path, "last_30_days_log.csv")
                if os.path.exists(csv_file):
                    history_files.append({
                        'directory': item,
                        'path': csv_file,
                        'timestamp': item
                    })
    
    # Also check current directory
    current_csv = "last_30_days_log.csv"
    if os.path.exists(current_csv):
        history_files.append({
            'directory': 'current',
            'path': current_csv,
            'timestamp': 'current'
        })
    
    return history_files

def load_csv_data(csv_file: str) -> List[Dict]:
    """Load CSV data from file"""
    connections = []
    
    try:
        with open(csv_file, 'r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            for row in reader:
                connections.append(row)
        print(f"✅ Loaded {len(connections)} connections from {csv_file}")
        return connections
    except Exception as e:
        print(f"❌ Error loading {csv_file}: {e}")
        return []

def test_night_cycle_logic(connections: List[Dict], target_date: str):
    """Test the night cycle logic for a specific target date"""
    print(f"\n🔍 Testing night cycle logic for target date: {target_date}")
    print("=" * 60)
    
    # Calculate the night cycle dates
    target_dt = datetime.fromisoformat(target_date)
    next_day = (target_dt + timedelta(days=1)).strftime('%Y-%m-%d')
    
    print(f"Night cycle spans:")
    print(f"  Evening: {target_date} 18:00-23:59")
    print(f"  Morning: {next_day} 00:00-05:59")
    
    # Filter to out-of-hours connections only
    out_of_hours_connections = [conn for conn in connections if is_out_of_hours(conn['timestamp'])]
    print(f"\n📊 Total out-of-hours connections: {len(out_of_hours_connections)}")
    
    # Find connections in the target night cycle
    target_evening_connections = []
    target_morning_connections = []
    
    for conn in out_of_hours_connections:
        conn_date = conn['timestamp'][:10]
        conn_dt = datetime.fromisoformat(conn['timestamp'].replace('Z', '+00:00'))
        
        # Check if this is target evening (target_date 18:00-23:59)
        if conn_date == target_date and conn_dt.hour >= 18:
            target_evening_connections.append(conn)
        
        # Check if this is target morning (next_day 00:00-05:59)
        elif conn_date == next_day and conn_dt.hour < 6:
            target_morning_connections.append(conn)
    
    print(f"\n🌆 Target evening connections ({target_date} 18:00-23:59): {len(target_evening_connections)}")
    print(f"🌅 Target morning connections ({next_day} 00:00-05:59): {len(target_morning_connections)}")
    
    # Show sample connections
    if target_evening_connections:
        print(f"\n📋 Sample evening connections:")
        for conn in target_evening_connections[:5]:
            print(f"  {conn['timestamp']} - {conn['client_mac']} - {conn['client_description']}")
    
    if target_morning_connections:
        print(f"\n📋 Sample morning connections:")
        for conn in target_morning_connections[:5]:
            print(f"  {conn['timestamp']} - {conn['client_mac']} - {conn['client_description']}")
    
    # Run the analysis
    print(f"\n🔬 Running analysis with target_date: {target_date}")
    analysis = analyze_out_of_hours_patterns(connections, target_date)
    
    # Check target date devices
    target_devices = analysis['target_date_devices']
    print(f"\n📱 Target date devices found: {len(target_devices)}")
    
    # Verify that target devices have both evening and morning connections
    devices_with_evening = 0
    devices_with_morning = 0
    devices_with_both = 0
    
    for device in target_devices:
        mac = device['mac']
        
        # Check device's connections in target night cycle
        device_evening = [conn for conn in target_evening_connections if conn['client_mac'] == mac]
        device_morning = [conn for conn in target_morning_connections if conn['client_mac'] == mac]
        
        if device_evening:
            devices_with_evening += 1
        if device_morning:
            devices_with_morning += 1
        if device_evening and device_morning:
            devices_with_both += 1
        
        # Show details for first few devices
        if len([d for d in target_devices if target_devices.index(d) < 5]) > target_devices.index(device):
            print(f"\n  Device: {mac} ({device['description']})")
            print(f"    Evening connections: {len(device_evening)}")
            print(f"    Morning connections: {len(device_morning)}")
            print(f"    Total target connections: {device['target_date_connections']}")
            print(f"    First connection: {device.get('first_target_connection', 'N/A')}")
            print(f"    Last connection: {device.get('last_target_connection', 'N/A')}")
    
    print(f"\n📊 Target device summary:")
    print(f"  Devices with evening connections: {devices_with_evening}")
    print(f"  Devices with morning connections: {devices_with_morning}")
    print(f"  Devices with both evening and morning: {devices_with_both}")
    
    # Test other categories
    print(f"\n📊 Analysis results summary:")
    print(f"  Target date devices: {len(analysis['target_date_devices'])}")
    print(f"  Baseline regular devices: {len(analysis['baseline_regular_devices'])}")
    print(f"  Anomalous devices: {len(analysis['anomalous_devices'])}")
    print(f"  Baseline only devices: {len(analysis['baseline_only_devices'])}")
    print(f"  Loitering devices: {len(analysis.get('loitering_devices', []))}")
    
    return analysis

def main():
    """Main test function"""
    print("🔍 NIGHT CYCLE LOGIC TEST")
    print("=" * 60)
    
    # Find history files
    history_files = find_history_files()
    
    if not history_files:
        print("❌ No history files found. Please run 30-day collection first.")
        return
    
    print(f"📁 Found {len(history_files)} history files:")
    for i, file_info in enumerate(history_files):
        print(f"  {i+1}. {file_info['directory']} - {file_info['path']}")
    
    # Select file to test - use the most recent one
    selected_file = history_files[0]  # Use first (most recent) file
    print(f"\n📂 Using most recent file: {selected_file['path']}")
    
    # Load data
    connections = load_csv_data(selected_file['path'])
    if not connections:
        return
    
    # Get date range from data
    timestamps = [conn['timestamp'] for conn in connections if conn['timestamp']]
    if not timestamps:
        print("❌ No valid timestamps found in data")
        return
    
    earliest = min(timestamps)[:10]
    latest = max(timestamps)[:10]
    print(f"\n📅 Data range: {earliest} to {latest}")
    
    # Use 2025-06-23 as target date for testing
    target_date = "2025-06-23"
    print(f"\n📅 Using target date: {target_date} for testing")
    
    # Run the test
    analysis = test_night_cycle_logic(connections, target_date)
    
    print(f"\n✅ Test completed!")
    print(f"📊 Check the results above to verify:")
    print(f"  1. Target devices include both evening and morning connections")
    print(f"  2. Morning connections from {(datetime.fromisoformat(target_date) + timedelta(days=1)).strftime('%Y-%m-%d')} are included")
    print(f"  3. Analysis properly separates target vs baseline devices")

if __name__ == "__main__":
    main()