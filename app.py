#!/usr/bin/env python3
"""
Meraki Client Detective CLI Application

A standalone command-line tool for investigating WiFi connection data from Meraki networks.
Designed for security investigations to identify suspicious device connections and patterns.

Features:
- 30-day baseline data collection
- Out-of-hours activity analysis
- Extended session detection
- Historical data management
- CSV export capabilities

Author: Security Investigation Team
License: MIT
"""

import csv
import getpass
import meraki
import os
import shutil
import sys
from datetime import datetime, timedelta
from typing import List, Dict, Optional

try:
    from dotenv import load_dotenv
    # Look for .env file in the same directory as the executable
    if getattr(sys, 'frozen', False):
        # Running as PyInstaller executable
        exe_dir = os.path.dirname(sys.executable)
    else:
        # Running as Python script
        exe_dir = os.path.dirname(os.path.abspath(__file__))
    
    env_path = os.path.join(exe_dir, '.env')
    load_dotenv(env_path)
except ImportError:
    pass


dashboard = None
DEFAULT_START_TIME = "18:00"
DEFAULT_END_TIME = "06:00"

def is_out_of_hours(timestamp: str) -> bool:
    """Check if timestamp is between 18:00 and 06:00 (out of hours)"""
    try:
        dt = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
        hour = dt.hour
        # Out of hours: 18:00-23:59 and 00:00-06:00
        return hour >= 18 or hour < 6
    except:
        return False

def is_business_hours(timestamp: str) -> bool:
    """Check if timestamp is during business hours (06:00-18:00)"""
    try:
        dt = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
        hour = dt.hour
        return 6 <= hour < 18
    except:
        return False

def detect_loitering_patterns(connections: List[Dict], target_date: str) -> List[Dict]:
    """Detect devices that arrived during business hours but stayed through incident window"""
    loitering_devices = []
    
    # Group all connections by device MAC for the target date
    target_day_connections = {}
    for conn in connections:
        conn_date = conn['timestamp'][:10]
        if conn_date == target_date and conn['client_mac']:
            mac = conn['client_mac']
            if mac not in target_day_connections:
                target_day_connections[mac] = []
            target_day_connections[mac].append(conn)
    
    # Analyze each device's pattern on target date
    for mac, device_conns in target_day_connections.items():
        if len(device_conns) < 2:  # Need multiple connections to detect pattern
            continue
            
        # Sort connections by timestamp
        device_conns.sort(key=lambda x: x['timestamp'])
        
        first_conn = datetime.fromisoformat(device_conns[0]['timestamp'].replace('Z', '+00:00'))
        last_conn = datetime.fromisoformat(device_conns[-1]['timestamp'].replace('Z', '+00:00'))
        
        # Check if device arrived during business hours (06:00-18:00)
        arrived_business_hours = 6 <= first_conn.hour < 18
        
        # Check if device was present during incident window (18:00+)
        stayed_late = last_conn.hour >= 18
        
        # Calculate duration (in hours)
        duration_hours = (last_conn - first_conn).total_seconds() / 3600
        
        if arrived_business_hours and stayed_late and duration_hours > 8:  # Stayed > 8 hours
            loitering_devices.append({
                'mac': mac,
                'description': device_conns[0]['client_description'],
                'first_target_connection': device_conns[0]['timestamp'],
                'last_target_connection': device_conns[-1]['timestamp'],
                'duration_hours': round(duration_hours, 1),
                'target_date_connections': len(device_conns),
                'baseline_connections': 0,  # Default for loitering analysis
                'days_seen_out_of_hours': 1,  # Default for loitering analysis
                'networks': [],  # Will be populated later
                'ssids': [],  # Will be populated later
                'arrived_hour': first_conn.hour,
                'departed_hour': last_conn.hour if last_conn.hour >= 18 else 24,  # If still connected
                'risk_level': 'LOITERING_SUSPICIOUS',
                'risk_explanation': f"LOITERING PATTERN: Arrived at {first_conn.hour:02d}:00 during business hours, stayed until {last_conn.hour:02d}:00+ ({duration_hours:.1f} hours total). Unusual for employee to stay this late - potential insider threat or theft preparation."
            })
    
    return loitering_devices

def analyze_out_of_hours_patterns(connections: List[Dict], target_date: str = None) -> Dict:
    """Analyze out-of-hours device patterns to identify baseline vs anomalous behavior"""
    
    # Extract target date from latest connection if not provided
    if not target_date:
        if connections:
            latest_timestamp = max(conn['timestamp'] for conn in connections)
            target_date = latest_timestamp[:10]
        else:
            target_date = datetime.now().strftime('%Y-%m-%d')
    
    # Separate connections by date and out-of-hours status
    out_of_hours_connections = [conn for conn in connections if is_out_of_hours(conn['timestamp'])]
    
    # Group by device MAC
    device_patterns = {}
    
    for conn in out_of_hours_connections:
        mac = conn['client_mac']
        if not mac:
            continue
            
        conn_date = conn['timestamp'][:10]  # Extract date part
        
        if mac not in device_patterns:
            device_patterns[mac] = {
                'description': conn['client_description'],
                'networks': set(),
                'ssids': set(),
                'target_date_connections': [],
                'baseline_connections': [],
                'all_dates': set()
            }
        
        device_patterns[mac]['networks'].add(conn['network'])
        device_patterns[mac]['ssids'].add(conn['ssid'])
        device_patterns[mac]['all_dates'].add(conn_date)
        
        # Check if this connection is part of the target night cycle
        # Night cycle includes: evening of target_date + morning of target_date+1
        target_dt = datetime.fromisoformat(target_date)
        next_day = (target_dt + timedelta(days=1)).strftime('%Y-%m-%d')
        
        conn_dt = datetime.fromisoformat(conn['timestamp'].replace('Z', '+00:00'))
        is_target_evening = (conn_date == target_date and conn_dt.hour >= 18)
        is_target_morning = (conn_date == next_day and conn_dt.hour < 6)
        
        if is_target_evening or is_target_morning:
            device_patterns[mac]['target_date_connections'].append(conn)
        else:
            device_patterns[mac]['baseline_connections'].append(conn)
    
    # Detect loitering patterns (business hours arrival + late stay)
    loitering_devices = detect_loitering_patterns(connections, target_date)
    
    # Analyze patterns
    analysis = {
        'target_date_devices': [],
        'baseline_regular_devices': [],
        'anomalous_devices': [],
        'baseline_only_devices': [],
        'loitering_devices': loitering_devices  # New category for insider threat detection
    }
    
    for mac, data in device_patterns.items():
        target_count = len(data['target_date_connections'])
        baseline_count = len(data['baseline_connections'])
        days_seen = len(data['all_dates'])
        
        device_info = {
            'mac': mac,
            'description': data['description'],
            'target_date_connections': target_count,
            'baseline_connections': baseline_count,
            'days_seen_out_of_hours': days_seen,
            'networks': list(data['networks']),
            'ssids': list(data['ssids']),
            'first_target_connection': min(conn['timestamp'] for conn in data['target_date_connections']) if data['target_date_connections'] else None,
            'last_target_connection': max(conn['timestamp'] for conn in data['target_date_connections']) if data['target_date_connections'] else None,
            'risk_explanation': ''
        }
        
        # Classification logic for devices seen on target date
        if target_count > 0:
            device_info['risk_level'] = 'TARGET_DATE'
            analysis['target_date_devices'].append(device_info)
            
            # Check if this device shows loitering pattern (overrides other classifications)
            loitering_device = next((ld for ld in loitering_devices if ld['mac'] == mac), None)
            if loitering_device:
                device_info['risk_level'] = 'LOITERING_SUSPICIOUS'
                device_info['risk_explanation'] = loitering_device['risk_explanation']
                device_info['duration_hours'] = loitering_device['duration_hours']
                device_info['arrived_hour'] = loitering_device['arrived_hour']
                device_info['departed_hour'] = loitering_device['departed_hour']
                analysis['anomalous_devices'].append(device_info)
            elif baseline_count == 0:
                device_info['risk_level'] = 'ANOMALOUS_SUSPICIOUS'
                device_info['risk_explanation'] = f"NEVER seen out-of-hours in 7-day baseline period. This device appeared for the first time during incident window ({target_count} connections on target date). Could be: intruder device, stolen device, or employee device used during theft."
                analysis['anomalous_devices'].append(device_info)
            elif baseline_count >= 1 and days_seen >= 2:
                device_info['risk_level'] = 'BASELINE_REGULAR'
                device_info['risk_explanation'] = f"Regular out-of-hours device: {baseline_count} baseline connections across {days_seen} days. Expected to be present during incident window."
                analysis['baseline_regular_devices'].append(device_info)
            elif baseline_count >= 3:
                device_info['risk_level'] = 'BASELINE_REGULAR'
                device_info['risk_explanation'] = f"Regular out-of-hours device: {baseline_count} baseline connections (single day pattern). Likely IoT/always-on device."
                analysis['baseline_regular_devices'].append(device_info)
            else:
                device_info['risk_level'] = 'ANOMALOUS_SUSPICIOUS'
                device_info['risk_explanation'] = f"Suspicious pattern: Only {baseline_count} baseline connections on {days_seen} day(s), but {target_count} connections on target date. Could be: employee working unusual hours, device brought in for theft, or coincidental usage."
                analysis['anomalous_devices'].append(device_info)
        
        # Classification for devices only seen in baseline (always-on devices)
        elif baseline_count > 0:
            device_info['risk_level'] = 'BASELINE_ONLY'
            if days_seen >= 3:
                device_info['risk_explanation'] = f"Always-on device: {baseline_count} baseline connections across {days_seen} days, but NO connections on target date. Could be normal (stayed connected) or suspicious (device turned off/removed during incident)."
            else:
                device_info['risk_explanation'] = f"Baseline device: {baseline_count} baseline connections on {days_seen} day(s), but absent on target date. Monitor for unusual absence pattern."
            
            analysis['baseline_only_devices'].append(device_info)
            
            # If they're regularly seen, also add to baseline regular
            if baseline_count >= 1 and days_seen >= 2:
                device_info_copy = device_info.copy()
                device_info_copy['risk_level'] = 'BASELINE_REGULAR'
                analysis['baseline_regular_devices'].append(device_info_copy)
            elif baseline_count >= 3:
                device_info_copy = device_info.copy()
                device_info_copy['risk_level'] = 'BASELINE_REGULAR'
                analysis['baseline_regular_devices'].append(device_info_copy)
    
    return analysis

def export_out_of_hours_analysis_to_csv(connections: List[Dict], analysis: Dict, history_path: str = None):
    """Export out-of-hours analysis to multiple CSV files"""
    
    # Use history path if provided, otherwise current directory
    base_path = history_path if history_path else "."
    
    # Export raw connections
    if connections:
        fieldnames = [
            'organization', 'network', 'timestamp', 'event_type', 
            'client_mac', 'client_description', 'device_serial', 
            'ssid', 'description'
        ]
        
        csv_path = os.path.join(base_path, 'all_connections.csv')
        with open(csv_path, 'w', newline='', encoding='utf-8') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(connections)
    
    # Export device analysis with out-of-hours focus
    device_fieldnames = [
        'mac', 'description', 'target_date_connections', 'baseline_connections', 
        'days_seen_out_of_hours', 'networks', 'ssids', 'first_target_connection', 
        'last_target_connection', 'risk_level', 'risk_explanation', 'duration_hours',
        'arrived_hour', 'departed_hour'
    ]
    
    # Export each category to separate CSV files
    for category_name, devices in analysis.items():
        if devices:
            csv_path = os.path.join(base_path, f'{category_name}.csv')
            with open(csv_path, 'w', newline='', encoding='utf-8') as csvfile:
                writer = csv.DictWriter(csvfile, fieldnames=device_fieldnames)
                writer.writeheader()
                
                for device in devices:
                    # Convert lists to strings for CSV and handle missing fields
                    device_copy = device.copy()
                    
                    # Ensure all fieldnames are present with default values first
                    for field in device_fieldnames:
                        if field not in device_copy:
                            device_copy[field] = ''
                    
                    # Convert lists to strings for CSV - handle both list and string types
                    if isinstance(device_copy.get('networks'), list):
                        device_copy['networks'] = ', '.join(device_copy['networks'])
                    elif not device_copy.get('networks'):
                        device_copy['networks'] = ''
                        
                    if isinstance(device_copy.get('ssids'), list):
                        device_copy['ssids'] = ', '.join(device_copy['ssids'])
                    elif not device_copy.get('ssids'):
                        device_copy['ssids'] = ''
                    
                    writer.writerow(device_copy)
    
    print(f"✅ CSV files exported to: {base_path}")
    print(f"   - all_connections.csv ({len(connections)} connections)")
    for category_name, devices in analysis.items():
        if devices:
            print(f"   - {category_name}.csv ({len(devices)} devices)")

def analyze_extended_sessions(connections: List[Dict], target_date: str = None) -> List[Dict]:
    """Analyze devices that connect during business hours but stay past 18:00"""
    
    # Extract target date from latest connection if not provided
    if not target_date:
        if connections:
            latest_timestamp = max(conn['timestamp'] for conn in connections)
            target_date = latest_timestamp[:10]
        else:
            target_date = datetime.now().strftime('%Y-%m-%d')
    
    extended_session_devices = []
    
    # Group connections by device MAC for the target date
    target_day_connections = {}
    for conn in connections:
        conn_date = conn['timestamp'][:10]
        if conn_date == target_date and conn['client_mac']:
            mac = conn['client_mac']
            if mac not in target_day_connections:
                target_day_connections[mac] = []
            target_day_connections[mac].append(conn)
    
    # Analyze each device's session pattern
    for mac, device_conns in target_day_connections.items():
        if len(device_conns) < 2:  # Need multiple connections to detect pattern
            continue
            
        # Sort connections by timestamp
        device_conns.sort(key=lambda x: x['timestamp'])
        
        first_conn = datetime.fromisoformat(device_conns[0]['timestamp'].replace('Z', '+00:00'))
        last_conn = datetime.fromisoformat(device_conns[-1]['timestamp'].replace('Z', '+00:00'))
        
        # Check if device connected during business hours (06:00-18:00)
        connected_business_hours = is_business_hours(device_conns[0]['timestamp'])
        
        # Check if device was still active after 18:00
        stayed_after_hours = last_conn.hour >= 18
        
        # Calculate session duration
        duration_hours = (last_conn - first_conn).total_seconds() / 3600
        
        if connected_business_hours and stayed_after_hours:
            extended_session_devices.append({
                'mac': mac,
                'description': device_conns[0]['client_description'],
                'first_connection': device_conns[0]['timestamp'],
                'last_connection': device_conns[-1]['timestamp'],
                'duration_hours': round(duration_hours, 1),
                'total_connections': len(device_conns),
                'connected_hour': first_conn.hour,
                'last_seen_hour': last_conn.hour,
                'business_hours_start': True,
                'after_hours_activity': True,
                'risk_explanation': f"EXTENDED SESSION: Connected at {first_conn.hour:02d}:00 during business hours, last seen at {last_conn.hour:02d}:00 after hours. Session duration: {duration_hours:.1f} hours."
            })
    
    return extended_session_devices
# Get the directory where the executable/script is located
if getattr(sys, 'frozen', False):
    # Running as PyInstaller executable
    BASE_DIR = os.path.dirname(sys.executable)
else:
    # Running as Python script
    BASE_DIR = os.path.dirname(os.path.abspath(__file__))

HISTORY_DIR = os.path.join(BASE_DIR, "history")

def create_history_directory() -> str:
    """Create a timestamped directory in history for storing analysis data"""
    if not os.path.exists(HISTORY_DIR):
        os.makedirs(HISTORY_DIR)
    
    # Create timestamp directory
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    history_path = os.path.join(HISTORY_DIR, timestamp)
    os.makedirs(history_path, exist_ok=True)
    
    return history_path

def get_available_history() -> List[Dict]:
    """Get list of available historical datasets"""
    history_datasets = []
    
    if not os.path.exists(HISTORY_DIR):
        return history_datasets
    
    for item in os.listdir(HISTORY_DIR):
        item_path = os.path.join(HISTORY_DIR, item)
        if os.path.isdir(item_path) and len(item) == 15 and '_' in item:
            try:
                # Parse timestamp from directory name
                timestamp = datetime.strptime(item, "%Y%m%d_%H%M%S")
                
                # Check what files are in this directory
                files = os.listdir(item_path)
                dataset_info = {
                    'timestamp': timestamp,
                    'directory': item,
                    'path': item_path,
                    'files': files,
                    'has_30_day_log': 'last_30_days_log.csv' in files,
                    'has_analysis': any(f.startswith('all_connections') for f in files),
                    'age_hours': (datetime.now() - timestamp).total_seconds() / 3600
                }
                history_datasets.append(dataset_info)
            except ValueError:
                # Skip directories that don't match timestamp format
                continue
    
    # Sort by timestamp (newest first)
    history_datasets.sort(key=lambda x: x['timestamp'], reverse=True)
    return history_datasets

def copy_files_to_history(history_path: str, files_to_copy: List[str], description: str = ""):
    """Copy specified files to history directory and create metadata"""
    copied_files = []
    
    for filename in files_to_copy:
        if os.path.exists(filename):
            dest_path = os.path.join(history_path, filename)
            shutil.copy2(filename, dest_path)
            copied_files.append(filename)
            print(f"  📁 Saved {filename} to history")
    
    # Create metadata file
    metadata = {
        'created': datetime.now().isoformat(),
        'description': description,
        'files': copied_files,
        'file_count': len(copied_files)
    }
    
    metadata_path = os.path.join(history_path, 'metadata.txt')
    with open(metadata_path, 'w') as f:
        f.write(f"Created: {metadata['created']}\n")
        f.write(f"Description: {metadata['description']}\n")
        f.write(f"Files: {len(copied_files)}\n")
        for file in copied_files:
            f.write(f"  - {file}\n")
    
    return copied_files

def get_organizations() -> List[Dict]:
    """Get all organizations available to the API key"""
    global dashboard
    try:
        organizations = dashboard.organizations.getOrganizations()
        return organizations
    except Exception as e:
        print(f"Error fetching organizations: {e}")
        return []

def get_networks(org_id: str) -> List[Dict]:
    """Get all networks for an organization"""
    global dashboard
    try:
        networks = dashboard.organizations.getOrganizationNetworks(org_id)
        return networks
    except Exception as e:
        print(f"Error fetching networks for org {org_id}: {e}")
        return []

def get_client_events(network_id: str, start_time: str, end_time: Optional[str] = None) -> List[Dict]:
    """Get client connection events for a network within time period with pagination"""
    global dashboard
    try:
        print(f"    🔍 Fetching events from {start_time} to {end_time or 'now'}")
        
        all_events = []
        page = 1
        per_page = 1000
        
        while True:
            print(f"      📄 Fetching page {page}...")
            
            # Meraki API only allows one of startingAfter or endingBefore, not both
            if end_time:
                # Use endingBefore for day-specific queries
                events = dashboard.networks.getNetworkEvents(
                    network_id,
                    perPage=per_page,
                    endingBefore=end_time,
                    productType='wireless'
                )
            else:
                # Use startingAfter for ongoing queries
                events = dashboard.networks.getNetworkEvents(
                    network_id,
                    perPage=per_page,
                    startingAfter=start_time,
                    productType='wireless'
                )
            
            page_events = events.get('events', [])
            
            # If we used endingBefore, filter events to only include those after start_time
            if end_time:
                filtered_events = []
                for event in page_events:
                    event_time = event.get('occurredAt', '')
                    if event_time >= start_time and event_time < end_time:
                        filtered_events.append(event)
                page_events = filtered_events
            
            if not page_events:
                break
                
            all_events.extend(page_events)
            
            # If we got less than per_page events, we've reached the end
            if len(page_events) < per_page:
                break
                
            # Update start_time for next page (use last event's timestamp)
            if page_events:
                last_event_time = page_events[-1].get('occurredAt', '')
                if end_time:
                    end_time = last_event_time
                else:
                    start_time = last_event_time
                    
            page += 1
            
            # Continue until no more data is returned
        
        print(f"    📊 Found {len(all_events)} total wireless events across {page} pages")
        
        # Show sample of event types found
        event_types = {}
        for event in all_events:
            event_type = event.get('type', 'unknown')
            event_types[event_type] = event_types.get(event_type, 0) + 1
        
        if event_types:
            print(f"    📈 Event types found: {dict(list(event_types.items())[:5])}")
        
        return all_events
    except Exception as e:
        print(f"    ❌ Error fetching client events for network {network_id}: {e}")
        return []

def get_comprehensive_baseline_events(network_id: str, investigation_date: str) -> List[Dict]:
    """Get comprehensive baseline events by collecting data day by day for 7 days with proper cross-day handling"""
    from datetime import datetime, timedelta
    
    target_dt = datetime.fromisoformat(investigation_date)
    all_baseline_events = []
    
    print(f"    🔍 Collecting comprehensive 7-day baseline data with cross-day periods...")
    
    # Collect data for each of the 7 days before target date
    # For proper out-of-hours analysis, we need complete night cycles
    for i in range(7, 0, -1):  # 7 days ago to 1 day ago
        day_dt = target_dt - timedelta(days=i)
        next_day_dt = day_dt + timedelta(days=1)
        
        # Collect evening period (18:00-23:59) of the baseline day
        evening_start = day_dt.strftime("%Y-%m-%dT18:00:00.000Z")
        evening_end = day_dt.strftime("%Y-%m-%dT23:59:59.999Z")
        
        # Collect morning period (00:00-05:59) of the next day
        morning_start = next_day_dt.strftime("%Y-%m-%dT00:00:00.000Z")
        morning_end = next_day_dt.strftime("%Y-%m-%dT05:59:59.999Z")
        
        print(f"      📅 Day {8-i}/7: {day_dt.strftime('%Y-%m-%d')} evening + {next_day_dt.strftime('%Y-%m-%d')} morning")
        
        # Get evening events from baseline day
        evening_events = get_client_events(network_id, evening_start, evening_end)
        all_baseline_events.extend(evening_events)
        
        # Get morning events from next day
        morning_events = get_client_events(network_id, morning_start, morning_end)
        all_baseline_events.extend(morning_events)
    
    print(f"    ✅ Total baseline events collected: {len(all_baseline_events)}")
    return all_baseline_events

def check_existing_csv_files() -> Dict:
    """Check for existing CSV files and return their info"""
    csv_files = {}
    
    # Check for 30-day log file in current directory
    if os.path.exists("last_30_days_log.csv"):
        try:
            # Get file modification time and row count
            stat = os.stat("last_30_days_log.csv")
            modified_time = datetime.fromtimestamp(stat.st_mtime)
            
            # Count rows quickly
            with open("last_30_days_log.csv", 'r', encoding='utf-8') as f:
                row_count = sum(1 for line in f) - 1  # Subtract header
            
            csv_files["last_30_days_log.csv"] = {
                'modified': modified_time,
                'rows': row_count,
                'age_hours': (datetime.now() - modified_time).total_seconds() / 3600,
                'location': 'current'
            }
        except Exception as e:
            print(f"⚠️  Error reading last_30_days_log.csv: {e}")
    
    # Check for 30-day log files in history directories
    history_datasets = get_available_history()
    for dataset in history_datasets:
        if dataset['has_30_day_log']:
            history_csv_path = os.path.join(dataset['path'], 'last_30_days_log.csv')
            try:
                # Count rows quickly
                with open(history_csv_path, 'r', encoding='utf-8') as f:
                    row_count = sum(1 for line in f) - 1  # Subtract header
                
                csv_files[f"history/{dataset['directory']}/last_30_days_log.csv"] = {
                    'modified': dataset['timestamp'],
                    'rows': row_count,
                    'age_hours': dataset['age_hours'],
                    'location': 'history',
                    'full_path': history_csv_path
                }
            except Exception as e:
                print(f"⚠️  Error reading {history_csv_path}: {e}")
    
    return csv_files

def load_csv_data_for_investigation(csv_file: str, investigation_date: str, investigation_time: str, target_end: str) -> List[Dict]:
    """Load and filter CSV data for specific investigation period"""
    from datetime import datetime
    
    print(f"📂 Loading data from {csv_file}...")
    
    # Parse investigation timestamps
    investigation_start = f"{investigation_date}T{investigation_time}:00.000Z"
    
    all_connections = []
    target_connections = []
    baseline_connections = []
    
    try:
        with open(csv_file, 'r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            for row in reader:
                timestamp = row.get('timestamp', '')
                if not timestamp:
                    continue
                
                all_connections.append(row)
                
                # Check if this event falls within investigation period
                if investigation_start <= timestamp <= target_end:
                    target_connections.append(row)
                else:
                    # This is baseline data
                    baseline_connections.append(row)
        
        print(f"📊 Loaded {len(all_connections)} total connections from CSV")
        print(f"🎯 Found {len(target_connections)} connections in investigation period")
        print(f"📋 Found {len(baseline_connections)} baseline connections")
        
        return all_connections
        
    except Exception as e:
        print(f"❌ Error loading CSV data: {e}")
        return []

def stream_30_days_to_csv(network_id: str, org_name: str, network_name: str, csv_writer):
    """Stream 30 days of events directly to CSV to minimize memory usage"""
    from datetime import datetime, timedelta
    
    now = datetime.now()
    total_events = 0
    
    print(f"    🔍 Streaming last 30 days of connection data to CSV...")
    
    # Process data day by day and write immediately to CSV
    for i in range(30, 0, -1):  # 30 days ago to 1 day ago
        day_dt = now - timedelta(days=i)
        day_start = day_dt.strftime("%Y-%m-%dT00:00:00.000Z")
        day_end = day_dt.strftime("%Y-%m-%dT23:59:59.999Z")
        
        print(f"      📅 Day {31-i}/30: {day_dt.strftime('%Y-%m-%d')}")
        day_events = get_client_events(network_id, day_start, day_end)
        
        # Process and write events immediately
        day_connections = 0
        for event in day_events:
            if event.get('type') in ['association', 'wpa_auth', 'disassociation']:
                connection_data = {
                    'organization': org_name,
                    'network': network_name,
                    'timestamp': event.get('occurredAt'),
                    'event_type': event.get('type'),
                    'client_mac': event.get('clientMac'),
                    'client_description': event.get('clientDescription', ''),
                    'device_serial': event.get('deviceSerial'),
                    'ssid': event.get('ssid', ''),
                    'description': event.get('description', '')
                }
                csv_writer.writerow(connection_data)
                day_connections += 1
        
        total_events += day_connections
        print(f"        ✅ Wrote {day_connections} connections from this day")
    
    print(f"    ✅ Total connections streamed: {total_events}")
    return total_events

def test_network_connectivity(network_id: str) -> Dict:
    """Test basic network connectivity and get network info"""
    global dashboard
    try:
        print(f"    🔍 Testing network connectivity for {network_id}")
        network_info = dashboard.networks.getNetwork(network_id)
        print(f"    ✅ Network found: {network_info.get('name', 'Unknown')}")
        print(f"    📡 Product types: {network_info.get('productTypes', [])}")
        
        # Try to get recent events without time filter
        print(f"    🔍 Checking for any recent events...")
        recent_events = dashboard.networks.getNetworkEvents(
            network_id,
            perPage=10,
            productType='wireless'
        )
        recent_count = len(recent_events.get('events', []))
        print(f"    📊 Found {recent_count} recent wireless events")
        
        return {
            'network_info': network_info,
            'recent_events_count': recent_count
        }
    except Exception as e:
        print(f"    ❌ Error testing network {network_id}: {e}")
        return {}

def clear_screen():
    """Clear the terminal screen"""
    os.system('cls' if os.name == 'nt' else 'clear')

def print_header():
    """Print the application header"""
    print("=" * 60)
    print("           MERAKI CLIENT DETECTIVE - CLI")
    print("    WiFi Connection Analysis for Security Investigation")
    print("=" * 60)
    
    # Show .env status
    env_configured = (
        os.getenv('MERAKI_DASHBOARD_API_KEY') or
        os.getenv('MERAKI_ORG_ID') or 
        os.getenv('MERAKI_NETWORK_ID')
    )
    
    if env_configured:
        print("💡 .env file detected - using saved configuration")
    else:
        print("💡 Tip: Create a .env file to save API key and IDs for faster startup")
    print()

def get_api_key():
    """Get Meraki API key from .env file or prompt user"""
    # Check for API key in environment first
    api_key = os.getenv('MERAKI_DASHBOARD_API_KEY')
    
    if api_key and api_key.strip():
        print("📡 Using API key from .env file")
        return api_key.strip()
    
    print("📡 Meraki Dashboard API Setup")
    print("You need a Meraki Dashboard API key to continue.")
    print("Get your API key from: https://dashboard.meraki.com/api_access")
    print("Tip: Save it in a .env file as MERAKI_DASHBOARD_API_KEY=your_key")
    print()
    
    api_key = getpass.getpass("Enter your Meraki API key: ")
    
    if not api_key.strip():
        print("❌ API key cannot be empty")
        return None
    
    return api_key.strip()

def initialize_dashboard(api_key: str) -> bool:
    """Initialize the Meraki dashboard connection"""
    global dashboard
    
    try:
        print("🔍 Testing API connection...")
        dashboard = meraki.DashboardAPI(api_key=api_key, suppress_logging=True)
        
        # Test the connection by fetching organizations
        orgs = dashboard.organizations.getOrganizations()
        print(f"✅ Connection successful! Found {len(orgs)} organizations.")
        return True
        
    except meraki.exceptions.APIKeyError:
        print("❌ Invalid API key. Please check your key and try again.")
        return False
    except Exception as e:
        print(f"❌ Connection failed: {e}")
        return False

def select_organization() -> Optional[str]:
    """Let user select an organization or use preset from .env"""
    # Check for preset organization ID
    preset_org_id = os.getenv('MERAKI_ORG_ID')
    if preset_org_id and preset_org_id.strip():
        print(f"\n🏢 Using organization from .env: {preset_org_id}")
        return preset_org_id.strip()
    
    print("\n🏢 Select Organization")
    print("-" * 30)
    
    try:
        organizations = get_organizations()
        if not organizations:
            print("❌ No organizations found")
            return None
        
        if len(organizations) == 1:
            org = organizations[0]
            print(f"📍 Using organization: {org['name']} ({org['id']})")
            print("Tip: Save this in .env as MERAKI_ORG_ID to skip selection next time")
            return org['id']
        
        print("Available organizations:")
        for i, org in enumerate(organizations, 1):
            print(f"{i}. {org['name']} ({org['id']})")
        print("\nTip: Save your choice in .env as MERAKI_ORG_ID to skip selection next time")
        
        while True:
            try:
                choice = input(f"\nSelect organization (1-{len(organizations)}): ").strip()
                index = int(choice) - 1
                
                if 0 <= index < len(organizations):
                    selected_org = organizations[index]
                    print(f"✅ Selected: {selected_org['name']}")
                    return selected_org['id']
                else:
                    print(f"❌ Please enter a number between 1 and {len(organizations)}")
            except ValueError:
                print("❌ Please enter a valid number")
                
    except Exception as e:
        print(f"❌ Error fetching organizations: {e}")
        return None

def select_network(org_id: str) -> Optional[str]:
    """Let user select a network or use preset from .env"""
    # Check for preset network ID
    preset_network_id = os.getenv('MERAKI_NETWORK_ID')
    if preset_network_id and preset_network_id.strip():
        print(f"\n📡 Using network from .env: {preset_network_id}")
        return preset_network_id.strip()
    
    print("\n📡 Select Network")
    print("-" * 30)
    
    try:
        networks = get_networks(org_id)
        if not networks:
            print("❌ No networks found")
            return None
        
        # Filter to only wireless networks
        wireless_networks = [n for n in networks if 'wireless' in n.get('productTypes', [])]
        
        if not wireless_networks:
            print("❌ No wireless networks found")
            return None
        
        if len(wireless_networks) == 1:
            network = wireless_networks[0]
            print(f"📍 Using network: {network['name']} ({network['id']})")
            print("Tip: Save this in .env as MERAKI_NETWORK_ID to skip selection next time")
            return network['id']
        
        print("Available wireless networks:")
        for i, network in enumerate(wireless_networks, 1):
            print(f"{i}. {network['name']} ({network['id']})")
        print("\nTip: Save your choice in .env as MERAKI_NETWORK_ID to skip selection next time")
        
        while True:
            try:
                choice = input(f"\nSelect network (1-{len(wireless_networks)}): ").strip()
                index = int(choice) - 1
                
                if 0 <= index < len(wireless_networks):
                    selected_network = wireless_networks[index]
                    print(f"✅ Selected: {selected_network['name']}")
                    return selected_network['id']
                else:
                    print(f"❌ Please enter a number between 1 and {len(wireless_networks)}")
            except ValueError:
                print("❌ Please enter a valid number")
                
    except Exception as e:
        print(f"❌ Error fetching networks: {e}")
        return None

def get_investigation_parameters():
    """Get investigation date and time parameters from user"""
    print("\n📅 Investigation Parameters")
    print("-" * 30)
    
    # Check for existing CSV files
    csv_files = check_existing_csv_files()
    
    print("Choose investigation mode:")
    print("1. Last night (yesterday 18:00 to today 06:00) - fetch new API data")
    print("2. Specific date range - fetch new API data")
    print("3. Custom date and time - fetch new API data")
    print("4. Last 30 days log collection - fetch new API data")
    
    # Initialize CSV options outside the if block
    csv_options = {}
    option_num = 5
    
    if csv_files:
        print("\n📂 Available CSV data sources:")
        for filename, info in csv_files.items():
            age_desc = f"{info['age_hours']:.1f} hours ago" if info['age_hours'] < 24 else f"{info['age_hours']/24:.1f} days ago"
            location_desc = "📁 Current" if info['location'] == 'current' else "🗂️  History"
            print(f"{option_num}. {location_desc}: {filename} ({info['rows']} connections, {age_desc})")
            csv_options[str(option_num)] = filename
            option_num += 1
    
    max_option = option_num - 1 if csv_files else 4
    
    while True:
        choice = input(f"\nSelect option (1-{max_option}): ").strip()
        
        if choice == "1":
            # Last night
            yesterday = datetime.now() - timedelta(days=1)
            today = datetime.now()
            
            investigation_date = yesterday.strftime('%Y-%m-%d')
            investigation_time = DEFAULT_START_TIME
            target_end = today.strftime(f"%Y-%m-%dT{DEFAULT_END_TIME}:00.000Z")
            
            print(f"📅 Analyzing last night: {investigation_date} {DEFAULT_START_TIME} to today {DEFAULT_END_TIME}")
            return investigation_date, investigation_time, target_end
            
        elif choice == "2":
            # Specific date range
            while True:
                try:
                    date_str = input("Enter investigation date (YYYY-MM-DD): ").strip()
                    datetime.strptime(date_str, '%Y-%m-%d')  # Validate format
                    break
                except ValueError:
                    print("❌ Invalid date format. Please use YYYY-MM-DD")
            
            start_time = input(f"Enter start time (HH:MM, default {DEFAULT_START_TIME}): ").strip()
            if not start_time:
                start_time = DEFAULT_START_TIME
            
            end_time = input(f"Enter end time (HH:MM, default {DEFAULT_END_TIME}): ").strip()
            if not end_time:
                end_time = DEFAULT_END_TIME
            
            # Calculate end timestamp
            date_dt = datetime.strptime(date_str, '%Y-%m-%d')
            start_hour = int(start_time.split(':')[0])
            end_hour = int(end_time.split(':')[0])
            
            if end_hour <= start_hour:
                # End time is next day
                next_day = date_dt + timedelta(days=1)
                target_end = next_day.strftime(f"%Y-%m-%dT{end_time}:00.000Z")
            else:
                # End time is same day
                target_end = date_dt.strftime(f"%Y-%m-%dT{end_time}:00.000Z")
            
            print(f"📅 Analyzing: {date_str} from {start_time} to {end_time}")
            return date_str, start_time, target_end
            
        elif choice == "3":
            # Custom date and time
            while True:
                try:
                    start_datetime = input("Enter start date and time (YYYY-MM-DD HH:MM): ").strip()
                    end_datetime = input("Enter end date and time (YYYY-MM-DD HH:MM): ").strip()
                    
                    start_dt = datetime.strptime(start_datetime, '%Y-%m-%d %H:%M')
                    end_dt = datetime.strptime(end_datetime, '%Y-%m-%d %H:%M')
                    
                    if end_dt <= start_dt:
                        print("❌ End time must be after start time")
                        continue
                    
                    investigation_date = start_dt.strftime('%Y-%m-%d')
                    investigation_time = start_dt.strftime('%H:%M')
                    target_end = end_dt.strftime('%Y-%m-%dT%H:%M:00.000Z')
                    
                    print(f"📅 Analyzing custom range: {start_datetime} to {end_datetime}")
                    return investigation_date, investigation_time, target_end
                    
                except ValueError:
                    print("❌ Invalid date/time format. Please use YYYY-MM-DD HH:MM")
        
        elif choice == "4":
            # Last 30 days mode
            print("📅 Analyzing last 30 days of connection logs")
            return "30_days_mode", None, None
        
        elif choice in csv_options:
            # Use existing CSV data
            csv_filename = csv_options[choice]
            csv_info = csv_files[csv_filename]
            
            # Get the actual file path
            if csv_info['location'] == 'history':
                actual_csv_path = csv_info['full_path']
            else:
                actual_csv_path = csv_filename
                
            print(f"📂 Using existing CSV data from {csv_filename}")
            
            # Still need to get investigation timeframe for filtering
            print("\nSpecify investigation period to analyze from the CSV data:")
            print("A. Last night (yesterday 18:00 to today 06:00)")
            print("B. Specific date range")
            print("C. Custom date and time")
            
            while True:
                sub_choice = input("\nSelect timeframe (A-C): ").strip().upper()
                
                if sub_choice == "A":
                    # Last night
                    yesterday = datetime.now() - timedelta(days=1)
                    today = datetime.now()
                    
                    investigation_date = yesterday.strftime('%Y-%m-%d')
                    investigation_time = DEFAULT_START_TIME
                    target_end = today.strftime(f"%Y-%m-%dT{DEFAULT_END_TIME}:00.000Z")
                    
                    print(f"📅 Analyzing last night from CSV: {investigation_date} {DEFAULT_START_TIME} to today {DEFAULT_END_TIME}")
                    return "csv_mode", actual_csv_path, (investigation_date, investigation_time, target_end)
                
                elif sub_choice == "B":
                    # Specific date range
                    while True:
                        try:
                            date_str = input("Enter investigation date (YYYY-MM-DD): ").strip()
                            datetime.strptime(date_str, '%Y-%m-%d')  # Validate format
                            break
                        except ValueError:
                            print("❌ Invalid date format. Please use YYYY-MM-DD")
                    
                    start_time = input(f"Enter start time (HH:MM, default {DEFAULT_START_TIME}): ").strip()
                    if not start_time:
                        start_time = DEFAULT_START_TIME
                    
                    end_time = input(f"Enter end time (HH:MM, default {DEFAULT_END_TIME}): ").strip()
                    if not end_time:
                        end_time = DEFAULT_END_TIME
                    
                    # Calculate end timestamp
                    date_dt = datetime.strptime(date_str, '%Y-%m-%d')
                    start_hour = int(start_time.split(':')[0])
                    end_hour = int(end_time.split(':')[0])
                    
                    if end_hour <= start_hour:
                        # End time is next day
                        next_day = date_dt + timedelta(days=1)
                        target_end = next_day.strftime(f"%Y-%m-%dT{end_time}:00.000Z")
                    else:
                        # End time is same day
                        target_end = date_dt.strftime(f"%Y-%m-%dT{end_time}:00.000Z")
                    
                    print(f"📅 Analyzing from CSV: {date_str} from {start_time} to {end_time}")
                    return "csv_mode", actual_csv_path, (date_str, start_time, target_end)
                
                elif sub_choice == "C":
                    # Custom date and time
                    while True:
                        try:
                            start_datetime = input("Enter start date and time (YYYY-MM-DD HH:MM): ").strip()
                            end_datetime = input("Enter end date and time (YYYY-MM-DD HH:MM): ").strip()
                            
                            start_dt = datetime.strptime(start_datetime, '%Y-%m-%d %H:%M')
                            end_dt = datetime.strptime(end_datetime, '%Y-%m-%d %H:%M')
                            
                            if end_dt <= start_dt:
                                print("❌ End time must be after start time")
                                continue
                            
                            investigation_date = start_dt.strftime('%Y-%m-%d')
                            investigation_time = start_dt.strftime('%H:%M')
                            target_end = end_dt.strftime('%Y-%m-%dT%H:%M:00.000Z')
                            
                            print(f"📅 Analyzing custom range from CSV: {start_datetime} to {end_datetime}")
                            return "csv_mode", actual_csv_path, (investigation_date, investigation_time, target_end)
                            
                        except ValueError:
                            print("❌ Invalid date/time format. Please use YYYY-MM-DD HH:MM")
                else:
                    print("❌ Please select A, B, or C")
        
        else:
            if csv_files:
                print(f"❌ Please select 1-{max_option}")
            else:
                print("❌ Please select 1, 2, 3, or 4")

def run_30_day_analysis(org_id: str, network_id: str):
    """Run 30-day log collection and stream to CSV for memory efficiency"""
    print("\n🔍 Starting 30-Day Log Collection")
    print("-" * 40)
    
    # Create history directory for this collection
    history_path = create_history_directory()
    
    
    print(f"🏢 Organization: {org_id}")
    print(f"📡 Network: {network_id}")
    print(f"📁 History: {history_path}")
    
    # Get organization and network info
    organizations = [{'id': org_id, 'name': f'Organization {org_id}'}]
    networks = [{'id': network_id, 'name': f'Network {network_id}', 'productTypes': ['wireless']}]
    
    filename = "last_30_days_log.csv"
    total_connections = 0
    
    # Open CSV file for streaming write
    with open(filename, 'w', newline='', encoding='utf-8') as csvfile:
        fieldnames = ['organization', 'network', 'timestamp', 'event_type', 'client_mac', 
                     'client_description', 'device_serial', 'ssid', 'description']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        
        for org in organizations:
            org_name = org['name']
            
            for network in networks:
                current_network_id = network['id']
                network_name = network['name']
                
                print(f"\n📡 Streaming logs from network: {network_name}")
                
                # Test network connectivity
                network_test = test_network_connectivity(current_network_id)
                
                if network_test.get('recent_events_count', 0) == 0:
                    print("⚠️  No recent events found, this network might not have wireless activity")
                    continue
                
                # Stream 30 days data directly to CSV
                connections_written = stream_30_days_to_csv(current_network_id, org_name, network_name, writer)
                total_connections += connections_written
    
    if total_connections > 0:
        print(f"\n✅ Last 30 days log exported to: {filename}")
        print(f"📊 Total connections logged: {total_connections}")
        print(f"💾 Memory-efficient streaming used - no data kept in memory")
        
        # Save to history
        print(f"\n📁 Saving to history...")
        description = f"30-day log collection from {org_id}/{network_id} - {total_connections} connections"
        copy_files_to_history(history_path, [filename], description)
        
        print(f"✅ Data saved to history: {os.path.basename(history_path)}")
        print(f"ℹ️  For summary statistics, you can analyze the CSV file")
        
    else:
        print("ℹ️  No connections found in the last 30 days")
        # Remove empty history directory
        if os.path.exists(history_path):
            os.rmdir(history_path)

def run_csv_analysis(csv_filename: str, params: tuple):
    """Run analysis using existing CSV data"""
    investigation_date, investigation_time, target_end = params
    
    print("\n🔍 Starting CSV-Based Analysis")
    print("-" * 40)
    
    # Create history directory for this analysis
    history_path = create_history_directory()
    
    # Clean up old CSV files (except the source file)
    
    print(f"📂 Source: {csv_filename}")
    print(f"📅 Investigation period: {investigation_date} {investigation_time} to {target_end}")
    print(f"📁 History: {history_path}")
    
    # Load and filter CSV data
    all_connections = load_csv_data_for_investigation(csv_filename, investigation_date, investigation_time, target_end)
    
    if all_connections:
        print("\n🔍 Analyzing out-of-hours device patterns...")
        # Use the investigation date as the target date
        target_date = investigation_date
        
        pattern_analysis = analyze_out_of_hours_patterns(all_connections, target_date)
        
        print(f"\n📊 Analysis Results:")
        print(f"✅ Total connections analyzed: {len(all_connections)}")
        print(f"📱 Devices active on target date: {len(pattern_analysis['target_date_devices'])}")
        print(f"🔄 Baseline regular devices: {len(pattern_analysis['baseline_regular_devices'])}")
        print(f"🚨 Anomalous devices (suspicious): {len(pattern_analysis['anomalous_devices'])}")
        print(f"📋 Baseline-only devices: {len(pattern_analysis['baseline_only_devices'])}")
        print(f"🕐 Extended session devices: {len(pattern_analysis.get('extended_session_devices', []))}")
        
        # Export analysis
        export_out_of_hours_analysis_to_csv(all_connections, pattern_analysis, history_path)
        
        # Save analysis results to history
        analysis_files = [
            "all_connections.csv",
            "target_date_devices.csv", 
            "baseline_regular_devices.csv",
            "anomalous_devices.csv",
            "baseline_only_devices.csv",
            "extended_session_devices.csv"
        ]
        
        print(f"\n📁 Saving analysis to history...")
        description = f"Investigation analysis for {investigation_date} {investigation_time} to {target_end} (source: {csv_filename})"
        copy_files_to_history(history_path, analysis_files, description)
        
        print(f"\n📊 Analysis complete! Results saved to:")
        print(f"   🏠 Current directory: all analysis CSV files")
        print(f"   📁 History: {os.path.basename(history_path)}")
        print(f"📂 Source data: {csv_filename}")
        
    else:
        print("ℹ️  No connections found in the specified time period")
        # Remove empty history directory
        if os.path.exists(history_path):
            os.rmdir(history_path)

def run_analysis(org_id: str, network_id: str, investigation_date: str, investigation_time: str, target_end: str):
    """Run the main analysis"""
    print("\n🔍 Starting Analysis")
    print("-" * 30)
    
    # Create history directory for this analysis
    history_path = create_history_directory()
    
    
    print(f"📅 Investigation period: {investigation_date} {investigation_time} to {target_end}")
    print(f"🏢 Organization: {org_id}")
    print(f"📡 Network: {network_id}")
    print(f"📁 History: {history_path}")
    
    all_connections = []
    
    # Get organization and network info
    organizations = [{'id': org_id, 'name': f'Organization {org_id}'}]
    networks = [{'id': network_id, 'name': f'Network {network_id}', 'productTypes': ['wireless']}]
    
    for org in organizations:
        current_org_id = org['id']
        org_name = org['name']
        
        for network in networks:
            current_network_id = network['id']
            network_name = network['name']
            
            print(f"\n📡 Analyzing network: {network_name}")
            
            # Test network connectivity
            network_test = test_network_connectivity(current_network_id)
            
            if network_test.get('recent_events_count', 0) == 0:
                print("⚠️  No recent events found, this network might not have wireless activity")
                continue
            
            # Get comprehensive baseline events
            baseline_events = get_comprehensive_baseline_events(current_network_id, investigation_date)
            
            # Get target date events  
            target_dt = datetime.fromisoformat(investigation_date)
            time_parts = investigation_time.split(':')
            target_dt = target_dt.replace(hour=int(time_parts[0]), minute=int(time_parts[1]), second=0, microsecond=0)
            formatted_start = target_dt.isoformat()
            
            print(f"🔍 Collecting target date events from {formatted_start} until {target_end}")
            target_events = get_client_events(current_network_id, formatted_start, target_end)
            
            # Combine and process events
            all_events = baseline_events + target_events
            seen_events = set()
            deduplicated_events = []
            
            for event in all_events:
                event_key = (event.get('occurredAt'), event.get('clientMac'), event.get('type'))
                if event_key not in seen_events:
                    seen_events.add(event_key)
                    deduplicated_events.append(event)
            
            print(f"📊 Processing {len(deduplicated_events)} unique events")
            
            for event in deduplicated_events:
                if event.get('type') in ['association', 'wpa_auth', 'disassociation']:
                    connection_data = {
                        'organization': org_name,
                        'network': network_name,
                        'timestamp': event.get('occurredAt'),
                        'event_type': event.get('type'),
                        'client_mac': event.get('clientMac'),
                        'client_description': event.get('clientDescription', ''),
                        'device_serial': event.get('deviceSerial'),
                        'ssid': event.get('ssid', ''),
                        'description': event.get('description', '')
                    }
                    all_connections.append(connection_data)
    
    # Analyze patterns
    if all_connections:
        print("\n🔍 Analyzing out-of-hours device patterns...")
        # Use the investigation date as the target date
        target_date = investigation_date
        
        pattern_analysis = analyze_out_of_hours_patterns(all_connections, target_date)
        
        print(f"\n📊 Analysis Results:")
        print(f"✅ Total connections found: {len(all_connections)}")
        print(f"📱 Devices active on target date: {len(pattern_analysis['target_date_devices'])}")
        print(f"🔄 Baseline regular devices: {len(pattern_analysis['baseline_regular_devices'])}")
        print(f"🚨 Anomalous devices (suspicious): {len(pattern_analysis['anomalous_devices'])}")
        print(f"📋 Baseline-only devices: {len(pattern_analysis['baseline_only_devices'])}")
        print(f"🕐 Extended session devices: {len(pattern_analysis.get('extended_session_devices', []))}")
        
        # Export analysis
        export_out_of_hours_analysis_to_csv(all_connections, pattern_analysis, history_path)
        
        # Save analysis results to history
        analysis_files = [
            "all_connections.csv",
            "target_date_devices.csv", 
            "baseline_regular_devices.csv",
            "anomalous_devices.csv",
            "baseline_only_devices.csv",
            "extended_session_devices.csv"
        ]
        
        print(f"\n📁 Saving analysis to history...")
        description = f"API investigation analysis for {investigation_date} {investigation_time} to {target_end} (org: {org_id}, network: {network_id})"
        copy_files_to_history(history_path, analysis_files, description)
        
        print(f"\n📊 Analysis complete! Results saved to:")
        print(f"   🏠 Current directory: all analysis CSV files")
        print(f"   📁 History: {os.path.basename(history_path)}")
        
    else:
        print("ℹ️  No connections found in the specified time period")
        # Remove empty history directory
        if os.path.exists(history_path):
            os.rmdir(history_path)

def get_investigation_timeframe():
    """Get investigation timeframe for API mode (no CSV option)"""
    print("Choose investigation timeframe:")
    print("1. Last night (yesterday 18:00 to today 06:00)")
    print("2. Specific date range")
    print("3. Custom date and time")
    print("4. Last 30 days log collection")
    
    while True:
        try:
            choice = input("\nSelect timeframe (1-4): ").strip()
            if choice in ['1', '2', '3', '4']:
                return {
                    '1': 'last_night',
                    '2': 'specific_date',
                    '3': 'custom',
                    '4': '30_days'
                }[choice]
            else:
                print("❌ Invalid choice. Please select 1, 2, 3, or 4.")
        except KeyboardInterrupt:
            return None

def get_investigation_details(timeframe):
    """Get specific investigation details based on timeframe"""
    if timeframe == 'last_night':
        # Last night logic
        today = datetime.now()
        yesterday = today - timedelta(days=1)
        
        investigation_date = yesterday.strftime('%Y-%m-%d')
        investigation_time = DEFAULT_START_TIME
        target_end_dt = today.replace(hour=int(DEFAULT_END_TIME.split(':')[0]), minute=int(DEFAULT_END_TIME.split(':')[1]), second=0, microsecond=0)
        target_end = target_end_dt.isoformat()
        
        return investigation_date, investigation_time, target_end
        
    elif timeframe == 'specific_date':
        # Get specific date
        investigation_date = input("Enter investigation date (YYYY-MM-DD): ").strip()
        try:
            datetime.strptime(investigation_date, '%Y-%m-%d')
        except ValueError:
            print("❌ Invalid date format")
            return None, None, None
            
        investigation_time = DEFAULT_START_TIME
        
        # Calculate target end (next day 06:00)
        target_date = datetime.strptime(investigation_date, '%Y-%m-%d')
        target_end_dt = target_date + timedelta(days=1)
        target_end_dt = target_end_dt.replace(hour=int(DEFAULT_END_TIME.split(':')[0]), minute=int(DEFAULT_END_TIME.split(':')[1]), second=0, microsecond=0)
        target_end = target_end_dt.isoformat()
        
        return investigation_date, investigation_time, target_end
        
    elif timeframe == 'custom':
        # Get custom date and time
        investigation_date = input("Enter investigation date (YYYY-MM-DD): ").strip()
        try:
            datetime.strptime(investigation_date, '%Y-%m-%d')
        except ValueError:
            print("❌ Invalid date format")
            return None, None, None
            
        investigation_time = input(f"Enter start time (HH:MM, default {DEFAULT_START_TIME}): ").strip()
        if not investigation_time:
            investigation_time = DEFAULT_START_TIME
            
        end_time = input(f"Enter end time (HH:MM, default {DEFAULT_END_TIME}): ").strip()
        if not end_time:
            end_time = DEFAULT_END_TIME
            
        # Convert to target_end format
        target_date = datetime.strptime(investigation_date, '%Y-%m-%d')
        if end_time < investigation_time:  # End time is next day
            target_date = target_date + timedelta(days=1)
            
        target_end_dt = target_date.replace(hour=int(end_time.split(':')[0]), minute=int(end_time.split(':')[1]), second=0, microsecond=0)
        target_end = target_end_dt.isoformat()
        
        return investigation_date, investigation_time, target_end
    
    return None, None, None

def get_csv_file_selection():
    """Get CSV file selection for analysis"""
    csv_files = check_existing_csv_files()
    
    if not csv_files:
        print("❌ No CSV files found. Please run '30-Day Baseline Collection' first.")
        return None
        
    print("\n📂 Available CSV data sources:")
    options = {}
    option_num = 1
    
    for filename, info in csv_files.items():
        age_desc = f"{info['age_hours']:.1f} hours ago" if info['age_hours'] < 24 else f"{info['age_hours']/24:.1f} days ago"
        location_desc = "📁 Current" if info['location'] == 'current' else "🗂️  History"
        print(f"{option_num}. {location_desc}: {filename} ({info['rows']} connections, {age_desc})")
        options[str(option_num)] = filename
        option_num += 1
    
    while True:
        try:
            choice = input(f"\nSelect CSV file (1-{len(options)}): ").strip()
            if choice in options:
                return options[choice]
            else:
                print(f"❌ Invalid choice. Please select 1-{len(options)}.")
        except KeyboardInterrupt:
            return None

def get_investigation_date_for_csv():
    """Get investigation date for CSV analysis"""
    investigation_date = input("Enter investigation date (YYYY-MM-DD): ").strip()
    try:
        datetime.strptime(investigation_date, '%Y-%m-%d')
        return investigation_date
    except ValueError:
        print("❌ Invalid date format")
        return datetime.now().strftime('%Y-%m-%d')

def show_main_menu():
    """Display the main menu and get user choice"""
    clear_screen()
    print_header()
    
    print("\n📋 Main Menu")
    print("=" * 50)
    print("1. 🔍 Run Investigation (API)")
    print("2. 📊 Analyze CSV Data")
    print("3. 📅 Collect 30-Day Baseline")
    print("4. 🚪 Exit")
    print("=" * 50)
    
    while True:
        try:
            choice = input("\nSelect an option (1-4): ").strip()
            if choice in ['1', '2', '3', '4']:
                return choice
            else:
                print("❌ Invalid choice. Please select 1, 2, 3, or 4.")
        except KeyboardInterrupt:
            print("\n\n👋 Goodbye!")
            sys.exit(0)

def run_investigation_workflow(org_id, network_id):
    """Run the investigation workflow"""
    # Get investigation parameters  
    result = get_investigation_parameters()
    
    # Handle different return formats
    if isinstance(result, tuple) and len(result) == 3:
        if result[0] == "30_days_mode":
            run_30_day_analysis(org_id, network_id)
        elif result[0] == "csv_mode":
            run_csv_analysis(result[1], result[2])
        else:
            # Normal API mode
            investigation_date, investigation_time, target_end = result
            run_analysis(org_id, network_id, investigation_date, investigation_time, target_end)
    else:
        print("❌ Invalid investigation parameters")
        return
    
    print("\n🎉 Analysis completed successfully!")
    input("\nPress Enter to continue...")

def main():
    """Main application entry point"""
    clear_screen()
    print_header()
    
    # Get API key
    api_key = get_api_key()
    if not api_key:
        sys.exit(1)
    
    # Initialize dashboard
    if not initialize_dashboard(api_key):
        sys.exit(1)
    
    # Select organization
    org_id = select_organization()
    if not org_id:
        sys.exit(1)
    
    # Select network
    network_id = select_network(org_id)
    if not network_id:
        sys.exit(1)
    
    # Main menu loop
    while True:
        try:
            choice = show_main_menu()
            
            if choice == '1':
                # Run Investigation (API) - Force API mode
                print("\n📡 Running API Investigation")
                print("=" * 50)
                
                # Get investigation timeframe (skip CSV option)
                timeframe = get_investigation_timeframe()
                if timeframe == "30_days":
                    run_30_day_analysis(org_id, network_id)
                else:
                    investigation_date, investigation_time, target_end = get_investigation_details(timeframe)
                    run_analysis(org_id, network_id, investigation_date, investigation_time, target_end)
                    
            elif choice == '2':
                # Analyze CSV Data - Force CSV mode
                print("\n📊 Analyzing CSV Data")
                print("=" * 50)
                
                # Get CSV file selection
                csv_filename = get_csv_file_selection()
                if csv_filename:
                    investigation_date = get_investigation_date_for_csv()
                    # Create dummy params tuple for CSV analysis (only investigation_date is used)
                    params = (investigation_date, "18:00", "06:00")
                    run_csv_analysis(csv_filename, params)
                else:
                    print("❌ No CSV file selected")
                    input("\nPress Enter to continue...")
                    continue
                    
            elif choice == '3':
                # Collect 30-Day Baseline
                run_30_day_analysis(org_id, network_id)
                
            elif choice == '4':
                # Exit
                print("\n👋 Goodbye!")
                sys.exit(0)
            
            print("\n🎉 Analysis completed successfully!")
            input("\nPress Enter to continue...")
            
        except KeyboardInterrupt:
            print("\n\n👋 Goodbye!")
            sys.exit(0)
        except Exception as e:
            print(f"\n❌ Error: {e}")
            input("\nPress Enter to continue...")

if __name__ == "__main__":
    main()