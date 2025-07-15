# Meraki Client Detective - CLI Application

A command-line tool for analyzing WiFi connection data from Meraki networks. Designed for security investigations to identify suspicious device connections and patterns during potential theft or unauthorized access incidents.

## What It Does

This tool analyzes WiFi connection logs to identify devices that show suspicious behavior patterns:

- **Baseline Analysis**: Compares target investigation period against 7-day historical baseline
- **Out-of-Hours Detection**: Identifies devices connecting during after-hours (18:00-06:00)
- **Extended Session Detection**: Finds devices that arrive during business hours but stay past 18:00
- **Risk Classification**: Categorizes devices as regular, suspicious, or anomalous based on connection patterns
- **Pattern Recognition**: Detects unusual device behavior that may indicate theft or unauthorized access

## Features

- **Interactive Main Menu**: Choose between API investigation, CSV analysis, or 30-day baseline collection
- **Cross-Platform Support**: Works on Windows, macOS, and Linux
- **Standalone Executable**: No Python installation required for end users
- **Environment Configuration**: Save API credentials in .env file for streamlined usage
- **Historical Data Management**: Save and reuse analysis results with timestamps

## Quick Start

### For End Users (Pre-built Executable)

1. Download the `meraki-client-detective` executable for your platform
2. Create a `.env` file with your credentials (optional):
   ```bash
   cp .env.example .env
   # Edit .env with your API credentials
   ```
3. Run the executable:
   ```bash
   ./meraki-client-detective
   ```
4. Follow the interactive setup and main menu:
   - Enter API credentials (if not in .env)
   - Select organization and network
   - Choose from main menu options:
     - **🔍 Run Investigation (API)**: Fetch new data and analyze
     - **📊 Analyze CSV Data**: Analyze existing CSV files
     - **📅 Collect 30-Day Baseline**: Gather historical data
     - **🚪 Exit**: Exit application

### For Developers (Build from Source)

#### Prerequisites

- Python 3.7 or higher
- Meraki Dashboard API key

#### Build Instructions

```bash
# Clone repository
git clone [repository]
cd cli_app

# Create virtual environment
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Create environment file (optional)
cp .env.example .env
# Edit .env with your API credentials

# Build executable
pyinstaller --onefile --name meraki-client-detective app.py

# Run the executable
./dist/meraki-client-detective
```

## Main Menu Options

### 🔍 Run Investigation (API)

Fetch new data from Meraki API and analyze:

- **Last Night**: Yesterday 18:00 to today 06:00
- **Specific Date**: Custom date with 18:00-06:00 timeframe
- **Custom Range**: Full date and time range specification
- **30-Day Collection**: Collect comprehensive baseline data

### 📊 Analyze CSV Data

Analyze existing CSV files without API calls:

- Select from available CSV files (current directory or history)
- Specify investigation date for analysis
- Reuse previously collected data

### 📅 Collect 30-Day Baseline

Gather 30 days of historical connection data for future analysis

## Analysis Output

The tool generates CSV files with different device categories:

### Core Analysis Files

- **`all_connections.csv`** - Raw connection data from API
- **`target_date_devices.csv`** - All devices active during investigation period
- **`anomalous_devices.csv`** - ⚠️ **SUSPICIOUS** devices requiring investigation priority
- **`baseline_regular_devices.csv`** - Devices with normal out-of-hours patterns
- **`baseline_only_devices.csv`** - Regular devices absent during investigation

### Extended Analysis Files

- **`extended_session_devices.csv`** - Devices connecting during business hours but staying past 18:00
- **`loitering_devices.csv`** - Devices showing potential insider threat patterns
- **`last_30_days_log.csv`** - 30-day baseline data collection

### Risk Classifications

- **ANOMALOUS_SUSPICIOUS**: Never seen before or unusual patterns
- **LOITERING_SUSPICIOUS**: Arrived during business hours, stayed late (8+ hours)
- **BASELINE_REGULAR**: Expected out-of-hours devices
- **BASELINE_ONLY**: Always-on devices that disappeared during investigation

### Environment Configuration (Optional)

For streamlined usage, create a `.env` file in the CLI directory:

```bash
# Copy from .env.example
cp .env.example .env

# Edit the file with your credentials
MERAKI_DASHBOARD_API_KEY=your_api_key_here
MERAKI_ORG_ID=your_org_id_here
MERAKI_NETWORK_ID=your_network_id_here
```

When configured, the CLI will automatically use these values instead of prompting for input.

## Build from Source

```bash
# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Build executable
pyinstaller --onefile --name meraki-client-detective app.py
```
