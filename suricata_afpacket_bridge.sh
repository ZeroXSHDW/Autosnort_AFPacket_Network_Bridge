#!/bin/bash
# Suricata AFPACKET Bridge Startup Script
# This script starts Suricata in AFPACKET bridge mode for Ubuntu 18.04+
# Designed to work with a configuration file (full_suricata.conf)
# Includes logging, interface validation, and systemd service setup
# Based on Autosnort script structure for consistency

# Logging setup
logfile=/var/log/suricata_afpacket_install.log
mkfifo ${logfile}.pipe
tee < ${logfile}.pipe $logfile &
exec &> ${logfile}.pipe
rm ${logfile}.pipe

# Add timestamp to log
echo "[$(date '+%Y-%m-%d %H:%M:%S %Z')] Starting Suricata AFPACKET bridge script" >> $logfile

########################################
# Metasploit-like print functions
function print_status()
{
    echo -e "[$(date '+%Y-%m-%d %H:%M:%S %Z')] \x1B[01;34m[*]\x1B[0m $1" | tee -a $logfile
}

function print_good()
{
    echo -e "[$(date '+%Y-%m-%d %H:%M:%S %Z')] \x1B[01;32m[*]\x1B[0m $1" | tee -a $logfile
}

function print_error()
{
    echo -e "[$(date '+%Y-%m-%d %H:%M:%S %Z')] \x1B[01;31m[*]\x1B[0m $1" | tee -a $logfile
}

function print_notification()
{
    echo -e "[$(date '+%Y-%m-%d %H:%M:%S %Z')] \x1B[01;33m[*]\x1B[0m $1" | tee -a $logfile
}

########################################
# Error checking function
function error_check()
{
    local status=$?
    if [ $status -eq 0 ]; then
        print_good "$1 successfully completed."
    else
        print_error "$1 failed with exit code $status. Please check $logfile for more details."
        exit 1
    fi
}

########################################
# Directory creation function
function dir_check()
{
    if [ ! -d "$1" ]; then
        print_notification "$1 does not exist. Creating..."
        mkdir -p "$1" &>> $logfile
        chown suricata:suricata "$1" &>> $logfile
        chmod 770 "$1" &>> $logfile
        error_check "Creation of $1"
    else
        print_notification "$1 already exists."
    fi
}

########################################
# Validate network interfaces
function validate_interfaces()
{
    print_status "Validating network interfaces for AFPACKET bridge..."
    for iface in "$suricata_iface_1" "$suricata_iface_2"; do
        if [ -z "$iface" ]; then
            print_error "Network interface not defined in full_suricata.conf. Please set suricata_iface_1 and suricata_iface_2."
            exit 1
        fi
        ip link show "$iface" &>> $logfile
        if [ $? -ne 0 ]; then
            print_error "Network interface $iface does not exist. Check full_suricata.conf."
            exit 1
        fi
        print_good "Network interface $iface exists."
    done
}

########################################
# Disable network offloading
function disable_offloading()
{
    print_status "Disabling offloading options on interfaces $suricata_iface_1 and $suricata_iface_2..."
    for iface in "$suricata_iface_1" "$suricata_iface_2"; do
        ethtool -K "$iface" rx off &>> $logfile
        ethtool -K "$iface" tx off &>> $logfile
        ethtool -K "$iface" sg off &>> $logfile
        ethtool -K "$iface" tso off &>> $logfile
        ethtool -K "$iface" ufo off &>> $logfile
        ethtool -K "$iface" gso off &>> $logfile
        ethtool -K "$iface" gro off &>> $logfile
        ethtool -K "$iface" lro off &>> $logfile
        error_check "Disabling offloading for $iface"
    done
}

########################################
# Validate Suricata configuration
function validate_suricata_config()
{
    print_status "Validating Suricata configuration..."

    # Check if suricata.yaml exists
    if [ ! -f "$suricata_basedir/suricata.yaml" ]; then
        print_error "suricata.yaml not found at $suricata_basedir/suricata.yaml. Ensure Suricata is installed and configured."
        exit 1
    fi
    print_good "suricata.yaml found at $suricata_basedir/suricata.yaml"

    # Check if rules directory exists and is non-empty
    if [ ! -d "$suricata_basedir/rules" ]; then
        print_error "Rules directory not found at $suricata_basedir/rules."
        exit 1
    fi
    if ! ls "$suricata_basedir/rules"/*.rules >/dev/null 2>&1; then
        print_error "No rule files found in $suricata_basedir/rules. Ensure rules are installed."
        exit 1
    fi
    print_good "Rules directory contains rule files."

    # Test Suricata configuration
    print_status "Testing Suricata configuration..."
    /usr/bin/suricata -T -c "$suricata_basedir/suricata.yaml" --af-packet &>> $logfile
    if [ $? -ne 0 ]; then
        print_error "Suricata configuration test failed. Check $suricata_basedir/suricata.yaml and $logfile for errors."
        print_notification "Run manually: /usr/bin/suricata -T -c $suricata_basedir/suricata.yaml --af-packet"
        exit 1
    fi
    print_good "Suricata configuration test passed."
}

########################################
## MAIN SCRIPT ##

# Pre-checks: Ensure config file exists and script is run as root
print_status "Checking for config file..."
execdir=$(pwd)
if [ ! -f "$execdir/full_suricata.conf" ]; then
    print_error "full_suricata.conf not found in $execdir. Please create it with suricata_basedir, suricata_iface_1, and suricata_iface_2 defined."
    exit 1
fi
print_good "Found config file at $execdir/full_suricata.conf."
source "$execdir/full_suricata.conf"

print_status "Checking for root privileges..."
if [ "$(whoami)" != "root" ]; then
    print_error "This script must be run with sudo or root privileges."
    exit 1
fi
print_good "Running as root."

# Validate suricata_basedir
if [ -z "$suricata_basedir" ]; then
    print_error "suricata_basedir is not defined in full_suricata.conf. Please set it to a valid directory path."
    exit 1
fi
dir_check "$suricata_basedir"
print_good "suricata_basedir validated: $suricata_basedir"

# Validate Suricata binary
if [ ! -x "/usr/bin/suricata" ]; then
    print_error "Suricata binary not found at /usr/bin/suricata. Ensure Suricata is installed."
    exit 1
fi
print_good "Suricata binary found."

# Validate interfaces
validate_interfaces

# Disable network offloading
disable_offloading

# Validate Suricata configuration
validate_suricata_config

# Create log directory
dir_check /var/log/suricata
chown suricata:suricata /var/log/suricata &>> $logfile
chmod 770 /var/log/suricata &>> $logfile
error_check "Setting permissions for /var/log/suricata"

# Create systemd service
print_status "Configuring systemd service for Suricata AFPACKET bridge..."
if [ -f /etc/systemd/system/suricata-afpacket.service ]; then
    print_notification "suricata-afpacket.service already exists. Overwriting..."
fi

cat > /etc/systemd/system/suricata-afpacket.service << EOL
[Unit]
Description=Suricata AFPACKET Bridge
After=network.target

[Service]
ExecStart=/usr/bin/suricata -c $suricata_basedir/suricata.yaml --af-packet=$suricata_iface_1:$suricata_iface_2 -D -v --pidfile /var/run/suricata.pid
ExecReload=/bin/kill -HUP \$MAINPID
ExecStop=/bin/kill -TERM \$MAINPID
Restart=always
User=suricata
Group=suricata
PIDFile=/var/run/suricata.pid

[Install]
WantedBy=multi-user.target
EOL

chown root:root /etc/systemd/system/suricata-afpacket.service &>> $logfile
chmod 700 /etc/systemd/system/suricata-afpacket.service &>> $logfile
error_check "Creation of suricata-afpacket.service"

systemctl daemon-reload &>> $logfile
error_check "systemctl daemon-reload"

systemctl enable suricata-afpacket.service &>> $logfile
error_check "Enabling suricata-afpacket.service"

# Start Suricata service
print_status "Starting suricata-afpacket.service..."
systemctl start suricata-afpacket.service &>> $logfile
if [ $? -ne 0 ]; then
    print_error "Failed to start suricata-afpacket.service. Check systemctl status suricata-afpacket.service and $logfile for details."
    exit 1
fi
print_good "suricata-afpacket.service started successfully."

print_notification "Suricata AFPACKET bridge started. Log file: $logfile"
print_good "Setup complete. Suricata is running in AFPACKET bridge mode on interfaces $suricata_iface_1 and $suricata_iface_2."
exit 0