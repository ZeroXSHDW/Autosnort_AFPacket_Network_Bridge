#!/bin/bash
# Autosnort script for Ubuntu 18.04+
# Please note that this version of the script is specifically made available for students of Building Virtual Labs training on networkdefense.io, as well as the book, Building Virtual Machine Labs: A Hands-On Guide
# This script configures Snort and PulledPork with enhanced logging and debugging for rule downloads, targeting PulledPork 0.8.0
# Modified to enhance verification of Perl modules (libwww-perl, libarchive-zip-perl, libcrypt-ssleay-perl, liblwp-protocol-https-perl)
# PulledPork section reverted to original code from autosnort-ubuntu-AVATAR-orig.sh for version 0.8.0
# Updated GPG key import with retries, multiple keyservers, and fallback for apt keyring
# Updated snort.conf download to use hardcoded URL with retries
# Added validation checks for snort.conf, rules, and interfaces to prevent service startup failures
# Fixed syntax error on line 376 (incomplete cp command) and ensured all blocks are closed

# Logging setup. Uses FIFO/pipe to log all output to a file for troubleshooting.
logfile=/var/log/autosnort_install.log
mkfifo ${logfile}.pipe
tee < ${logfile}.pipe $logfile &
exec &> ${logfile}.pipe
rm ${logfile}.pipe

# Add timestamp to log for debugging.
echo "[$(date '+%Y-%m-%d %H:%M:%S %Z')] Starting Autosnort script" >> $logfile

########################################

# Metasploit-like print statements for status, success, error, and notification messages.
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

# Error checking function. Exits on non-zero status with details logged.
function error_check()
{
    local status=$?
    if [ $status -eq 0 ]; then
        print_good "$1 successfully completed."
    else
        print_error "$1 failed with exit code $status. Please check $logfile for more details, or contact deusexmachina667 at gmail dot com for more assistance."
        exit 1
    fi
}

########################################
# Package installation function.
function install_packages()
{
    print_status "Updating package lists and installing packages: ${@}"
    apt-get update &>> $logfile && apt-get install -y "${@}" &>> $logfile
    error_check "Package installation for ${@}"
}

########################################
# Function to import GPG keys with retries and multiple keyservers.
function import_gpg_key()
{
    local key_id=$1
    local key_file=$2
    local keyservers=("hkp://keyserver.ubuntu.com:80" "hkp://pgp.mit.edu:80" "hkp://keys.openpgp.org:80")
    local max_attempts=3
    local attempt=1
    local success=0

    print_status "Importing GPG key $key_id..."

    # Try each keyserver up to max_attempts times
    while [ $attempt -le $max_attempts ] && [ $success -eq 0 ]; do
        for keyserver in "${keyservers[@]}"; do
            print_notification "Attempt $attempt: Retrieving key $key_id from $keyserver..."
            gpg --keyserver "$keyserver" --recv-keys "$key_id" &>> $logfile
            if [ $? -eq 0 ]; then
                print_good "Successfully retrieved key $key_id from $keyserver"
                # Verify key presence
                gpg --list-keys "$key_id" &>> $logfile
                if [ $? -eq 0 ]; then
                    success=1
                    break
                else
                    print_notification "Key $key_id retrieved but not found in keyring. Retrying..."
                fi
            else
                print_notification "Failed to retrieve key $key_id from $keyserver."
            fi
        done
        attempt=$((attempt + 1))
        sleep 5
    done

    if [ $success -eq 0 ]; then
        print_error "Failed to retrieve GPG key $key_id after $max_attempts attempts across multiple keyservers."
        exit 1
    fi

    # Export key in ASCII-armored format
    print_status "Exporting key $key_id to /etc/apt/trusted.gpg.d/$key_file.asc..."
    gpg --export --armor "$key_id" > "/etc/apt/trusted.gpg.d/$key_file.asc" &>> $logfile
    error_check "Export GPG key $key_id to /etc/apt/trusted.gpg.d/$key_file.asc"

    # Export key in binary format as fallback
    print_status "Exporting key $key_id to /etc/apt/trusted.gpg.d/$key_file.gpg..."
    gpg --export "$key_id" > "/etc/apt/trusted.gpg.d/$key_file.gpg" &>> $logfile
    error_check "Export GPG key $key_id to /etc/apt/trusted.gpg.d/$key_file.gpg"

    # Set permissions
    chmod 644 "/etc/apt/trusted.gpg.d/$key_file.asc" "/etc/apt/trusted.gpg.d/$key_file.gpg" &>> $logfile
    error_check "Setting permissions for GPG key files $key_file"
}

########################################
# Function to verify and ensure apt recognizes keys.
function verify_apt_keyring()
{
    local key_id=$1
    print_status "Verifying apt recognizes key $key_id..."

    # Run apt-get update to test keyring
    apt-get update &>> $logfile
    if [ $? -ne 0 ]; then
        print_notification "apt-get update failed. Checking for NO_PUBKEY $key_id..."
        if grep -qi "NO_PUBKEY.*$key_id" $logfile; then
            print_notification "Key $key_id not recognized by apt. Attempting fallback import to apt-key..."
            # Fallback: Import to apt-key for Ubuntu 18.04 compatibility
            gpg --export "$key_id" | apt-key add - &>> $logfile
            if [ $? -eq 0 ]; then
                print_good "Fallback: Successfully added key $key_id to apt keyring"
                # Retry apt-get update
                apt-get update &>> $logfile
                error_check "apt-get update after fallback key import for $key_id"
            else
                print_error "Fallback: Failed to add key $key_id to apt keyring."
                exit 1
            fi
        else
            print_error "apt-get update failed for reasons other than missing key $key_id. Check $logfile."
            exit 1
        fi
    else
        print_good "apt-get update succeeded. Key $key_id is recognized."
    fi
}

########################################
# Function to validate Snort configuration and dependencies.
function validate_snort_config()
{
    print_status "Validating Snort configuration and dependencies..."

    # Check if snort.conf exists
    if [ ! -f "$snort_basedir/etc/snort.conf" ]; then
        print_error "snort.conf not found at $snort_basedir/etc/snort.conf. Ensure download was successful."
        exit 1
    fi
    print_good "snort.conf found at $snort_basedir/etc/snort.conf"

    # Check if snort.rules exists and is non-empty
    if [ ! -f "$snort_basedir/rules/snort.rules" ]; then
        print_error "snort.rules not found at $snort_basedir/rules/snort.rules. PulledPork may have failed."
        exit 1
    fi
    if [ ! -s "$snort_basedir/rules/snort.rules" ]; then
        print_error "snort.rules at $snort_basedir/rules/snort.rules is empty. PulledPork may have failed."
        exit 1
    fi
    print_good "snort.rules found and non-empty at $snort_basedir/rules/snort.rules"

    # Validate network interfaces
    for iface in "$snort_iface_1" "$snort_iface_2"; do
        if [ -n "$iface" ]; then
            ip link show "$iface" &>> $logfile
            if [ $? -ne 0 ]; then
                print_error "Network interface $iface does not exist. Check full_autosnort.conf."
                exit 1
            fi
            print_good "Network interface $iface exists."
        fi
    done

    # Test snort.conf
    print_status "Testing snort.conf with Snort..."
    $snort_basedir/bin/snort -T -c "$snort_basedir/etc/snort.conf" &>> $logfile
    if [ $? -ne 0 ]; then
        print_error "Snort configuration test failed. Check $snort_basedir/etc/snort.conf for errors."
        print_notification "Run manually: $snort_basedir/bin/snort -T -c $snort_basedir/etc/snort.conf"
        exit 1
    fi
    print_good "Snort configuration test passed."

    # Check Snort binary and libraries
    if [ ! -x "$snort_basedir/bin/snort" ]; then
        print_error "Snort binary not found or not executable at $snort_basedir/bin/snort."
        exit 1
    fi
    ldd "$snort_basedir/bin/snort" &>> $logfile
    if [ $? -ne 0 ]; then
        print_error "Missing libraries for Snort binary. Check ldd $snort_basedir/bin/snort output in $logfile."
        exit 1
    fi
    print_good "Snort binary and libraries verified."
}

########################################
# Postprocessing function for PulledPork to clean up dummy files and set up Snort configs.
function pp_postprocessing()
{
    print_good "Rules processed successfully. Rules located in $snort_basedir/rules."
    print_notification "Pulledpork is located in /usr/src/pulledpork."
    print_notification "By default, Autosnort runs PulledPork with the Security over Connectivity ruleset."
    print_notification "If you want to change how PulledPork operates and/or what rules get enabled/disabled, check out the /usr/src/pulledpork/etc directory and the .conf files contained therein."

    # Clean up dummy files, keeping snort.conf and sid-msg.map.
    for configs in $(ls -1 $snort_basedir/etc/* | egrep -v "snort.conf|sid-msg.map"); do
        rm -rf $configs
    done

    print_status "Moving other Snort configuration files.."
    cd /tmp
    tar -xzvf snortrules-snapshot-*.tar.gz &>> $logfile

    for conffiles in $(ls -1 /tmp/etc/* | egrep -v "snort.conf|sid-msg.map"); do
        cp $conffiles $snort_basedir/etc
    done

    cp /usr/src/$snortver/etc/gen-msg.map $snort_basedir/etc

    # Restore crontab backup to prevent duplicate entries.
    if [ -f /etc/crontab_bkup ]; then
        print_notification "Found /etc/crontab_bkup. Restoring original crontab to prevent duplicate cron entries.."
        cp /etc/crontab_bkup /etc/crontab
        chmod 644 /etc/crontab
        error_check 'crontab restore'
    fi

    print_status "Backing up crontab to /etc/crontab_bkup.."
    cp /etc/crontab /etc/crontab_bkup
    chmod 600 /etc/crontab_bkup
    error_check 'crontab backup'

    print_status "Adding entry to /etc/crontab to run PulledPork Sunday at midnight (once weekly).."
    echo "# This line has been added by Autosnort to run PulledPork for the latest rule updates." >> /etc/crontab
    echo "0 0 * * 7 root /usr/src/pulledpork/pulledpork.pl -c /usr/src/pulledpork/etc/pulledpork.conf" >> /etc/crontab
    print_notification "crontab has been modified. If you want to modify when PulledPork runs to check rule updates, modify /etc/crontab."
}

########################################
# Directory creation function.
function dir_check()
{
    if [ ! -d "$1" ]; then
        print_notification "$1 does not exist. Creating.."
        mkdir -p "$1"
    else
        print_notification "$1 already exists."
    fi
}

########################################
## BEGIN MAIN SCRIPT ##

# Pre-checks: Ensure config file exists and script is run as root.
print_status "Checking for config file.."
execdir=$(pwd)
if [ ! -f "$execdir/full_autosnort.conf" ]; then
    print_error "full_autosnort.conf was NOT found in $execdir. The script relies HEAVILY on this config file. Please make sure it is in the same directory you are executing the autosnort-ubuntu script from!"
    exit 1
else
    print_good "Found config file at $execdir/full_autosnort.conf."
fi

source "$execdir/full_autosnort.conf"

print_status "Checking for root privs.."
if [ "$(whoami)" != "root" ]; then
    print_error "This script must be run with sudo or root privileges."
    exit 1
else
    print_good "We are root."
fi

# Validate oinkcode format (40-character hexadecimal).
if [ -z "$o_code" ] || ! [[ $o_code =~ ^[0-9a-fA-F]{40}$ ]]; then
    print_error "Invalid or missing oinkcode in full_autosnort.conf. It must be a 40-character hexadecimal string."
    print_notification "Obtain a valid oinkcode from https://www.snort.org/users/sign_in and update o_code in $execdir/full_autosnort.conf."
    exit 1
else
    print_good "Oinkcode format validated successfully."
fi

# Suppress package installation messages.
export DEBIAN_FRONTEND=noninteractive

# System updates.
print_status "Performing apt-get update and upgrade (May take a while if this is a fresh install).."
apt-get update &>> $logfile && apt-get -y upgrade &>> $logfile
error_check 'System updates'

########################################
# OS version check.
print_status "OS Version Check.."
release=$(lsb_release -r | awk '{print $2}')
if [[ $release == "18."* || $release == "20."* ]]; then
    print_good "OS is Ubuntu $release. Good to go."
    if [[ $release == "18."* ]]; then
        distro="Ubuntu-18-04"
    else
        distro="Ubuntu-20-04"
    fi
else
    print_notification "This is not Ubuntu 18.x or 20.x (detected $release), this script has NOT been tested on other platforms."
    print_notification "You continue at your own risk! (Please report your successes or failures!)"
    distro="Ubuntu-18-04" # Fallback for non-standard Ubuntu versions
fi

########################################
# Install required packages for Snort, DAQ, and PulledPork.
# Includes libc6-dev, rpcsvc-proto, libtirpc-dev for rpc.h, Perl modules for PulledPork, and gnupg for GPG key management.
if [[ $release == "20."* ]]; then
    print_status "Installing base packages: gcc g++ make libdumbnet-dev libdnet-dev libpcap-dev ethtool build-essential libpcap0.8-dev libpcre3-dev bison flex autoconf libtool perl libnet-ssleay-perl liblzma-dev libluajit-5.1-2 libluajit-5.1-common libluajit-5.1-dev luajit libwww-perl libnghttp2-dev libssl-dev openssl pkg-config zlib1g-dev libc6-dev rpcsvc-proto libtirpc-dev libarchive-zip-perl libcrypt-ssleay-perl liblwp-protocol-https-perl gnupg.."
    
    declare -a packages=(gcc g++ make libdumbnet-dev libdnet-dev libpcap-dev ethtool build-essential libpcap0.8-dev libpcre3-dev bison flex autoconf libtool perl libnet-ssleay-perl liblzma-dev libluajit-5.1-2 libluajit-5.1-common libluajit-5.1-dev luajit libwww-perl libnghttp2-dev libssl-dev openssl pkg-config zlib1g-dev libc6-dev rpcsvc-proto libtirpc-dev libarchive-zip-perl libcrypt-ssleay-perl liblwp-protocol-https-perl gnupg)
    
    install_packages "${packages[@]}"

    # Verify Archive::Tar module.
    print_status "Verifying Archive::Tar module is available.."
    perl -MArchive::Tar -e 'exit 0' &>> $logfile
    error_check "Verification of Archive::Tar module"
else
    print_status "Adjusting /etc/apt/sources.list to utilize universe packages.."
    print_notification "If you are not running Ubuntu 18.04, I highly suggest hitting Ctrl+C to cancel this, or you'll end up adding package sources to your distro that could potentially break a lot of stuff."
    sleep 10
    if [ ! -f /etc/apt/sources.list.bak ]; then
        cp /etc/apt/sources.list /etc/apt/sources.list.bak &>> $logfile
        error_check 'Backup of /etc/apt/sources.list'
    else
        print_notification '/etc/apt/sources.list.bak already exists.'
    fi
    
    # Replace sources.list with Bionic repositories including universe.
    echo -e "deb http://archive.ubuntu.com/ubuntu bionic main universe restricted multiverse\ndeb http://archive.ubuntu.com/ubuntu bionic-security main universe restricted multiverse\ndeb http://archive.ubuntu.com/ubuntu bionic-updates main universe restricted multiverse" > /etc/apt/sources.list
    error_check 'Modification of /etc/apt/sources.list'

    # Ensure gnupg is installed for GPG operations
    print_status "Ensuring gnupg is installed for GPG key management..."
    apt-get install -y gnupg &>> $logfile
    error_check 'Installation of gnupg'

    # Clear apt cache to avoid stale keyring issues
    print_status "Clearing apt cache to ensure clean keyring..."
    rm -rf /var/lib/apt/lists/* &>> $logfile
    error_check 'Clearing apt cache'

    # Import Ubuntu repository GPG keys
    import_gpg_key "3B4FE6ACC0B21F32" "ubuntu-key1"
    import_gpg_key "871920D1991BC93C" "ubuntu-key2"

    # Verify keys are recognized by apt
    verify_apt_keyring "3B4FE6ACC0B21F32"
    verify_apt_keyring "871920D1991BC93C"

    print_notification 'This script assumes a default sources.list and changes all default repos to include universe. If you added third-party sources, re-enter them manually from /etc/apt/sources.list.bak into /etc/apt/sources.list.'
    
    print_status "Installing base packages: gcc g++ make libdumbnet-dev libdnet-dev libpcap-dev ethtool build-essential libpcap0.8-dev libpcre3-dev bison flex autoconf libtool perl libnet-ssleay-perl liblzma-dev libluajit-5.1-2 libluajit-5.1-common libluajit-5.1-dev luajit libwww-perl libnghttp2-dev libssl-dev openssl pkg-config zlib1g-dev libc6-dev rpcsvc-proto libtirpc-dev libarchive-zip-perl libcrypt-ssleay-perl liblwp-protocol-https-perl gnupg.."
    
    declare -a packages=(gcc g++ make libdumbnet-dev libdnet-dev libpcap-dev ethtool build-essential libpcap0.8-dev libpcre3-dev bison flex autoconf libtool perl libnet-ssleay-perl liblzma-dev libluajit-5.1-2 libluajit-5.1-common libluajit-5.1-dev luajit libwww-perl libnghttp2-dev libssl-dev openssl pkg-config zlib1g-dev libc6-dev rpcsvc-proto libtirpc-dev libarchive-zip-perl libcrypt-ssleay-perl liblwp-protocol-https-perl gnupg)
    
    install_packages "${packages[@]}"

    # Verify Archive::Tar module.
    print_status "Verifying Archive::Tar module is available.."
    perl -MArchive::Tar -e 'exit 0' &>> $logfile
    error_check "Verification of Archive::Tar module"
fi

# Create symlink for libdumbnet.h to dnet.h for barnyard2 compatibility.
if [ ! -h /usr/include/dnet.h ]; then
    print_status "Creating symlink for libdumbnet.h to dnet.h.."
    ln -s /usr/include/dumbnet.h /usr/include/dnet.h
fi

########################################
# Hardcode Snort and DAQ versions.
snorttar="snort-2.9.20.tar.gz"
snortver="snort-2.9.20"
daqtar="daq-2.0.7.tar.gz"
daqver="daq-2.0.7"

# Define snort.conf URLs for primary and fallback
primary_conf_url="https://www.snort.org/documents/snort-209200-conf"
fallback_conf_url="https://www.snort.org/documents/snort-209190-conf"

cd /usr/src

########################################
# Install DAQ libraries.
print_status "Acquiring and unpacking $daqver to /usr/src.."
print_notification "Attempting to download DAQ from: https://www.snort.org/downloads/snort/$daqtar"

for attempt in {1..3}; do
    print_status "Download attempt $attempt for $daqtar..."
    wget --tries=2 --timeout=10 https://www.snort.org/downloads/snort/$daqtar -O $daqtar &>> $logfile
    if [ $? -eq 0 ]; then
        print_good "Successfully downloaded $daqtar."
        break
    else
        print_notification "Attempt $attempt failed for $daqtar."
        if [ $attempt -eq 3 ]; then
            print_error "Failed to download $daqtar after 3 attempts. Check $logfile for details."
            print_notification "Possible reasons: Network issues, unavailable file, or snort.org server restrictions."
            print_notification "Manual workaround: Download https://www.snort.org/downloads/snort/$daqtar, place it in /usr/src as $daqtar, then re-run the script."
            exit 1
        fi
        sleep 5
    fi
done

tar -xzvf $daqtar &>> $logfile
error_check 'Untar of DAQ'

cd $daqver

print_status "Configuring, making, compiling, and linking DAQ libraries. This will take a moment or two.."
autoreconf -f -i &>> $logfile
error_check 'Autoreconf DAQ'

./configure &>> $logfile
error_check 'Configure DAQ'

print_status "Compiling DAQ with verbose output..."
make V=1 &>> $logfile
error_check 'Make DAQ'

make install &>> $logfile
error_check 'Installation of DAQ libraries'

# Ensure DAQ pkg-config file.
if [ -f libdaq.pc ]; then
    print_status "Installing DAQ pkg-config file..."
    mkdir -p /usr/local/lib/pkgconfig
    cp libdaq.pc /usr/local/lib/pkgconfig/
    error_check 'Installation of libdaq.pc'
else
    print_notification "libdaq.pc not found in DAQ source directory. Generating manually..."
    cat > libdaq.pc << EOL
prefix=/usr/local
exec_prefix=\${prefix}
libdir=\${exec_prefix}/lib
includedir=\${prefix}/include

Name: libdaq
Description: Data Acquisition library for Snort
Version: 2.0.7
Libs: -L\${libdir} -ldaq_static
Cflags: -I\${includedir}
EOL
    mkdir -p /usr/local/lib/pkgconfig
    mv libdaq.pc /usr/local/lib/pkgconfig/
    error_check 'Generation and installation of libdaq.pc'
fi

# Symlink libsfbpf.so.0.
if [ ! -h /usr/lib/libsfbpf.so.0 ]; then
    print_status "Creating symlink for libsfbpf.so.0 on default ld library path.."
    ln -s /usr/local/lib/libsfbpf.so.0 /usr/lib/libsfbpf.so.0
fi

# Update linker cache.
ldconfig &>> $logfile
error_check 'Update linker cache'

cd /usr/src

########################################
# Install Snort.
print_status "Acquiring and unpacking $snortver to /usr/src.."
print_notification "Attempting to download Snort from: https://www.snort.org/downloads/snort/$snorttar"

for attempt in {1..3}; do
    print_status "Download attempt $attempt for $snorttar..."
    wget --tries=2 --timeout=10 https://www.snort.org/downloads/snort/$snorttar -O $snorttar &>> $logfile
    if [ $? -eq 0 ]; then
        print_good "Successfully downloaded $snorttar."
        break
    else
        print_notification "Attempt $attempt failed for $snorttar."
        if [ $attempt -eq 3 ]; then
            print_error "Failed to download $snorttar after 3 attempts. Check $logfile for details."
            print_notification "Possible reasons: Network issues, unavailable file, or snort.org server restrictions."
            print_notification "Manual workaround: Download https://www.snort.org/downloads/snort/$snorttar, place it in /usr/src as $snorttar, then re-run the script."
            exit 1
        fi
        sleep 5
    fi
done

tar -xzvf $snorttar &>> $logfile
error_check 'Untar of Snort'

# Verify sp_rpc_check.c exists to ensure tarball integrity.
if [ ! -f /usr/src/$snortver/src/detection-plugins/sp_rpc_check.c ]; then
    print_error "sp_rpc_check.c not found in /usr/src/$snortver/src/detection-plugins. The Snort tarball may be corrupted."
    print_notification "Please re-download https://www.snort.org/downloads/snort/$snorttar and re-run the script."
    exit 1
fi

dir_check $snort_basedir
dir_check $snort_basedir/lib

cd $snortver

print_status "Checking build environment before compiling Snort..."
# Check disk space.
df -h /usr/src &>> $logfile
if [ $? -ne 0 ]; then
    print_error "Failed to check disk space. Ensure /usr/src has sufficient space."
    exit 1
fi
# Check DAQ installation.
if [ ! -f /usr/local/lib/libdaq.a ] || [ ! -f /usr/local/include/daq.h ]; then
    print_error "DAQ library or headers not found at /usr/local/lib/libdaq.a or /usr/local/include/daq.h. Ensure DAQ was installed correctly."
    exit 1
fi
# Check DAQ and libpcap pkg-config files.
if [ ! -f /usr/local/lib/pkgconfig/libdaq.pc ]; then
    print_error "DAQ pkg-config file not found at /usr/local/lib/pkgconfig/libdaq.pc. Ensure DAQ was installed correctly."
    exit 1
fi
if [ ! -f /usr/lib/pkgconfig/libpcap.pc ] && [ ! -f /usr/lib/x86_64-linux-gnu/pkgconfig/libpcap.pc ]; then
    print_error "libpcap pkg-config file not found. Ensure libpcap-dev is installed."
    exit 1
fi
# Check compiler and tools.
gcc --version &>> $logfile
make --version &>> $logfile
if [ $? -ne 0 ]; then
    print_error "Compiler or make tool missing. Install gcc, g++, and make."
    exit 1
fi
# Set library paths.
export LD_LIBRARY_PATH=/usr/local/lib:/usr/lib:/usr/lib/x86_64-linux-gnu:$LD_LIBRARY_PATH
export PKG_CONFIG_PATH=/usr/local/lib/pkgconfig:/usr/lib/pkgconfig:/usr/lib/x86_64-linux-gnu/pkgconfig:$PKG_CONFIG_PATH
print_notification "Library paths set: LD_LIBRARY_PATH=$LD_LIBRARY_PATH"
print_notification "PKG_CONFIG_PATH=$PKG_CONFIG_PATH"
# Verify pkg-config for libraries.
pkg-config --libs --cflags libdaq libpcap &>> $logfile
if [ $? -ne 0 ]; then
    print_error "pkg-config failed to find libdaq or libpcap. Ensure libraries are installed and paths are correct."
    print_notification "Try manually installing libpcap-dev and re-running DAQ installation."
    exit 1
fi
# Ensure rpc.h is available for sp_rpc_check.c.
print_status "Ensuring rpc.h is available for sp_rpc_check.c..."
# Check if rpc.h already exists in /usr/include/rpc.
if [ -f /usr/include/rpc/rpc.h ]; then
    print_good "rpc.h found at /usr/include/rpc/rpc.h"
    extra_cflags=""
else
    # Search for rpc.h system-wide.
    rpc_h_path=$(find /usr/include -name rpc.h 2>/dev/null | grep -E 'rpc/rpc.h$|tirpc/rpc/rpc.h$' | head -1)
    if [ -z "$rpc_h_path" ]; then
        print_notification "rpc.h not found. Attempting to reinstall libc6-dev, rpcsvc-proto, and libtirpc-dev..."
        apt-get install -y libc6-dev rpcsvc-proto libtirpc-dev &>> $logfile
        error_check 'Reinstallation of libc6-dev, rpcsvc-proto, and libtirpc-dev'
        rpc_h_path=$(find /usr/include -name rpc.h 2>/dev/null | grep -E 'rpc/rpc.h$|tirpc/rpc/rpc.h$' | head -1)
    fi
    if [ -n "$rpc_h_path" ]; then
        print_good "rpc.h found at $rpc_h_path"
        # Create /usr/include/rpc if it doesn't exist.
        mkdir -p /usr/include/rpc &>> $logfile
        # Copy or symlink rpc.h to /usr/include/rpc/rpc.h.
        if [ ! -f /usr/include/rpc/rpc.h ]; then
            print_notification "Copying $rpc_h_path to /usr/include/rpc/rpc.h..."
            cp "$rpc_h_path" /usr/include/rpc/rpc.h &>> $logfile
            if [ $? -eq 0 ]; then
                print_good "Successfully copied rpc.h to /usr/include/rpc/rpc.h"
                extra_cflags=""
            else
                print_notification "Copy failed. Creating symlink instead..."
                ln -sf "$rpc_h_path" /usr/include/rpc/rpc.h &>> $logfile
                error_check "Symlink of rpc.h to /usr/include/rpc/rpc.h"
                extra_cflags=""
            fi
        fi
    else
        print_error "rpc.h not found after reinstalling libc6-dev, rpcsvc-proto, and libtirpc-dev."
        print_notification "Please manually verify package installation and locate rpc.h."
        print_notification "Run: find /usr/include -name rpc.h"
        print_notification "You may need to update /etc/apt/sources.list or fix package issues."
        exit 1
    fi
fi
# Add fallback CFLAGS for non-standard paths.
extra_cflags="$extra_cflags -I/usr/include/tirpc -I/usr/include/x86_64-linux-gnu"
print_good "Build environment checks passed."

print_status "Configuring Snort (options --prefix=$snort_basedir and --enable-sourcefire), making and installing. This will take a moment or two."
./configure --prefix=$snort_basedir --libdir=$snort_basedir/lib --enable-sourcefire \
    CFLAGS="-I/usr/include -I/usr/local/include $extra_cflags" LDFLAGS="-L/usr/local/lib -L/usr/lib" &>> $logfile
error_check 'Configure Snort'

print_status "Compiling Snort with verbose output (this may take a while)..."
make V=1 &>> $logfile
error_check 'Make Snort'

make install &>> $logfile
error_check 'Installation of Snort'

dir_check /var/log/snort

print_status "Checking for Snort user and group.."
getent passwd snort &>> $logfile
if [ $? -eq 0 ]; then
    print_notification "Snort user exists. Verifying group exists.."
    id -g snort &>> $logfile
    if [ $? -eq 0 ]; then
        print_notification "Snort group exists."
    else
        print_notification "Snort group does not exist. Creating.."
        groupadd snort
        usermod -G snort snort
    fi
else
    print_status "Creating Snort user and group.."
    groupadd snort
    useradd -g snort snort -s /bin/false
fi

print_status "Tightening permissions to /var/log/snort.."
chmod 770 /var/log/snort
chown snort:snort /var/log/snort

# Set permissions for Snort directories
print_status "Setting permissions for Snort directories..."
chown -R snort:snort $snort_basedir/etc $snort_basedir/rules $snort_basedir/so_rules $snort_basedir/preproc_rules $snort_basedir/snort_dynamicrules &>> $logfile
chmod -R 660 $snort_basedir/etc/* $snort_basedir/rules/* $snort_basedir/so_rules/* $snort_basedir/preproc_rules/* $snort_basedir/snort_dynamicrules/* &>> $logfile
error_check "Setting permissions for Snort directories"

########################################
# Configure Snort directories and snort.conf.
dir_check $snort_basedir/etc
dir_check $snort_basedir/so_rules
dir_check $snort_basedir/rules
