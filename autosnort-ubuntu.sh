#!/bin/bash
# Autosnort script for Ubuntu 18.04+
# Please note that this version of the script is specifically made available for students of Building Virtual Labs training on networkdefense.io, as well as the book, Building Virtual Machine Labs: A Hands-On Guide
# This script configures Snort and PulledPork with enhanced logging and debugging for rule downloads, targeting PulledPork 0.8.0
# Modified to enhance verification of Perl modules (libwww-perl, libarchive-zip-perl, libcrypt-ssleay-perl, liblwp-protocol-https-perl)
# PulledPork section reverted to original code from autosnort-ubuntu-AVATAR-orig.sh for version 0.8.0
# Updated GPG key import with retries, multiple keyservers, and fallback for apt keyring
# Updated snort.conf download to use hardcoded URL with retries
# Added validation checks for snort.conf, rules, and interfaces to prevent service startup failures

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
    
    print_status "Installing base packages: gcc g++ make libdumbnet-dev libdnet-dev libpcap-dev ethtool build-essential libpcap0.8-dev libpcre3-dev bison flex autoconf libtool perl libnet-ssleay-perl liblzma-dev libluajit-5.1-2 libluajit-5.1-common libluajit-5.1-dev luajit libwww-perl libnghttp2-dev libssl-dev openssl pkg-config zlib1g-dev libc6-dev rpcsvc-proto libtirpc-dev libarchive-zip-perl libcrypt-ssleay-perl liblwp-protocol-https-perl gnupg
