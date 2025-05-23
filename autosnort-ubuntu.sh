#!/bin/bash
# Autosnort script for Ubuntu 18.04+
# Please note that this version of the script is specifically made available for students of Building Virtual Labs training on networkdefense.io, as well as the book, Building Virtual Machine Labs: A Hands-On Guide
# This script configures Snort and PulledPork with enhanced logging and debugging for rule downloads, targeting PulledPork 0.8.0
# Modified to enhance verification of Perl modules (libwww-perl, libarchive-zip-perl, libcrypt-ssleay-perl, liblwp-protocol-https-perl)
# PulledPork section reverted to original code from autosnort-ubuntu-AVATAR-orig.sh for version 0.8.0
# Updated GPG key import with retries, multiple keyservers, and fallback to ensure keys are trusted by apt

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
# New function to import GPG keys with retries and multiple keyservers.
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
# New function to verify and ensure apt recognizes keys.
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
# Download snort.conf from snort.org.
print_status "Checking latest snort.conf versions via snort.org..."
cd /tmp
wget https://www.snort.org/documents -O /tmp/snort_conf &> $logfile
error_check 'Download of snort.conf examples page'

# Hardcode Snort and DAQ versions.
snorttar="snort-2.9.20.tar.gz"
snortver="snort-2.9.20"
daqtar="daq-2.0.7.tar.gz"
daqver="daq-2.0.7"

# Regex for snort.conf download choices.
choice1conf=$(egrep -o "snort-20.*-conf" /tmp/snort_conf | sort -ru | head -1)
choice2conf=$(egrep -o "snort-20.*-conf" /tmp/snort_conf | sort -ru | head -2 | tail -1)
rm /tmp/snort_conf
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

########################################
# Configure Snort directories and snort.conf.
dir_check $snort_basedir/etc
dir_check $snort_basedir/so_rules
dir_check $snort_basedir/rules
dir_check $snort_basedir/preproc_rules
dir_check $snort_basedir/snort_dynamicrules
dir_check $snort_basedir/rules/iplists
touch $snort_basedir/rules/iplists/IPRVersion.dat

print_status "Attempting to download .conf file for $snortver.."
wget https://www.snort.org/documents/$choice1conf -O $snort_basedir/etc/snort.conf --no-check-certificate &>> $logfile
if [ $? != 0 ]; then
    print_error "Attempt to download $snortver conf file from snort.org failed. Attempting to download $choice2conf.."
    wget https://www.snort.org/documents/$choice2conf -O $snort_basedir/etc/snort.conf --no-check-certificate &>> $logfile
    error_check 'Download of secondary snort.conf'
else
    print_good "Successfully downloaded .conf file for $snortver."
fi

print_status "ldconfig processing and creation of whitelist/blocklist.rules files taking place."
touch $snort_basedir/rules/white_list.rules
touch $snort_basedir/rules/black_list.rules
ldconfig

print_status "Modifying snort.conf -- specifying unified 2 output, SO whitelist/blocklist, and standard rule locations.."
sed -i "s#dynamicpreprocessor directory /usr/local/lib/snort_dynamicpreprocessor#dynamicpreprocessor directory $snort_basedir/lib/snort_dynamicpreprocessor#" $snort_basedir/etc/snort.conf
sed -i "s#dynamicengine /usr/local/lib/snort_dynamicengine/libsf_engine.so#dynamicengine $snort_basedir/lib/snort_dynamicengine/libsf_engine.so#" $snort_basedir/etc/snort.conf
sed -i "s#dynamicdetection directory /usr/local/lib/snort_dynamicrules#dynamicdetection directory $snort_basedir/snort_dynamicrules#" $snort_basedir/etc/snort.conf
sed -i "s/# output unified2: filename merged.log, limit 128, nostamp, mpls_event_types, vlan_event_types/output unified2: filename snort.u2, limit 128/" $snort_basedir/etc/snort.conf
sed -i "s#var WHITE_LIST_PATH ../rules#var WHITE_LIST_PATH $snort_basedir/rules#" $snort_basedir/etc/snort.conf
sed -i "s#var BLACK_LIST_PATH ../rules#var BLACK_LIST_PATH $snort_basedir/rules#" $snort_basedir/etc/snort.conf
sed -i "s/include \$RULE\_PATH/#include \$RULE\_PATH/" $snort_basedir/etc/snort.conf
echo "# unified snort.rules entry" >> $snort_basedir/etc/snort.conf
echo "include \$RULE_PATH/snort.rules" >> $snort_basedir/etc/snort.conf

# Create dummy files for Snort to generate SO rule stubs.
touch $snort_basedir/etc/reference.config
touch $snort_basedir/etc/classification.config
cp /usr/src/$snortver/etc/unicode.map $snort_basedir/etc/unicode.map
touch $snort_basedir/etc/threshold.conf
touch $snort_basedir/rules/snort.rules

print_good "snort.conf configured. Location: $snort_basedir/etc/snort.conf"

# Install PulledPork.
cd /usr/src
if [ -d /usr/src/pulledpork ]; then
    print_notification "Removing existing PulledPork directory to ensure fresh clone.."
    rm -rf /usr/src/pulledpork
fi

# Verify Perl and required modules.
print_status "Verifying Perl and required modules for PulledPork.."
which perl &>> $logfile
if [ $? -ne 0 ]; then
    print_error "Perl not found. Install perl package with: sudo apt-get install perl"
    exit 1
fi

# Define required Perl modules and their corresponding packages
declare -A module_to_package=(
    ["LWP::UserAgent"]="libwww-perl"
    ["Archive::Tar"]="libarchive-zip-perl"
    ["Crypt::SSLeay"]="libcrypt-ssleay-perl"
    ["LWP::Protocol::https"]="liblwp-protocol-https-perl"
)

# Check each module and attempt reinstallation if missing
for module in "${!module_to_package[@]}"; do
    print_status "Checking Perl module $module..."
    perl -M"$module" -e 'exit 0' &>> $logfile
    if [ $? -ne 0 ]; then
        print_notification "Perl module $module not found. Attempting to install ${module_to_package[$module]}..."
        apt-get install -y ${module_to_package[$module]} &>> $logfile
        if [ $? -ne 0 ]; then
            print_error "Failed to install ${module_to_package[$module]}. Install manually with: sudo apt-get install ${module_to_package[$module]}"
            exit 1
        fi
        # Re-verify module after installation
        perl -M"$module" -e 'exit 0' &>> $logfile
        if [ $? -ne 0 ]; then
            print_error "Perl module $module still not found after installation attempt."
            print_notification "Try installing via CPAN: sudo cpan install $module"
            exit 1
        else
            print_good "Perl module $module installed and verified."
        fi
    else
        print_good "Perl module $module is available."
    fi
done

print_status "Acquiring Pulled Pork.."
git clone https://github.com/shirkdog/pulledpork.git &>> $logfile
error_check 'Download of pulledpork'

print_good "Pulledpork successfully installed to /usr/src."

print_status "Generating pulledpork.conf."
cd pulledpork/etc

# Create a copy of the original conf file (in case the user needs it).
cp pulledpork.conf pulledpork.conf.orig &>> $logfile
error_check 'Backup of pulledpork.conf'

# Adjust Snort version for PulledPork (expects 4-digit version, e.g., 2.9.20.0).
snortverperiods=$(echo $snortver | fgrep -o . | wc -l)
if [ $snortverperiods -eq 2 ]; then
    ppsnortver=$snortver.0
else
    ppsnortver=$snortver
fi

# Generate pulledpork.conf compatible with PulledPork 0.8.0.
echo "rule_url=https://www.snort.org/reg-rules/|snortrules-snapshot.tar.gz|$o_code" > pulledpork.tmp
echo "rule_url=https://snort.org/downloads/community/|opensource.gz|Opensource" >> pulledpork.tmp
echo "rule_url=https://snort.org/downloads/community/|community-rules.tar.gz|Community" >> pulledpork.tmp
echo "rule_url=https://snort.org/downloads/ip-block-list|IPBLOCKLIST|open" >> pulledpork.tmp
echo "ignore=deleted.rules,experimental.rules,local.rules" >> pulledpork.tmp
echo "temp_path=/tmp" >> pulledpork.tmp
echo "rule_path=$snort_basedir/rules/snort.rules" >> pulledpork.tmp
echo "local_rules=$snort_basedir/rules/local.rules" >> pulledpork.tmp
echo "sid_msg=$snort_basedir/etc/sid-msg.map" >> pulledpork.tmp
echo "sid_msg_version=1" >> pulledpork.tmp
echo "sid_changelog=/var/log/sid_changes.log" >> pulledpork.tmp
echo "sorule_path=$snort_basedir/snort_dynamicrules/" >> pulledpork.tmp
echo "snort_path=$snort_basedir/bin/snort" >> pulledpork.tmp
echo "snort_version=$(echo $ppsnortver | cut -d'-' -f2)" >> pulledpork.tmp
echo "distro=$distro" >> pulledpork.tmp
echo "config_path=$snort_basedir/etc/snort.conf" >> pulledpork.tmp
echo "black_list=$snort_basedir/rules/black_list.rules" >> pulledpork.tmp
echo "IPRVersion=$snort_basedir/rules/iplists" >> pulledpork.tmp
echo "ips_policy=security" >> pulledpork.tmp
echo "version=0.8.0" >> pulledpork.tmp
cp pulledpork.tmp pulledpork.conf &>> $logfile
error_check 'Generation of pulledpork.conf'

# Verify pulledpork.conf existence, readability, and permissions.
if [ ! -f /usr/src/pulledpork/etc/pulledpork.conf ]; then
    print_error "pulledpork.conf not found at /usr/src/pulledpork/etc/pulledpork.conf."
    exit 1
fi
if [ ! -r /usr/src/pulledpork/etc/pulledpork.conf ]; then
    print_error "pulledpork.conf at /usr/src/pulledpork/etc/pulledpork.conf is not readable."
    exit 1
fi
chmod 644 /usr/src/pulledpork/etc/pulledpork.conf &>> $logfile
error_check 'Setting permissions for pulledpork.conf'

# Run PulledPork.
cd /usr/src/pulledpork
print_status "Attempting to download rules for $ppsnortver.."
print_notification "If this hangs, please make sure you set the HTTP_PROXY, http_proxy, HTTPS_PROXY, and https_proxy variables as required!"
perl pulledpork.pl -W -vv -P -c /usr/src/pulledpork/etc/pulledpork.conf &>> $logfile
if [ $? == 0 ]; then
    pp_postprocessing
else
    print_error "Rule download for $ppsnortver has failed. Check $logfile, Troubleshoot your connectivity issues to snort.org, and ensure you wait a minimum of 15 minutes before trying again."
    exit 1
fi

########################################
# Disable network offloading options.
print_notification "Disabling offloading options on the sniffing interfaces.."
ethtool -K $snort_iface_1 rx off &>> $logfile
ethtool -K $snort_iface_1 tx off &>> $logfile
ethtool -K $snort_iface_1 sg off &>> $logfile
ethtool -K $snort_iface_1 tso off &>> $logfile
ethtool -K $snort_iface_1 ufo off &>> $logfile
ethtool -K $snort_iface_1 gso off &>> $logfile
ethtool -K $snort_iface_1 gro off &>> $logfile
ethtool -K $snort_iface_1 lro off &>> $logfile
ethtool -K $snort_iface_2 rx off &>> $logfile
ethtool -K $snort_iface_2 tx off &>> $logfile
ethtool -K $snort_iface_2 sg off &>> $logfile
ethtool -K $snort_iface_2 tso off &>> $logfile
ethtool -K $snort_iface_2 ufo off &>> $logfile
ethtool -K $snort_iface_2 gso off &>> $logfile
ethtool -K $snort_iface_2 gro off &>> $logfile
ethtool -K $snort_iface_2 lro off &>> $logfile

########################################
# Install systemd service.
cd "$execdir"
if [ -f /etc/systemd/system/snortd.service ]; then
    print_notification "Snortd init script already installed."
else
    if [ ! -f "$execdir/snortd.service" ]; then
        print_error "Unable to find $execdir/snortd.service. Please ensure the snortd.service file is there and try again."
        exit 1
    else
        print_good "Found snortd systemd service script. Configuring.."
    fi
    
    cp snortd.service snortd_2 &>> $logfile
    sed -i "s#snort_basedir#$snort_basedir#g" snortd_2
    sed -i "s#snort_iface1#$snort_iface_1#g" snortd_2
    sed -i "s#snort_iface2#$snort_iface_2#g" snortd_2
    cp snortd_2 /etc/systemd/system/snortd.service &>> $logfile
    chown root:root /etc/systemd/system/snortd.service &>> $logfile
    chmod 700 /etc/systemd/system/snortd.service &>> $logfile
    systemctl daemon-reload &>> $logfile
    error_check 'snortd.service installation'
    print_notification "Location: /etc/systemd/system/snortd.service"
    systemctl enable snortd.service &>> $logfile
    error_check 'snortd.service enable'
    rm -rf snortd_2 &>> $logfile
fi

########################################
print_status "Rebooting now.."
init 6
print_notification "The log file for Autosnort is located at: $logfile"
print_good "We're all done here. Have a nice day."
exit 0
