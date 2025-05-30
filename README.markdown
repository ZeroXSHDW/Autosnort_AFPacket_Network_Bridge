# Autosnort for Ubuntu with AFPACKET Bridging

This repository provides a script to install and configure Snort as an Intrusion Prevention System (IPS) with AFPACKET bridging on Ubuntu 18.04 or 20.04, specifically designed for cybersecurity labs as outlined in *Building Virtual Machine Labs: A Hands-On Guide* by Tony Robinson (ISBN-13: 978-1546932635). The script creates a network fail-safe killswitch to prevent malware exposure to the host system, critical for safe malware analysis and penetration testing labs.

The original script, `autosnort-ubuntu-AVATAR.sh` from [da667/Autosnort](https://github.com/da667/Autosnort/tree/master/Autosnort-Ubuntu/AVATAR), is included but is outdated and broken due to changes in package repositories, Snort versions, and dependency management. The updated script, `ZeroXSHDW_autosnort-ubuntu.sh`, fixes these issues, ensuring reliable installation of Snort with AFPACKET bridging.

## Overview

This script automates the installation of Snort, Data Acquisition (DAQ) libraries, and PulledPork for rule management, configuring Snort in inline mode using AFPACKET bridging between two network interfaces (`eth1` and `eth2` by default). This setup acts as a network bridge, inspecting and potentially dropping malicious traffic, thus protecting the host and external networks from malware or exploits within the lab environment.

Key features:
- Installs Snort 2.9.20 and DAQ 2.0.7 with dependencies.
- Configures AFPACKET bridging for inline IPS mode.
- Downloads and manages Snort rules via PulledPork 0.8.0.
- Includes enhanced logging, GPG key management, and configuration validation.
- Sets up a systemd service (`snortd.service`) for persistence.
- Implements a weekly cron job for rule updates.

## Repository Contents

- `ZeroXSHDW_autosnort-ubuntu.sh`: Enhanced script for installing and configuring Snort with AFPACKET bridging.
- `autosnort-ubuntu-AVATAR.sh`: Original script from da667/Autosnort (included for reference, not recommended for use).
- `full_autosnort.conf`: Configuration file for specifying Snort installation directory, interfaces, and Oinkcode.
- `snortd.service`: Systemd service file for Snort.
- `README.md`: This file, providing setup instructions and references.

## Prerequisites

### Hardware Requirements
- **Minimum**: Quad-core CPU with virtualization support, 16–24 GB RAM, 500–750 GB SSD.
- **Recommended**: 6–8 core CPU, 32 GB RAM, 1 TB SSD.
- **Network Interfaces**: At least three network interfaces for the IPS VM (one for management, two for bridging).

### Software Requirements
- **Operating System**: Ubuntu Server 18.04 or 20.04 LTS.
- **Hypervisor**: VirtualBox, Hyper-V, VMware Workstation Pro, VMware Fusion Pro, or VMware vSphere (ESXi).
- **Snort Oinkcode**: Register at [snort.org](https://www.snort.org/users/sign_in) to obtain a 40-character Oinkcode.
- **Network Configuration**: As per *Building Virtual Machine Labs*:
  - Bridged/External Network: For internet access.
  - Management Network: e.g., 172.16.1.0/24.
  - IPS 1 Network: e.g., 172.16.2.0/24 (e.g., Kali Linux VM).
  - IPS 2 Network: e.g., 172.16.3.0/24 (e.g., Metasploitable 2 VM).

### Knowledge Requirements
- Basic TCP/IP networking (IP addressing, subnetting, OSI model).
- Familiarity with Linux CLI (`ip`, `systemctl`, `nano`).
- Understanding of virtualization and network segmentation.

## Setup Instructions

### Step 1: Prepare the IPS VM
1. **Create the VM**:
   - Use your chosen hypervisor to create an Ubuntu Server 18.04/20.04 VM.
   - Allocate: 2 GB RAM, 20 GB disk, 2 vCPUs, 3 network interfaces:
     - Interface 1: Management (e.g., 172.16.1.4/24).
     - Interface 2: IPS 1 (e.g., `eth1`, connected to 172.16.2.0/24).
     - Interface 3: IPS 2 (e.g., `eth2`, connected to 172.16.3.0/24).
   - Refer to *Building Virtual Machine Labs* (Chapters 9–13) for hypervisor-specific setup.

2. **Install Ubuntu**:
   - Follow standard Ubuntu Server installation (e.g., Chapter 9.23 for Hyper-V).
   - Ensure network interfaces are correctly mapped to `eth1` and `eth2` for bridging.

3. **Network Configuration**:
   - Configure the management interface with a static IP (e.g., 172.16.1.4/24, gateway 172.16.1.1, DNS 172.16.1.1).
   - Verify `eth1` and `eth2` are present:
     ```bash
     ip link show
     ```
   - Refer to Chapter 6 for network segmentation details.

### Step 2: Configure full_autosnort.conf
1. **Create the Configuration File**:
   - Copy `full_autosnort.conf` to the same directory as `ZeroXSHDW_autosnort-ubuntu.sh`.
   - Edit `full_autosnort.conf` with a valid Oinkcode and interface names:
     ```bash
     o_code="your_40_char_oinkcode"  # Obtain from snort.org
     snort_basedir="/opt/snort"
     snort_iface_1="eth1"  # IPS 1 network
     snort_iface_2="eth2"  # IPS 2 network
     ```
   - Example command to edit:
     ```bash
     nano full_autosnort.conf
     ```
   - Secure the file after editing:
     ```bash
     chmod 600 full_autosnort.conf
     ```

2. **Obtain an Oinkcode**:
   - Register at [snort.org](https://www.snort.org/users/sign_in).
   - Log in, navigate to your account settings, and copy the 40-character Oinkcode.
   - Paste it into `o_code` in `full_autosnort.conf`.

### Step 3: Run the Script
1. **Copy Files to the VM**:
   - Transfer `ZeroXSHDW_autosnort-ubuntu.sh`, `full_autosnort.conf`, and `snortd.service` to the IPS VM (e.g., via SCP):
     ```bash
     scp ZeroXSHDW_autosnort-ubuntu.sh full_autosnort.conf snortd.service user@172.16.1.4:/home/user
     ```
   - Log into the VM:
     ```bash
     ssh user@172.16.1.4
     ```

2. **Execute the Script**:
   - Ensure all files are in the same directory:
     ```bash
     ls
     # Should show: ZeroXSHDW_autosnort-ubuntu.sh full_autosnort.conf snortd.service
     ```
   - Run the script as root:
     ```bash
     sudo bash ZeroXSHDW_autosnort-ubuntu.sh
     ```
   - The script will:
     - Install dependencies (e.g., libdumbnet-dev, libpcap-dev, Perl modules).
     - Download and compile Snort 2.9.20 and DAQ 2.0.7.
     - Configure Snort with unified2 output and AFPACKET bridging.
     - Install PulledPork and download rules using the provided Oinkcode.
     - Set up `snortd.service` for persistence.
     - Schedule weekly rule updates via cron.
     - Disable network offloading on `eth1` and `eth2`.
     - Reboot the system to start Snort.

3. **Verify Installation**:
   - After reboot, check Snort status:
     ```bash
     systemctl status snortd.service
     ```
   - Verify Snort is running:
     ```bash
     ps -ef | grep snort
     ```
   - Check logs for errors:
     ```bash
     cat /var/log/autosnort_install.log
     ```
   - Ensure rules are present:
     ```bash
     ls -l /opt/snort/rules/snort.rules
     ```

### Step 4: Test AFPACKET Bridging
1. **Set Up Test VMs**:
   - Configure a Kali Linux VM on the IPS 1 network (e.g., 172.16.2.2/24).
   - Configure a Metasploitable 2 VM on the IPS 2 network (e.g., 172.16.3.2/24).
   - Ensure pfSense routes traffic between networks (see Chapter 14).

2. **Test Connectivity**:
   - From the Kali VM, ping the Metasploitable 2 VM:
     ```bash
     ping 172.16.3.2
     ```
   - Traffic should pass through the IPS VM’s AFPACKET bridge.

3. **Verify Snort Alerts**:
   - Run a test attack (e.g., “Hail Mary” via Armitage on Kali, Chapter 20.8).
   - Check Snort logs:
     ```bash
     ls -l /var/log/snort
     ```
   - If integrated with Splunk, query alerts (Chapter 20.9):
     ```splunk
     index=main sourcetype=snort_json | table signature.msg | dedup signature.msg
     ```

### Step 5: Host Network Security (Windows)
To prevent network traffic fallout due to lab activities, secure the host system as recommended in *Building Virtual Machine Labs* (Chapter 15):
- **Disable Unnecessary Protocols**:
  - Unbind File and Printer Sharing, Client for Microsoft Networks, and QoS Packet Scheduler from the network adapter used for bridging (e.g., Bridged/External Network).
  - Command (Windows PowerShell as Administrator):
    ```powershell
    Disable-NetAdapterBinding -Name "Ethernet" -ComponentID ms_msclient,ms_server,ms_pacer
    ```
- **Configure Windows Firewall**:
  - Block all inbound connections to the host except for management protocols (e.g., SSH, RDP).
  - Example rule (PowerShell):
    ```powershell
    New-NetFirewallRule -Name "BlockInbound" -Direction Inbound -Action Block -Enabled True
    New-NetFirewallRule -Name "AllowSSH" -Direction Inbound -Protocol TCP -LocalPort 22 -Action Allow
    ```
- **Static Routes**:
  - Add routes to access lab networks (e.g., 172.16.1.0/24, 172.16.2.0/24, 172.16.3.0/24) via the pfSense WAN interface (Chapter 17.1–17.22).
    ```powershell
    route add 172.16.1.0 MASK 255.255.255.0 192.168.1.1 -p
    ```
- **Use a Jump Box** (for bare-metal hypervisors like ESXi):
  - Set up a Raspberry Pi or VM with SSH access (Chapter 18.6–18.11).
  - Configure SSH tunnels (Chapter 18.17–18.28).

## Differences from Original Script
The original `autosnort-ubuntu-AVATAR.sh` (from da667/Autosnort) is broken due to:
- Outdated package repositories (e.g., Ubuntu 16.04 support removed).
- Deprecated URLs for Snort rules and configurations.
- Missing dependencies (e.g., libluajit, Perl modules).
- Lack of robust error handling and logging.

The `ZeroXSHDW_autosnort-ubuntu.sh` script addresses these issues:
- **Hardcoded Versions**: Uses Snort 2.9.20 and DAQ 2.0.7 for stability.
- **Enhanced GPG Key Management**: Imports Ubuntu repository keys with retries across multiple keyservers.
- **Perl Module Verification**: Ensures `LWP::UserAgent`, `Archive::Tar`, `Crypt::SSLeay`, and `LWP::Protocol::https` are installed.
- **Robust Downloads**: Implements retries for Snort, DAQ, and snort.conf downloads with fallback to tarball snort.conf.
- **Configuration Validation**: Checks `snort.conf`, `snort.rules`, and network interfaces before enabling the service.
- **Permission Fixes**: Correctly sets ownership and permissions for Snort directories and files.
- **Verbose Logging**: Logs all actions to `/var/log/autosnort_install.log` with timestamps.
- **Systemd Enhancements**: Adds verbose output and logging to `snortd.service`.

## Troubleshooting
- **Script Fails**:
  - Check `/var/log/autosnort_install.log` for errors.
  - Verify internet connectivity to [snort.org](https://www.snort.org).
  - Ensure `o_code` is valid (40-character hexadecimal).
  - Confirm `eth1` and `eth2` exist (`ip link show`).
- **Snort Fails to Start**:
  - Check `systemctl status snortd.service`.
  - Test `snort.conf`:
    ```bash
    /opt/snort/bin/snort -T -c /opt/snort/etc/snort.conf
    ```
  - Verify rules: `ls -l /opt/snort/rules/snort.rules`.
- **Network Issues**:
  - Ensure pfSense firewall rules allow traffic (Chapter 14).
  - Verify AFPACKET bridging by pinging between VMs.
- **Host Network Fallout**:
  - Reapply Windows Firewall rules and unbind protocols (Chapter 15).
  - Check static routes on the host.

## License and Credits
- **Book**: *Building Virtual Machine Labs: A Hands-On Guide* by Tony Robinson.
- **Original Autosnort**: [da667/Autosnort](https://github.com/da667/Autosnort) by deusexmachina667@gmail.com.
- **Updated Script**: ZeroXSHDW.
- **License**: MIT License (see repository for details).

## Contributing
Submit pull requests or issues for improvements to the script or documentation.

## Contact
For support, open an issue on this repository or contact the original Autosnort author at deusexmachina667@gmail.com.