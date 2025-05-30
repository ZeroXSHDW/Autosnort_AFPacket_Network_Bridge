# Malware Lab with pfSense and AFPACKET Bridging

This repository provides a comprehensive guide and scripts to set up virtual machine (VM) labs for cybersecurity training, as outlined in *Building Virtual Machine Labs: A Hands-On Guide* by Tony Robinson. The labs leverage pfSense for network segmentation, AFPACKET bridging for IPS functionality, and include a custom `autosnort-ubuntu.sh` script to reliably install and configure Snort on the IPS VM. This script is an enhanced version of the original Autosnort script from [da667/Autosnort](https://github.com/da667/Autosnort), addressing issues such as GPG key imports, Perl module verification, and configuration validation.

## Overview

The labs are designed to be flexible, supporting multiple use cases:
- **Baseline Lab**: A foundational setup with pfSense, Kali Linux, Metasploitable 2, IPS (Snort/Suricata), and SIEM (Splunk) VMs.
- **Malware Analysis Lab**: Tailored for analyzing malware with minimal VMs and network monitoring tools.
- **Penetration Testing Lab**: Focused on red team exercises with complex network pivoting.
- **IT/OPs Lab**: Configured for testing IT automation and monitoring tools.

This guide assumes familiarity with TCP/IP networking, Linux/Windows command-line interfaces, and virtualization basics (see the book's *Prerequisite Knowledge* section for details).

## Repository Contents

- `autosnort-ubuntu.sh`: A Bash script to install and configure Snort on Ubuntu 18.04+ for the IPS VM, with enhanced logging, validation, and dependency management.
- `README.md`: This file, containing setup instructions for all lab types.

## Prerequisites

### Hardware Requirements
- **Minimum**:
  - CPU: Quad-core processor with virtualization support (Intel VT-x/AMD-V).
  - RAM: 16–24 GB (varies by lab type; see below).
  - Disk: 500–750 GB SSD (SSDs recommended for better performance).
- **Recommended**: 32 GB RAM, 1 TB SSD, 6–8 core CPU for running multiple VMs concurrently.

### Software Requirements
- **Hypervisor**: Choose one of the following:
  - Oracle VirtualBox (free, hosted)
  - Microsoft Client Hyper-V (Windows 10 Pro/Enterprise, hosted)
  - VMware Workstation Pro (paid, hosted)
  - VMware Fusion Pro (macOS, paid, hosted)
  - VMware vSphere Hypervisor (ESXi, free/paid, bare-metal)
- **Operating Systems**:
  - pfSense (latest ISO, e.g., 2.7.x)
  - Ubuntu Server 18.04/20.04 LTS (for IPS and SIEM VMs)
  - Kali Linux (latest ISO, e.g., 2025.x)
  - Metasploitable 2 (prebuilt VM from Rapid7)
  - Windows (for malware analysis or pentesting labs, optional; requires valid license)
- **Additional Tools**:
  - Splunk Enterprise and Universal Forwarder (free version or dev license)
  - SSH/SCP client (e.g., PuTTY/WinSCP for Windows, `ssh`/`scp` for Linux/macOS)
  - Snort Oinkcode (register at [snort.org](https://www.snort.org/users/sign_in))

### Knowledge Requirements
- Basic TCP/IP networking (IP addressing, subnetting, OSI model).
- Familiarity with Linux/Windows CLI (e.g., `ifconfig`, `ip`, `ping`, `netstat`).
- Experience with a Linux text editor (e.g., `vim`, `nano`).
- Understanding of virtualization concepts.

## Lab Setup Instructions

### Step 1: Hypervisor Installation
Choose a hypervisor based on your hardware and operating system. Follow the installation instructions in the book (Chapter 9–13) or the hypervisor’s official documentation:
- **VirtualBox**: Chapter 10, free, cross-platform.
- **Hyper-V**: Chapter 9, Windows 10 Pro/Enterprise.
- **VMware Workstation Pro**: Chapter 12, Windows/Linux.
- **VMware Fusion Pro**: Chapter 11, macOS.
- **ESXi**: Chapter 13, bare-metal, requires compatible hardware.

**Notes**:
- For hosted hypervisors, install on your primary OS (Windows/Linux/macOS).
- For ESXi, install on dedicated hardware and manage via a web interface or vSphere Client.
- Configure hypervisor preferences (e.g., disable guest extensions, drag-and-drop) as per the book to enhance security.

### Step 2: Virtual Network Configuration
Create four virtual network segments as described in the book (Chapter 6):
1. **Bridged/External Network**: Connects to the physical network for internet access.
2. **Management Network**: Hosts primary interfaces of IPS and SIEM VMs (e.g., 172.16.1.0/24).
3. **IPS 1 Network**: Hosts Kali Linux VM (e.g., 172.16.2.0/24).
4. **IPS 2 Network**: Hosts Metasploitable 2 VM (e.g., 172.16.3.0/24).

**Configuration**:
- For **hosted hypervisors**, configure virtual switches as Host-Only, NAT, or Bridged (Chapter 5.1).
- For **ESXi**, create virtual switches and port groups (Chapter 13.5–13.8).
- Ensure the IPS VM has two network interfaces (one for IPS 1, one for IPS 2) to enable AFPACKET bridging.

### Step 3: VM Creation and Configuration
Create and configure the following VMs as per the book’s hypervisor-specific chapters (9–13):

#### 1. pfSense VM
- **Purpose**: Firewall, DHCP, DNS, NTP, and proxy services.
- **Resources**: 512 MB RAM, 5 GB disk, 1 vCPU, 3 network interfaces (Bridged, Management, IPS 1).
- **Setup**:
  - Install pfSense (e.g., Chapter 9.11 for Hyper-V, 10.6 for VirtualBox).
  - Configure network interfaces (Chapter 14):
    - WAN (Bridged): DHCP or static IP for internet access.
    - LAN (Management): 172.16.1.1/24.
    - OPT1 (IPS 1): 172.16.2.1/24.
  - Set up firewall rules (Chapter 14.1–14.8) to isolate networks.
  - Enable core services: NTP, DHCP, DNS Resolver, Squid Proxy (Chapter 14.9–14.13).
  - Take a snapshot after configuration (e.g., Chapter 9.15).

#### 2. IPS VM (Ubuntu with Snort)
- **Purpose**: Intrusion Prevention System with AFPACKET bridging.
- **Resources**: 2 GB RAM, 20 GB disk, 2 vCPUs, 2 network interfaces (Management: 172.16.1.4, IPS 1/2: bridging).
- **Setup**:
  - Install Ubuntu Server 18.04/20.04 (e.g., Chapter 9.23 for Hyper-V).
  - Download `autosnort-ubuntu.sh` from this repository.
  - Create `full_autosnort.conf` in the same directory with the following content:
    ```bash
    o_code="your_40_char_oinkcode"  # Obtain from snort.org
    snort_basedir="/opt/snort"
    snort_iface_1="eth1"  # IPS 1 network
    snort_iface_2="eth2"  # IPS 2 network
    ```
  - Run the script as root:
    ```bash
    sudo bash autosnort-ubuntu.sh
    ```
  - The script:
    - Installs dependencies (DAQ, Snort, PulledPork).
    - Configures Snort with unified2 output and AFPACKET bridging.
    - Downloads rules using your Oinkcode.
    - Sets up a systemd service (`snortd.service`) and cron job for weekly rule updates.
    - Validates configuration and network interfaces.
  - Verify Snort is running:
    ```bash
    systemctl status snortd.service
    ```
  - Take a snapshot after successful installation.

#### 3. SIEM VM (Ubuntu with Splunk)
- **Purpose**: Log collection and analysis.
- **Resources**: 4–8 GB RAM, 50 GB disk, 2 vCPUs, 1 network interface (Management: 172.16.1.3).
- **Setup**:
  - Install Ubuntu Server 18.04/20.04 (e.g., Chapter 9.22 for Hyper-V).
  - Install Splunk Enterprise (Chapter 20.1):
    - Download the `.deb` package from [splunk.com](https://www.splunk.com).
    - Install and start Splunk:
      ```bash
      sudo dpkg -i splunk*.deb
      sudo /opt/splunk/bin/splunk start --accept-license
      sudo /opt/splunk/bin/splunk enable boot-start
      ```
    - Access the web interface at `https://172.16.1.3:8000` (admin/changeme).
    - Enable SSL and configure settings (Chapter 20.1).
  - (Optional) Request a Splunk Developer License for 10 GB/day (Chapter 20.2).
  - Install Splunk Universal Forwarder on the IPS VM (Chapter 20.3):
    - Download the `.deb` package and install:
      ```bash
      sudo dpkg -i splunkforwarder*.deb
      ```
    - Install the Hurricane Labs Add-On for Unified2 (Chapter 20.5):
      ```bash
      scp hurricane-labs-add-on-for-unified2_105.tgz root@172.16.1.4:/opt/splunkforwarder/etc/apps
      sudo tar -xzvf /opt/splunkforwarder/etc/apps/hurricane-labs-add-on-for-unified2_105.tgz
      ```
    - Configure `unified2.conf` and `inputs.conf` as per the book.
    - Start the forwarder:
      ```bash
      sudo /opt/splunkforwarder/bin/splunk start --accept-license
      sudo /opt/splunkforwarder/bin/splunk add forward-server 172.16.1.3:9997
      sudo /opt/splunkforwarder/bin/splunk enable boot-start
      ```
  - Enable receiving on Splunk (port 9997, Chapter 20.6).
  - Take a snapshot after configuration.

#### 4. Kali Linux VM
- **Purpose**: Attack simulation for testing IPS.
- **Resources**: 2 GB RAM, 20 GB disk, 1 vCPU, 1 network interface (IPS 1: 172.16.2.2).
- **Setup**:
  - Install Kali Linux (e.g., Chapter 9.21 for Hyper-V).
  - Configure network: 172.16.2.2/24, gateway 172.16.2.1, DNS 172.16.1.1.
  - Enable SSH (Chapter 17.33–17.36).
  - Take a snapshot after configuration.

#### 5. Metasploitable 2 VM
- **Purpose**: Vulnerable target for testing.
- **Resources**: 512 MB RAM, 8 GB disk, 1 vCPU, 1 network interface (IPS 2: 172.16.3.2).
- **Setup**:
  - Download and import the VM (e.g., Chapter 9.24 for Hyper-V).
  - Configure network: 172.16.3.2/24, gateway 172.16.2.1, DNS 172.16.1.1.
  - Take a snapshot after configuration.

### Step 4: Testing the Baseline Lab
- **Verify AFPACKET Bridging**:
  - From the Kali VM, ping the Metasploitable 2 VM (172.16.3.2).
  - Check IPS VM logs (`/var/log/snort`) for alerts.
- **Test Splunk**:
  - Run a “Hail Mary” attack using Armitage on Kali against Metasploitable 2 (Chapter 20.8).
  - Query Splunk for alerts (Chapter 20.9):
    ```splunk
    index=main sourcetype=snort_json | table signature.msg | dedup signature.msg
    ```
  - Use the “Last 60 minutes” timeframe.
- **Troubleshooting**:
  - Check `/var/log/autosnort_install.log` for Snort installation issues.
  - Verify firewall rules on pfSense (Chapter 14).
  - Ensure network interfaces are correctly configured (Chapter 6).

### Step 5: Configuring Alternative Lab Types
Based on your goals, modify the baseline lab as follows (Chapter 21):

#### Malware Analysis Lab
- **Changes**:
  - Remove Kali and Metasploitable 2 VMs.
  - Add a Payload Delivery VM (Linux/BSD, minimal, IPS 1: 172.16.2.2, 512 MB RAM).
  - Add Forensicator VM (SIFT/Remnux, IPS 2: 172.16.3.2, 4 GB RAM, 50 GB disk).
  - Add Windows Analysis VM (IPS 2: 172.16.3.3, 4 GB RAM, 50 GB disk).
  - Add Minimal Linux VM (IPS 2: 172.16.3.4, 512 MB RAM, 10 GB disk).
- **Resources**: ~18–22 GB RAM, 650 GB disk.
- **Setup**:
  - Download SIFT/Remnux from [sans.org](https://www.sans.org).
  - Install Windows with analysis tools (e.g., Process Explorer, Wireshark).
  - Configure IPS VM for additional monitoring (e.g., Bro IDS, tcpdump).
  - Update pfSense firewall rules to restrict IPS 2 traffic (Chapter 14.4).

#### Penetration Testing Lab
- **Changes**:
  - Add a second pfSense VM (IPS 2: 172.16.3.1, 512 MB RAM, 3 interfaces).
  - Add Vulnerable Web App VM (IPS 2: 172.16.3.2, 1 GB RAM).
  - Add Linux FTP Server (IPS 2: 172.16.3.3, 1 GB RAM).
  - Add Windows Workstation (IPS 2: 172.16.3.4, 2 GB RAM).
  - Add Domain Controller (IPS 2: 172.16.3.5, 2 GB RAM).
- **Resources**: ~17–22 GB RAM, 600+ GB disk.
- **Setup**:
  - Configure second pfSense to allow only ports 80/443 (Chapter 14.8).
  - Install vulnerable web apps (e.g., DVWA from [vulnhub.com](https://www.vulnhub.com)).
  - Set up Active Directory on the Domain Controller.
  - Practice pivoting and privilege escalation (Chapter 21.3).

#### IT/OPs Lab
- **Changes**:
  - Add VMs for Spiceworks, Nagios, or Icinga (Management: 172.16.1.x, 2–4 GB RAM each).
  - Add VMs for APT mirror, WSUS, or Docker (Management/IPS: 172.16.1.x/2.x, 2–4 GB RAM).
- **Resources**: ~20–24 GB RAM, 750 GB disk.
- **Setup**:
  - Install monitoring tools (e.g., Nagios from [nagios.org](https://www.nagios.org)).
  - Configure automation tools (e.g., Ansible, Puppet).
  - Update pfSense for additional services (Chapter 14.9).

### Step 6: Remote Access and Security
- **Enable SSH/SCP**:
  - Configure key-based authentication for all VMs (Chapter 17.7–17.36).
  - Use `ssh-keygen` (Linux/macOS) or PuTTYgen (Windows).
- **Static Routes**:
  - Add routes for Management/IPS networks on your workstation (Chapter 17.1–17.22).
- **Jump Box (Bare-Metal Hypervisors)**:
  - Set up a Raspberry Pi or VM as a jump box (Chapter 18.6–18.11).
  - Configure SSH tunnels and firewall rules (Chapter 18.17–18.28).
- **Windows Hardening (Hosted Hypervisors)**:
  - Unbind protocols and configure Windows Firewall (Chapter 15).
- **Automated Updates**:
  - Use `updater.sh` for Linux VMs (Chapter 16).

### Step 7: Snapshots and Maintenance
- Take snapshots of all VMs after initial setup and major changes (e.g., Chapter 9.15).
- Regularly update VMs and hypervisor software.
- Monitor `/var/log/autosnort_install.log` for Snort issues.
- Back up critical configuration files (e.g., `full_autosnort.conf`, `snort.conf`).

## Using autosnort-ubuntu.sh

The `autosnort-ubuntu.sh` script automates Snort installation and configuration, fixing issues in the original Autosnort script:
- **Enhancements**:
  - Robust GPG key import with retries and multiple keyservers.
  - Verification of Perl modules (e.g., `LWP::UserAgent`, `Archive::Tar`).
  - Validation of `snort.conf`, rules, and network interfaces.
  - Fixed syntax errors and permission issues.
  - Enhanced logging to `/var/log/autosnort_install.log`.
- **Usage**:
  - Place `autosnort-ubuntu.sh` and `full_autosnort.conf` in the same directory on the IPS VM.
  - Ensure a valid Oinkcode in `full_autosnort.conf`.
  - Run as root: `sudo bash autosnort-ubuntu.sh`.
- **Troubleshooting**:
  - Check `/var/log/autosnort_install.log` for errors.
  - Verify network connectivity to [snort.org](https://www.snort.org).
  - Ensure `eth1` and `eth2` exist for AFPACKET bridging.

## License and Credits
- **Book**: *Building Virtual Machine Labs: A Hands-On Guide* by Tony Robinson (ISBN-13: 978-1546932635).
- **Original Autosnort**: [da667/Autosnort](https://github.com/da667/Autosnort).
- **Script Author**: ZeroXSHDW.
- **License**: This repository is licensed under the MIT License. See the book for its copyright terms.

## Contributing
Contributions are welcome! Please submit pull requests or issues for improvements to the script or documentation.

## Contact
For questions or support, open an issue on this repository or contact the original Autosnort author at deusexmachina667@gmail.com.