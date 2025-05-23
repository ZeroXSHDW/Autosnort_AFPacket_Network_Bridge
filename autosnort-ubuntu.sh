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

    # Import Ubuntu repository GPG keys to /etc/apt/trusted.gpg.d/
    print_status "Importing Ubuntu repository GPG keys..."
    gpg --keyserver hkp://keyserver.ubuntu.com:80 --recv-keys 3B4FE6ACC0B21F32 &>> $logfile
    error_check 'Retrieval of GPG key 3B4FE6ACC0B21F32'
    gpg --export --armor 3B4FE6ACC0B21F32 > /etc/apt/trusted.gpg.d/ubuntu-key1.asc &>> $logfile
    error_check 'Export GPG key 3B4FE6ACC0B21F32 to /etc/apt/trusted.gpg.d/ubuntu-key1.asc'

    gpg --keyserver hkp://keyserver.ubuntu.com:80 --recv-keys 871920D1991BC93C &>> $logfile
    error_check 'Retrieval of GPG key 871920D1991BC93C'
    gpg --export --armor 871920D1991BC93C > /etc/apt/trusted.gpg.d/ubuntu-key2.asc &>> $logfile
    error_check 'Export GPG key 871920D1991BC93C to /etc/apt/trusted.gpg.d/ubuntu-key2.asc'

    # Set permissions for GPG key files
    chmod 644 /etc/apt/trusted.gpg.d/ubuntu-key*.asc &>> $logfile
    error_check 'Setting permissions for GPG key files'

    print_notification 'This script assumes a default sources.list and changes all default repos to include universe. If you added third-party sources, re-enter them manually from /etc/apt/sources.list.bak into /etc/apt/sources.list.'
    
    print_status "Installing base packages: gcc g++ make libdumbnet-dev libdnet-dev libpcap-dev ethtool build-essential libpcap0.8-dev libpcre3-dev bison flex autoconf libtool perl libnet-ssleay-perl liblzma-dev libluajit-5.1-2 libluajit-5.1-common libluajit-5.1-dev luajit libwww-perl libnghttp2-dev libssl-dev openssl pkg-config zlib1g-dev libc6-dev rpcsvc-proto libtirpc-dev libarchive-zip-perl libcrypt-ssleay-perl liblwp-protocol-https-perl.."
    
    declare -a packages=(gcc g++ make libdumbnet-dev libdnet-dev libpcap-dev ethtool build-essential libpcap0.8-dev libpcre3-dev bison flex autoconf libtool perl libnet-ssleay-perl liblzma-dev libluajit-5.1-2 libluajit-5.1-common libluajit-5.1-dev luajit libwww-perl libnghttp2-dev libssl-dev openssl pkg-config zlib1g-dev libc6-dev rpcsvc-proto libtirpc-dev libarchive-zip-perl libcrypt-ssleay-perl liblwp-protocol-https-perl)
    
    install_packages "${packages[@]}"

    # Verify Archive::Tar module.
    print_status "Verifying Archive::Tar module is available.."
    perl -MArchive::Tar -e 'exit 0' &>> $logfile
    error_check "Verification of Archive::Tar module"
fi
